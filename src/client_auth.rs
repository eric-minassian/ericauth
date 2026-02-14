use axum::http::{header, HeaderMap};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{db::client::ClientTable, error::AuthError, state::AppState};

/// A client that has been authenticated via client_secret_basic or client_secret_post.
pub struct AuthenticatedClient {
    pub client_id: String,
    pub client: ClientTable,
}

/// Credentials extracted from either HTTP Basic auth or form body.
struct ClientCredentials {
    client_id: String,
    client_secret: String,
}

/// Parse HTTP Basic Authorization header.
/// Format: `Basic base64(client_id:client_secret)`
fn parse_basic_auth(headers: &HeaderMap) -> Option<ClientCredentials> {
    let auth_header = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = auth_header.strip_prefix("Basic ")?;

    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;

    let (client_id, client_secret) = decoded_str.split_once(':')?;
    if client_id.is_empty() || client_secret.is_empty() {
        return None;
    }

    Some(ClientCredentials {
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
    })
}

/// Verify a plaintext secret against a stored SHA-256 hash using constant-time comparison.
///
/// SHA-256 (without salt/KDF) is acceptable here because client secrets are
/// system-generated with high entropy. If low-entropy secrets were ever supported,
/// this should use Argon2id instead.
fn verify_client_secret(plaintext: &str, stored_hash: &str) -> bool {
    let computed = hex::encode(Sha256::digest(plaintext.as_bytes()));
    computed.as_bytes().ct_eq(stored_hash.as_bytes()).into()
}

/// Authenticate a client from the request. Tries Basic auth first, then form body.
///
/// The `form_client_id` and `form_client_secret` are optional fields from the
/// form-urlencoded body (for client_secret_post).
pub async fn authenticate_client(
    state: &AppState,
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> Result<AuthenticatedClient, AuthError> {
    // Try Basic auth first
    let credentials = if let Some(basic) = parse_basic_auth(headers) {
        basic
    } else if let (Some(id), Some(secret)) = (form_client_id, form_client_secret) {
        if id.is_empty() || secret.is_empty() {
            return Err(AuthError::Unauthorized("invalid client credentials".into()));
        }
        ClientCredentials {
            client_id: id.to_string(),
            client_secret: secret.to_string(),
        }
    } else {
        return Err(AuthError::Unauthorized("missing client credentials".into()));
    };

    // Look up the client
    let client = state
        .db
        .get_client(&credentials.client_id)
        .await?
        .ok_or_else(|| AuthError::Unauthorized("invalid client credentials".into()))?;

    // Must be a confidential client (has a secret)
    let stored_hash = client
        .client_secret
        .as_ref()
        .ok_or_else(|| AuthError::Unauthorized("invalid client credentials".into()))?;

    // Verify the secret
    if !verify_client_secret(&credentials.client_secret, stored_hash) {
        return Err(AuthError::Unauthorized("invalid client credentials".into()));
    }

    Ok(AuthenticatedClient {
        client_id: credentials.client_id,
        client,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::HeaderValue;

    fn hash_secret(secret: &str) -> String {
        hex::encode(Sha256::digest(secret.as_bytes()))
    }

    #[test]
    fn test_verify_client_secret_valid() {
        let secret = "my-secret-123";
        let hash = hash_secret(secret);
        assert!(verify_client_secret(secret, &hash));
    }

    #[test]
    fn test_verify_client_secret_invalid() {
        let hash = hash_secret("correct-secret");
        assert!(!verify_client_secret("wrong-secret", &hash));
    }

    #[test]
    fn test_parse_basic_auth_valid() {
        let mut headers = HeaderMap::new();
        let encoded = STANDARD.encode("my-client:my-secret");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );

        let result = parse_basic_auth(&headers).unwrap();
        assert_eq!(result.client_id, "my-client");
        assert_eq!(result.client_secret, "my-secret");
    }

    #[test]
    fn test_parse_basic_auth_missing_header() {
        let headers = HeaderMap::new();
        assert!(parse_basic_auth(&headers).is_none());
    }

    #[test]
    fn test_parse_basic_auth_not_basic() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer some-token"),
        );
        assert!(parse_basic_auth(&headers).is_none());
    }

    #[test]
    fn test_parse_basic_auth_empty_client_id() {
        let mut headers = HeaderMap::new();
        let encoded = STANDARD.encode(":my-secret");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        assert!(parse_basic_auth(&headers).is_none());
    }

    #[test]
    fn test_parse_basic_auth_empty_secret() {
        let mut headers = HeaderMap::new();
        let encoded = STANDARD.encode("my-client:");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        assert!(parse_basic_auth(&headers).is_none());
    }

    #[test]
    fn test_parse_basic_auth_no_colon() {
        let mut headers = HeaderMap::new();
        let encoded = STANDARD.encode("just-a-string");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        assert!(parse_basic_auth(&headers).is_none());
    }

    #[test]
    fn test_parse_basic_auth_colon_in_secret() {
        let mut headers = HeaderMap::new();
        let encoded = STANDARD.encode("my-client:secret:with:colons");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        let result = parse_basic_auth(&headers).unwrap();
        assert_eq!(result.client_id, "my-client");
        assert_eq!(result.client_secret, "secret:with:colons");
    }
}
