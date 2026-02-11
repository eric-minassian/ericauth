use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::AuthError;

const ISSUER: &str = "https://auth.ericminassian.com";

/// Claims for an OAuth2 access token (JWT).
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub scope: String,
    pub email: String,
}

/// Claims for an OpenID Connect ID token (JWT).
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub auth_time: usize,
    pub nonce: Option<String>,
    pub email: String,
    pub email_verified: bool,
}

/// Holds the ES256 signing/verification keys and metadata for JWT operations.
#[derive(Clone)]
pub struct JwtKeys {
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    pub kid: String,
    pub public_key_pem: String,
}

impl JwtKeys {
    /// Load JWT keys from a PEM-encoded ES256 private key.
    pub fn from_pem(private_pem: &[u8], kid: &str) -> Result<Self, AuthError> {
        let encoding_key = EncodingKey::from_ec_pem(private_pem)
            .map_err(|e| AuthError::Internal(format!("Failed to load JWT encoding key: {e}")))?;

        // Extract the public key from the private key PEM
        let private_key = p256::SecretKey::from_sec1_pem(
            std::str::from_utf8(private_pem)
                .map_err(|e| AuthError::Internal(format!("Invalid PEM encoding: {e}")))?,
        )
        .or_else(|_| {
            p256::SecretKey::from_pkcs8_pem(
                std::str::from_utf8(private_pem)
                    .map_err(|e| AuthError::Internal(format!("Invalid PEM encoding: {e}")))?,
            )
            .map_err(|e| AuthError::Internal(format!("Failed to parse private key: {e}")))
        })?;

        let public_key = private_key.public_key();
        let public_key_pem = public_key.to_string();

        let decoding_key = DecodingKey::from_ec_pem(public_key_pem.as_bytes())
            .map_err(|e| AuthError::Internal(format!("Failed to load JWT decoding key: {e}")))?;

        Ok(Self {
            encoding_key,
            decoding_key,
            kid: kid.to_string(),
            public_key_pem,
        })
    }

    /// Sign an access token JWT with ES256.
    pub fn sign_access_token(&self, claims: &AccessTokenClaims) -> Result<String, AuthError> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());

        jsonwebtoken::encode(&header, claims, &self.encoding_key)
            .map_err(|e| AuthError::Internal(format!("Failed to sign access token: {e}")))
    }

    /// Sign an ID token JWT with ES256.
    pub fn sign_id_token(&self, claims: &IdTokenClaims) -> Result<String, AuthError> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());

        jsonwebtoken::encode(&header, claims, &self.encoding_key)
            .map_err(|e| AuthError::Internal(format!("Failed to sign ID token: {e}")))
    }

    /// Verify and decode an access token JWT.
    pub fn verify_access_token(
        &self,
        token: &str,
        audience: &str,
    ) -> Result<AccessTokenClaims, AuthError> {
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[audience]);

        let token_data =
            jsonwebtoken::decode::<AccessTokenClaims>(token, &self.decoding_key, &validation)
                .map_err(|e| AuthError::Unauthorized(format!("Invalid access token: {e}")))?;

        Ok(token_data.claims)
    }
}

/// Generate a new ES256 keypair. Returns `(private_pem, public_pem)`.
pub fn generate_es256_keypair() -> Result<(String, String), AuthError> {
    let signing_key = SigningKey::random(&mut OsRng);
    let secret_key = p256::SecretKey::from(signing_key);

    let private_pem = secret_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| AuthError::Internal(format!("Failed to encode private key: {e}")))?;

    let public_key = secret_key.public_key();
    let public_pem = public_key.to_string();

    Ok((private_pem.to_string(), public_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> JwtKeys {
        let (private_pem, _) = generate_es256_keypair().unwrap();
        JwtKeys::from_pem(private_pem.as_bytes(), "test-kid-1").unwrap()
    }

    #[test]
    fn test_generate_and_load_keypair() {
        let (private_pem, _public_pem) = generate_es256_keypair().unwrap();
        let keys = JwtKeys::from_pem(private_pem.as_bytes(), "test-kid-1").unwrap();

        assert_eq!(keys.kid, "test-kid-1");
        assert!(!keys.public_key_pem.is_empty());
    }

    #[test]
    fn test_sign_and_verify_access_token() {
        let keys = test_keys();
        let now = chrono::Utc::now().timestamp() as usize;

        let claims = AccessTokenClaims {
            iss: ISSUER.to_string(),
            sub: "user-123".to_string(),
            aud: "my-client".to_string(),
            exp: now + 900,
            iat: now,
            scope: "openid email".to_string(),
            email: "test@example.com".to_string(),
        };

        let token = keys.sign_access_token(&claims).unwrap();
        let decoded = keys.verify_access_token(&token, "my-client").unwrap();

        assert_eq!(decoded.iss, ISSUER);
        assert_eq!(decoded.sub, "user-123");
        assert_eq!(decoded.aud, "my-client");
        assert_eq!(decoded.scope, "openid email");
        assert_eq!(decoded.email, "test@example.com");
    }

    #[test]
    fn test_verify_access_token_wrong_audience() {
        let keys = test_keys();
        let now = chrono::Utc::now().timestamp() as usize;

        let claims = AccessTokenClaims {
            iss: ISSUER.to_string(),
            sub: "user-123".to_string(),
            aud: "my-client".to_string(),
            exp: now + 900,
            iat: now,
            scope: "openid".to_string(),
            email: "test@example.com".to_string(),
        };

        let token = keys.sign_access_token(&claims).unwrap();
        let result = keys.verify_access_token(&token, "wrong-client");

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_access_token_expired() {
        let keys = test_keys();
        let now = chrono::Utc::now().timestamp() as usize;

        let claims = AccessTokenClaims {
            iss: ISSUER.to_string(),
            sub: "user-123".to_string(),
            aud: "my-client".to_string(),
            exp: now - 120,
            iat: now - 1020,
            scope: "openid".to_string(),
            email: "test@example.com".to_string(),
        };

        let token = keys.sign_access_token(&claims).unwrap();
        let result = keys.verify_access_token(&token, "my-client");

        assert!(result.is_err());
    }

    #[test]
    fn test_sign_id_token() {
        let keys = test_keys();
        let now = chrono::Utc::now().timestamp() as usize;

        let claims = IdTokenClaims {
            iss: ISSUER.to_string(),
            sub: "user-456".to_string(),
            aud: "my-client".to_string(),
            exp: now + 3600,
            iat: now,
            auth_time: now,
            nonce: Some("abc123".to_string()),
            email: "user@example.com".to_string(),
            email_verified: true,
        };

        let token = keys.sign_id_token(&claims).unwrap();
        assert!(!token.is_empty());

        // Verify the ID token can be decoded with the same key
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[&claims.aud]);

        let decoded =
            jsonwebtoken::decode::<IdTokenClaims>(&token, &keys.decoding_key, &validation).unwrap();

        assert_eq!(decoded.claims.sub, "user-456");
        assert_eq!(decoded.claims.nonce, Some("abc123".to_string()));
        assert!(decoded.claims.email_verified);
    }

    #[test]
    fn test_sign_id_token_without_nonce() {
        let keys = test_keys();
        let now = chrono::Utc::now().timestamp() as usize;

        let claims = IdTokenClaims {
            iss: ISSUER.to_string(),
            sub: "user-789".to_string(),
            aud: "my-client".to_string(),
            exp: now + 3600,
            iat: now,
            auth_time: now,
            nonce: None,
            email: "user@example.com".to_string(),
            email_verified: false,
        };

        let token = keys.sign_id_token(&claims).unwrap();
        assert!(!token.is_empty());

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[&claims.aud]);

        let decoded =
            jsonwebtoken::decode::<IdTokenClaims>(&token, &keys.decoding_key, &validation).unwrap();

        assert_eq!(decoded.claims.nonce, None);
        assert!(!decoded.claims.email_verified);
    }

    #[test]
    fn test_access_token_has_kid_in_header() {
        let keys = test_keys();
        let now = chrono::Utc::now().timestamp() as usize;

        let claims = AccessTokenClaims {
            iss: ISSUER.to_string(),
            sub: "user-123".to_string(),
            aud: "my-client".to_string(),
            exp: now + 900,
            iat: now,
            scope: "openid".to_string(),
            email: "test@example.com".to_string(),
        };

        let token = keys.sign_access_token(&claims).unwrap();

        // Decode the header without verification to check kid
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid, Some("test-kid-1".to_string()));
    }
}
