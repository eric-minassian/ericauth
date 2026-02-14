# Token Introspection (RFC 7662) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add RFC 7662 token introspection with confidential client support.

**Architecture:** Add `client_secret` (optional, SHA-256 hashed) to `ClientTable` for confidential client distinction. New `client_auth` module handles Basic/POST client authentication. New `/token/introspect` endpoint decodes JWTs and returns RFC 7662 responses.

**Tech Stack:** Rust, axum, jsonwebtoken, sha2, base64, subtle (constant-time comparison via existing sha2/hex)

---

### Task 1: Add `client_secret` to `ClientTable`

**Files:**
- Modify: `src/db/client.rs:8-14`

**Step 1: Add the field**

In `src/db/client.rs`, add `client_secret` to the struct:

```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientTable {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub client_name: String,
}
```

The `#[serde(default)]` ensures existing DynamoDB items without the field deserialize as `None`.

**Step 2: Run tests to verify nothing breaks**

Run: `ENCRYPTION_KEY="01234567890123456789012345678901" cargo test --all-features`
Expected: All existing tests pass (no behavioral change, just a new optional field)

**Step 3: Commit**

```bash
git add src/db/client.rs
git commit -m "Add optional client_secret field to ClientTable for confidential client support"
```

---

### Task 2: Add `subtle` dependency for constant-time comparison

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add the dependency**

Add `subtle = "2"` to the `[dependencies]` section in `Cargo.toml`.

**Step 2: Verify it compiles**

Run: `cargo check --all-features`
Expected: Compiles without errors

**Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "Add subtle crate for constant-time secret comparison"
```

---

### Task 3: Create client authentication module — tests first

**Files:**
- Create: `src/client_auth.rs`
- Modify: `src/lib.rs`

**Step 1: Write the module with tests**

Create `src/client_auth.rs`:

```rust
use axum::{
    extract::State,
    http::{header, HeaderMap},
    Form,
};
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

    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .ok()?;
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
        // base64("my-client:my-secret") = "bXktY2xpZW50Om15LXNlY3JldA=="
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "my-client:my-secret",
        );
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
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            ":my-secret",
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        assert!(parse_basic_auth(&headers).is_none());
    }

    #[test]
    fn test_parse_basic_auth_empty_secret() {
        let mut headers = HeaderMap::new();
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "my-client:",
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        assert!(parse_basic_auth(&headers).is_none());
    }

    #[test]
    fn test_parse_basic_auth_no_colon() {
        let mut headers = HeaderMap::new();
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "just-a-string",
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        assert!(parse_basic_auth(&headers).is_none());
    }

    #[test]
    fn test_parse_basic_auth_colon_in_secret() {
        let mut headers = HeaderMap::new();
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            "my-client:secret:with:colons",
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        let result = parse_basic_auth(&headers).unwrap();
        assert_eq!(result.client_id, "my-client");
        assert_eq!(result.client_secret, "secret:with:colons");
    }
}
```

**Step 2: Register the module in `src/lib.rs`**

Add `pub mod client_auth;` to `src/lib.rs` (alphabetically after `db`):

```rust
pub mod client_auth;
```

**Step 3: Run the tests**

Run: `ENCRYPTION_KEY="01234567890123456789012345678901" cargo test client_auth --all-features`
Expected: All 7 unit tests pass

**Step 4: Run full test suite**

Run: `ENCRYPTION_KEY="01234567890123456789012345678901" cargo test --all-features`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/client_auth.rs src/lib.rs
git commit -m "Add client authentication module with Basic/POST support and constant-time secret verification"
```

---

### Task 4: Create introspection endpoint — tests first

**Files:**
- Create: `src/routes/introspect.rs`
- Modify: `src/routes/mod.rs`

**Step 1: Write the introspect handler with tests**

Create `src/routes/introspect.rs`:

```rust
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue},
    response::IntoResponse,
    Form, Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{client_auth::authenticate_client, error::AuthError, state::AppState};

#[derive(Deserialize)]
pub struct IntrospectRequest {
    token: String,
    token_type_hint: Option<String>,
    /// For client_secret_post authentication
    client_id: Option<String>,
    client_secret: Option<String>,
}

pub async fn handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<IntrospectRequest>,
) -> Result<impl IntoResponse, AuthError> {
    // Authenticate the calling client
    let _authenticated = authenticate_client(
        &state,
        &headers,
        body.client_id.as_deref(),
        body.client_secret.as_deref(),
    )
    .await?;

    // Log unknown token_type_hint values (but accept them per RFC)
    if let Some(hint) = body.token_type_hint.as_deref() {
        if hint != "access_token" {
            tracing::debug!("token_type_hint is not access_token: {hint}");
        }
    }

    // Try to verify the token as a JWT access token
    let jwt_keys = match state.jwt_keys.as_ref() {
        Some(keys) => keys,
        None => {
            return Ok(inactive_response());
        }
    };

    // For introspection, we don't validate audience — any confidential client can introspect any token
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&["https://auth.ericminassian.com"]);
    validation.validate_aud = false;

    let claims = match jsonwebtoken::decode::<crate::jwt::AccessTokenClaims>(
        &body.token,
        &jwt_keys.decoding_key,
        &validation,
    ) {
        Ok(token_data) => token_data.claims,
        Err(_) => {
            return Ok(inactive_response());
        }
    };

    let response = json!({
        "active": true,
        "scope": claims.scope,
        "client_id": claims.aud,
        "sub": claims.sub,
        "exp": claims.exp,
        "iat": claims.iat,
        "iss": claims.iss,
        "token_type": "Bearer",
        "email": claims.email,
    });

    Ok((
        [
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            ),
            (
                header::PRAGMA,
                HeaderValue::from_static("no-cache"),
            ),
        ],
        Json(response),
    ))
}

fn inactive_response() -> (
    [(header::HeaderName, HeaderValue); 2],
    Json<serde_json::Value>,
) {
    (
        [
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            ),
            (
                header::PRAGMA,
                HeaderValue::from_static("no-cache"),
            ),
        ],
        Json(json!({"active": false})),
    )
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use lambda_http::tower::ServiceExt;
    use sha2::{Digest, Sha256};

    use crate::{
        db::{client::ClientTable, Database},
        jwt::{generate_es256_keypair, AccessTokenClaims, JwtKeys},
        state::AppState,
    };

    fn test_jwt_keys() -> JwtKeys {
        let (private_pem, _) = generate_es256_keypair().unwrap();
        JwtKeys::from_pem(private_pem.as_bytes(), "test-kid").unwrap()
    }

    fn test_app_state() -> AppState {
        AppState {
            db: Database::memory(),
            jwt_keys: Some(test_jwt_keys()),
            webauthn: std::sync::Arc::new(
                crate::webauthn_config::build_webauthn().unwrap(),
            ),
        }
    }

    fn build_router(state: AppState) -> axum::Router {
        crate::routes::router(state)
    }

    fn hash_secret(secret: &str) -> String {
        hex::encode(Sha256::digest(secret.as_bytes()))
    }

    fn basic_auth_header(client_id: &str, client_secret: &str) -> String {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!("{client_id}:{client_secret}"),
        );
        format!("Basic {encoded}")
    }

    async fn setup_confidential_client(state: &AppState) {
        let client = ClientTable {
            client_id: "test-confidential".to_string(),
            client_secret: Some(hash_secret("test-secret")),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            allowed_scopes: vec!["openid".to_string()],
            client_name: "Test Confidential Client".to_string(),
        };
        state.db.insert_client(client).await.unwrap();
    }

    async fn setup_public_client(state: &AppState) {
        let client = ClientTable {
            client_id: "test-public".to_string(),
            client_secret: None,
            redirect_uris: vec!["https://example.com/callback".to_string()],
            allowed_scopes: vec!["openid".to_string()],
            client_name: "Test Public Client".to_string(),
        };
        state.db.insert_client(client).await.unwrap();
    }

    fn sign_test_token(keys: &JwtKeys, expired: bool) -> String {
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = AccessTokenClaims {
            iss: "https://auth.ericminassian.com".to_string(),
            sub: "user-123".to_string(),
            aud: "some-client".to_string(),
            exp: if expired { now - 120 } else { now + 900 },
            iat: if expired { now - 1020 } else { now },
            scope: "openid email".to_string(),
            email: "test@example.com".to_string(),
        };
        keys.sign_access_token(&claims).unwrap()
    }

    #[tokio::test]
    async fn test_introspect_active_token() {
        let state = test_app_state();
        setup_confidential_client(&state).await;

        let token = sign_test_token(state.jwt_keys.as_ref().unwrap(), false);
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token/introspect")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header(
                        "authorization",
                        basic_auth_header("test-confidential", "test-secret"),
                    )
                    .body(Body::from(format!("token={token}")))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("cache-control").unwrap(),
            "no-store"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["active"], true);
        assert_eq!(json["sub"], "user-123");
        assert_eq!(json["client_id"], "some-client");
        assert_eq!(json["scope"], "openid email");
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["iss"], "https://auth.ericminassian.com");
        assert_eq!(json["email"], "test@example.com");
    }

    #[tokio::test]
    async fn test_introspect_expired_token() {
        let state = test_app_state();
        setup_confidential_client(&state).await;

        let token = sign_test_token(state.jwt_keys.as_ref().unwrap(), true);
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token/introspect")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header(
                        "authorization",
                        basic_auth_header("test-confidential", "test-secret"),
                    )
                    .body(Body::from(format!("token={token}")))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["active"], false);
    }

    #[tokio::test]
    async fn test_introspect_malformed_token() {
        let state = test_app_state();
        setup_confidential_client(&state).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token/introspect")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header(
                        "authorization",
                        basic_auth_header("test-confidential", "test-secret"),
                    )
                    .body(Body::from("token=not-a-valid-jwt"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["active"], false);
    }

    #[tokio::test]
    async fn test_introspect_no_credentials_returns_401() {
        let state = test_app_state();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token/introspect")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("token=some-token"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_introspect_wrong_secret_returns_401() {
        let state = test_app_state();
        setup_confidential_client(&state).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token/introspect")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header(
                        "authorization",
                        basic_auth_header("test-confidential", "wrong-secret"),
                    )
                    .body(Body::from("token=some-token"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_introspect_public_client_returns_401() {
        let state = test_app_state();
        setup_public_client(&state).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token/introspect")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header(
                        "authorization",
                        basic_auth_header("test-public", "some-secret"),
                    )
                    .body(Body::from("token=some-token"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_introspect_client_secret_post() {
        let state = test_app_state();
        setup_confidential_client(&state).await;

        let token = sign_test_token(state.jwt_keys.as_ref().unwrap(), false);
        let app = build_router(state);

        let body = format!(
            "token={token}&client_id=test-confidential&client_secret=test-secret"
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token/introspect")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["active"], true);
    }
}
```

**Step 2: Register the route in `src/routes/mod.rs`**

Add `mod introspect;` to the module declarations at the top of `src/routes/mod.rs`.

Add the route to `cors_routes`:

```rust
.route("/token/introspect", post(introspect::handler))
```

This goes after the `.route("/token/revoke", post(token_revoke::handler))` line.

**Step 3: Run the introspection tests**

Run: `ENCRYPTION_KEY="01234567890123456789012345678901" cargo test introspect --all-features`
Expected: All 7 handler tests pass

**Step 4: Run full test suite**

Run: `ENCRYPTION_KEY="01234567890123456789012345678901" cargo test --all-features`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/routes/introspect.rs src/routes/mod.rs
git commit -m "Add POST /token/introspect endpoint with RFC 7662 token introspection"
```

---

### Task 5: Update OpenID Configuration

**Files:**
- Modify: `src/routes/openid_config.rs:9-24`

**Step 1: Add introspection fields to the config response**

Add these two fields to the `json!({...})` object in `src/routes/openid_config.rs`:

```rust
"introspection_endpoint": "https://auth.ericminassian.com/token/introspect",
"introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
```

**Step 2: Update the existing test**

The test `test_openid_config_returns_json` should also assert the new fields. Add:

```rust
assert_eq!(
    json["introspection_endpoint"],
    "https://auth.ericminassian.com/token/introspect"
);
assert_eq!(
    json["introspection_endpoint_auth_methods_supported"],
    json!(["client_secret_basic", "client_secret_post"])
);
```

**Step 3: Run the openid_config tests**

Run: `ENCRYPTION_KEY="01234567890123456789012345678901" cargo test openid_config --all-features`
Expected: Test passes with new assertions

**Step 4: Commit**

```bash
git add src/routes/openid_config.rs
git commit -m "Add introspection_endpoint to OpenID Configuration discovery"
```

---

### Task 6: Add integration tests

**Files:**
- Modify: `tests/integration_test.rs`

**Step 1: Add integration tests for the full introspection flow**

Add these tests to `tests/integration_test.rs`:

```rust
// --- Token introspection ---

#[tokio::test]
async fn test_introspect_valid_access_token() {
    use ericauth::db::client::ClientTable;

    let state = test_state();

    // Register a confidential client
    let client_secret = "integration-test-secret";
    let secret_hash = hex::encode(Sha256::new().chain(client_secret.as_bytes()).finalize());
    let client = ClientTable {
        client_id: "introspect-client".to_string(),
        client_secret: Some(secret_hash),
        redirect_uris: vec!["https://example.com/callback".to_string()],
        allowed_scopes: vec!["openid".to_string(), "email".to_string()],
        client_name: "Introspect Test Client".to_string(),
    };
    state.db.insert_client(client).await.unwrap();

    // Create an access token
    let jwt_keys = state.jwt_keys.as_ref().unwrap();
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = ericauth::jwt::AccessTokenClaims {
        iss: "https://auth.ericminassian.com".to_string(),
        sub: "user-introspect".to_string(),
        aud: "some-app".to_string(),
        exp: now + 900,
        iat: now,
        scope: "openid email".to_string(),
        email: "introspect@example.com".to_string(),
    };
    let token = jwt_keys.sign_access_token(&claims).unwrap();

    // Introspect it
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        format!("introspect-client:{client_secret}"),
    );
    let app = test_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", format!("Basic {encoded}"))
                .body(Body::from(format!("token={token}")))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["active"], true);
    assert_eq!(json["sub"], "user-introspect");
    assert_eq!(json["email"], "introspect@example.com");
}

#[tokio::test]
async fn test_introspect_without_auth_returns_401() {
    let state = test_state();
    let app = test_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("token=any-token"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
```

**Step 2: Add import for base64 in integration test**

Add `use base64` to the imports at the top of the integration test file. The `base64` crate is already a dependency.

**Step 3: Run all tests**

Run: `ENCRYPTION_KEY="01234567890123456789012345678901" cargo test --all-features`
Expected: All tests pass, including new integration tests

**Step 4: Commit**

```bash
git add tests/integration_test.rs
git commit -m "Add integration tests for token introspection endpoint"
```

---

### Task 7: Run linter and final verification

**Step 1: Format code**

Run: `cargo fmt --all`

**Step 2: Run clippy**

Run: `cargo clippy --all-targets --all-features`
Expected: No warnings (CI treats warnings as errors)

**Step 3: Run full test suite one final time**

Run: `ENCRYPTION_KEY="01234567890123456789012345678901" cargo test --all-features`
Expected: All tests pass

**Step 4: Fix any issues found, commit if needed**

If formatting or clippy produced changes:
```bash
git add -A
git commit -m "Fix lint and formatting issues"
```

---

### Task 8: Squash commits and prepare PR

Per the repo's git workflow (AGENTS.md), PRs must have exactly 1 commit.

**Step 1: Squash all commits from this feature into one**

Use interactive rebase to squash all feature commits into a single commit with message:

```
Add RFC 7662 token introspection endpoint with confidential client support
```

**Step 2: Push and open PR**

Push the branch and open a PR with auto-merge enabled.
