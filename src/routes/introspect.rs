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
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (header::PRAGMA, HeaderValue::from_static("no-cache")),
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
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (header::PRAGMA, HeaderValue::from_static("no-cache")),
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
    use base64::Engine;
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
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
        }
    }

    fn build_router(state: AppState) -> axum::Router {
        crate::routes::router(state)
    }

    fn hash_secret(secret: &str) -> String {
        hex::encode(Sha256::digest(secret.as_bytes()))
    }

    fn basic_auth_header(client_id: &str, client_secret: &str) -> String {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(format!("{client_id}:{client_secret}"));
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
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");

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

        let body = format!("token={token}&client_id=test-confidential&client_secret=test-secret");

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
