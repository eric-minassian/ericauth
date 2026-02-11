use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Form, Json,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{digest::Update, Digest, Sha256};

use crate::{
    db::refresh_token::RefreshTokenTable, jwt::AccessTokenClaims,
    refresh_token::generate_refresh_token, state::AppState,
};

const ISSUER: &str = "https://auth.ericminassian.com";
const ACCESS_TOKEN_EXPIRY_SECS: i64 = 900; // 15 minutes
const REFRESH_TOKEN_EXPIRY_SECS: i64 = 30 * 24 * 60 * 60; // 30 days

#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    refresh_token: Option<String>,
    client_id: Option<String>,
    scope: Option<String>,
    // authorization_code fields for future use
    #[allow(dead_code)]
    code: Option<String>,
    #[allow(dead_code)]
    redirect_uri: Option<String>,
    #[allow(dead_code)]
    code_verifier: Option<String>,
}

/// RFC 6749 Section 5.2 error response.
fn token_error(error: &str, description: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": error,
            "error_description": description,
        })),
    )
}

pub async fn handler(
    State(state): State<AppState>,
    Form(body): Form<TokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    match body.grant_type.as_str() {
        "refresh_token" => handle_refresh_token(state, body).await,
        "authorization_code" => Err(token_error(
            "unsupported_grant_type",
            "authorization_code grant is not yet supported",
        )),
        _ => Err(token_error(
            "unsupported_grant_type",
            &format!("grant_type '{}' is not supported", body.grant_type),
        )),
    }
}

async fn handle_refresh_token(
    state: AppState,
    body: TokenRequest,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let raw_token = body
        .refresh_token
        .ok_or_else(|| token_error("invalid_request", "refresh_token parameter is required"))?;

    // Hash the refresh token for lookup
    let token_hash = hex::encode(Sha256::new().chain(raw_token.as_bytes()).finalize());

    // Look up the refresh token
    let stored_token = state
        .db
        .get_refresh_token(&token_hash)
        .await
        .map_err(|e| token_error("server_error", &format!("failed to look up token: {e}")))?
        .ok_or_else(|| token_error("invalid_grant", "refresh token is invalid or expired"))?;

    // Revoke the old refresh token (rotation)
    state
        .db
        .revoke_refresh_token(&token_hash)
        .await
        .map_err(|e| token_error("server_error", &format!("failed to revoke token: {e}")))?;

    // Get JWT keys
    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| token_error("server_error", "JWT signing is not configured"))?;

    // Look up user to get email for JWT claims
    let user = state
        .db
        .get_user_by_id(&stored_token.user_id)
        .await
        .map_err(|e| token_error("server_error", &format!("failed to look up user: {e}")))?
        .ok_or_else(|| token_error("invalid_grant", "user not found"))?;

    let now = chrono::Utc::now().timestamp() as usize;
    let scope = body.scope.unwrap_or(stored_token.scope.clone());

    // Sign new access token
    let access_claims = AccessTokenClaims {
        iss: ISSUER.to_string(),
        sub: stored_token.user_id.clone(),
        aud: body.client_id.unwrap_or_default(),
        exp: now + ACCESS_TOKEN_EXPIRY_SECS as usize,
        iat: now,
        scope: scope.clone(),
        email: user.email,
    };

    let access_token = jwt_keys
        .sign_access_token(&access_claims)
        .map_err(|e| token_error("server_error", &format!("failed to sign access token: {e}")))?;

    // Generate and store new refresh token
    let new_raw_token = generate_refresh_token().map_err(|e| {
        token_error(
            "server_error",
            &format!("failed to generate refresh token: {e}"),
        )
    })?;
    let new_token_hash = hex::encode(Sha256::new().chain(new_raw_token.as_bytes()).finalize());
    let new_expires_at = chrono::Utc::now().timestamp() + REFRESH_TOKEN_EXPIRY_SECS;

    let new_refresh_entry = RefreshTokenTable {
        token_hash: new_token_hash,
        user_id: stored_token.user_id,
        scope: scope.clone(),
        expires_at: new_expires_at,
        revoked: false,
    };

    state
        .db
        .insert_refresh_token(&new_refresh_entry)
        .await
        .map_err(|e| {
            token_error(
                "server_error",
                &format!("failed to store refresh token: {e}"),
            )
        })?;

    // Build response with cache control headers
    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", HeaderValue::from_static("no-store"));
    headers.insert("Pragma", HeaderValue::from_static("no-cache"));

    let response_body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRY_SECS,
        "refresh_token": new_raw_token,
        "scope": scope,
    });

    Ok((StatusCode::OK, headers, Json(response_body)))
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Router,
    };
    use lambda_http::tower::ServiceExt;

    use crate::{
        db::{refresh_token::RefreshTokenTable, Database},
        jwt::{generate_es256_keypair, JwtKeys},
        state::AppState,
    };

    fn test_state() -> AppState {
        let (private_pem, _) = generate_es256_keypair().unwrap();
        let jwt_keys = JwtKeys::from_pem(private_pem.as_bytes(), "test-kid").unwrap();
        AppState {
            db: Database::memory(),
            jwt_keys: Some(jwt_keys),
        }
    }

    fn test_router(state: AppState) -> Router {
        Router::new()
            .route("/token", axum::routing::post(handler))
            .with_state(state)
    }

    async fn setup_refresh_token(state: &AppState, user_id: &str, scope: &str) -> String {
        let raw_token = generate_refresh_token().unwrap();
        let token_hash = hex::encode(Sha256::new().chain(raw_token.as_bytes()).finalize());
        let expires_at = chrono::Utc::now().timestamp() + REFRESH_TOKEN_EXPIRY_SECS;

        let entry = RefreshTokenTable {
            token_hash,
            user_id: user_id.to_string(),
            scope: scope.to_string(),
            expires_at,
            revoked: false,
        };

        state.db.insert_refresh_token(&entry).await.unwrap();
        raw_token
    }

    async fn setup_user(state: &AppState) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let user_id = state
            .db
            .insert_user(
                "test@example.com".to_string(),
                "hashed_pw".to_string(),
                now.clone(),
                now,
                vec!["openid".to_string(), "email".to_string()],
            )
            .await
            .unwrap();
        user_id.to_string()
    }

    #[tokio::test]
    async fn test_refresh_token_grant_success() {
        let state = test_state();
        let user_id = setup_user(&state).await;
        let raw_token = setup_refresh_token(&state, &user_id, "openid email").await;
        let app = test_router(state);

        let body = format!("grant_type=refresh_token&refresh_token={raw_token}");
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        assert_eq!(response.headers().get("Cache-Control").unwrap(), "no-store");
        assert_eq!(response.headers().get("Pragma").unwrap(), "no-cache");

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["expires_in"], 900);
        assert_eq!(json["scope"], "openid email");
        assert!(json["access_token"].is_string());
        assert!(json["refresh_token"].is_string());
    }

    #[tokio::test]
    async fn test_refresh_token_grant_rotates_token() {
        let state = test_state();
        let user_id = setup_user(&state).await;
        let raw_token = setup_refresh_token(&state, &user_id, "openid").await;
        let app = test_router(state.clone());

        let body = format!("grant_type=refresh_token&refresh_token={raw_token}");
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // The old token should now be revoked - using it again should fail
        let app2 = test_router(state);
        let body2 = format!("grant_type=refresh_token&refresh_token={raw_token}");
        let request2 = Request::builder()
            .method("POST")
            .uri("/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body2))
            .unwrap();

        let response2 = app2.oneshot(request2).await.unwrap();
        assert_eq!(response2.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response2.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_missing_refresh_token_param() {
        let state = test_state();
        let app = test_router(state);

        let body = "grant_type=refresh_token";
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn test_invalid_refresh_token() {
        let state = test_state();
        let app = test_router(state);

        let body = "grant_type=refresh_token&refresh_token=invalid_token_value";
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn test_unsupported_grant_type() {
        let state = test_state();
        let app = test_router(state);

        let body = "grant_type=client_credentials";
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn test_authorization_code_grant_unsupported() {
        let state = test_state();
        let app = test_router(state);

        let body = "grant_type=authorization_code&code=abc&redirect_uri=http://localhost";
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn test_no_jwt_keys_configured() {
        let state = AppState {
            db: Database::memory(),
            jwt_keys: None,
        };
        let user_id = setup_user(&state).await;
        let raw_token = setup_refresh_token(&state, &user_id, "openid").await;
        let app = test_router(state);

        let body = format!("grant_type=refresh_token&refresh_token={raw_token}");
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "server_error");
    }
}
