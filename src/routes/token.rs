use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Form, Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use sha2::{digest::Update, Digest, Sha256};

use crate::{
    db::refresh_token::RefreshTokenTable,
    jwt::{AccessTokenClaims, IdTokenClaims},
    refresh_token::generate_refresh_token,
    state::AppState,
};

const ISSUER: &str = "https://auth.ericminassian.com";
const ACCESS_TOKEN_EXPIRY_SECS: i64 = 900; // 15 minutes
const REFRESH_TOKEN_EXPIRY_SECS: i64 = 30 * 24 * 60 * 60; // 30 days
const ID_TOKEN_EXPIRY_SECS: i64 = 3600; // 1 hour

#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    refresh_token: Option<String>,
    client_id: Option<String>,
    scope: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
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

fn cache_control_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", HeaderValue::from_static("no-store"));
    headers.insert("Pragma", HeaderValue::from_static("no-cache"));
    headers
}

pub async fn handler(
    State(state): State<AppState>,
    Form(body): Form<TokenRequest>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    match body.grant_type.as_str() {
        "refresh_token" => handle_refresh_token(state, body)
            .await
            .map(|r| r.into_response()),
        "authorization_code" => handle_authorization_code(state, body)
            .await
            .map(|r| r.into_response()),
        _ => Err(token_error(
            "unsupported_grant_type",
            &format!("grant_type '{}' is not supported", body.grant_type),
        )),
    }
}

async fn handle_authorization_code(
    state: AppState,
    body: TokenRequest,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // Validate required fields
    let raw_code = body
        .code
        .ok_or_else(|| token_error("invalid_request", "code parameter is required"))?;
    let redirect_uri = body
        .redirect_uri
        .ok_or_else(|| token_error("invalid_request", "redirect_uri parameter is required"))?;
    let client_id = body
        .client_id
        .ok_or_else(|| token_error("invalid_request", "client_id parameter is required"))?;
    let code_verifier = body
        .code_verifier
        .ok_or_else(|| token_error("invalid_request", "code_verifier parameter is required"))?;

    // Hash the code for lookup
    let code_hash = hex::encode(Sha256::new().chain(raw_code.as_bytes()).finalize());

    // Redeem the auth code (atomic single-use)
    let auth_code = state
        .db
        .redeem_auth_code(&code_hash)
        .await
        .map_err(|e| token_error("server_error", &format!("failed to redeem auth code: {e}")))?
        .ok_or_else(|| token_error("invalid_grant", "authorization code is invalid or expired"))?;

    // Verify client_id matches
    if auth_code.client_id != client_id {
        return Err(token_error("invalid_grant", "client_id mismatch"));
    }

    // Verify redirect_uri matches exactly
    if auth_code.redirect_uri != redirect_uri {
        return Err(token_error("invalid_grant", "redirect_uri mismatch"));
    }

    // Validate PKCE: BASE64URL(SHA256(code_verifier)) == stored code_challenge
    let verifier_hash = Sha256::new().chain(code_verifier.as_bytes()).finalize();
    let computed_challenge = URL_SAFE_NO_PAD.encode(verifier_hash);

    if computed_challenge != auth_code.code_challenge {
        return Err(token_error("invalid_grant", "PKCE verification failed"));
    }

    // Get JWT keys
    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| token_error("server_error", "JWT signing is not configured"))?;

    // Look up user
    let user = state
        .db
        .get_user_by_id(&auth_code.user_id)
        .await
        .map_err(|e| token_error("server_error", &format!("failed to look up user: {e}")))?
        .ok_or_else(|| token_error("invalid_grant", "user not found"))?;

    let now = chrono::Utc::now().timestamp() as usize;
    let scope = auth_code.scope.clone();

    // Sign access token
    let access_claims = AccessTokenClaims {
        iss: ISSUER.to_string(),
        sub: auth_code.user_id.clone(),
        aud: client_id.clone(),
        exp: now + ACCESS_TOKEN_EXPIRY_SECS as usize,
        iat: now,
        scope: scope.clone(),
        email: user.email.clone(),
    };

    let access_token = jwt_keys
        .sign_access_token(&access_claims)
        .map_err(|e| token_error("server_error", &format!("failed to sign access token: {e}")))?;

    // Generate and store refresh token
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
        user_id: auth_code.user_id.clone(),
        client_id: client_id.clone(),
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

    // Build response
    let mut response_body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRY_SECS,
        "refresh_token": new_raw_token,
        "scope": scope,
    });

    // If scope contains "openid", issue an ID token
    let scopes: Vec<&str> = scope.split_whitespace().collect();
    if scopes.contains(&"openid") {
        let id_claims = IdTokenClaims {
            iss: ISSUER.to_string(),
            sub: auth_code.user_id,
            aud: client_id,
            exp: now + ID_TOKEN_EXPIRY_SECS as usize,
            iat: now,
            auth_time: auth_code.auth_time as usize,
            nonce: auth_code.nonce,
            email: user.email,
            email_verified: true,
        };

        let id_token = jwt_keys
            .sign_id_token(&id_claims)
            .map_err(|e| token_error("server_error", &format!("failed to sign ID token: {e}")))?;

        response_body["id_token"] = json!(id_token);
    }

    Ok((StatusCode::OK, cache_control_headers(), Json(response_body)))
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

    // Validate client_id matches if provided
    if let Some(ref req_client_id) = body.client_id {
        if *req_client_id != stored_token.client_id {
            return Err(token_error("invalid_grant", "client_id mismatch"));
        }
    }

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
    let scope = match body.scope {
        Some(ref requested) => {
            let stored_scopes: std::collections::HashSet<&str> =
                stored_token.scope.split_whitespace().collect();
            for s in requested.split_whitespace() {
                if !stored_scopes.contains(s) {
                    return Err(token_error(
                        "invalid_scope",
                        &format!("scope '{}' was not in the original grant", s),
                    ));
                }
            }
            requested.clone()
        }
        None => stored_token.scope.clone(),
    };

    // Sign new access token
    let access_claims = AccessTokenClaims {
        iss: ISSUER.to_string(),
        sub: stored_token.user_id.clone(),
        aud: stored_token.client_id.clone(),
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
        client_id: stored_token.client_id.clone(),
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

    let response_body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRY_SECS,
        "refresh_token": new_raw_token,
        "scope": scope,
    });

    Ok((StatusCode::OK, cache_control_headers(), Json(response_body)))
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
        db::{
            auth_code::AuthCodeTable, client::ClientTable, refresh_token::RefreshTokenTable,
            Database,
        },
        jwt::{generate_es256_keypair, JwtKeys},
        state::AppState,
    };

    fn test_state() -> AppState {
        let (private_pem, _) = generate_es256_keypair().unwrap();
        let jwt_keys = JwtKeys::from_pem(private_pem.as_bytes(), "test-kid").unwrap();
        AppState {
            db: Database::memory(),
            jwt_keys: Some(jwt_keys),
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
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
            client_id: "test-client".to_string(),
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
                Some("hashed_pw".to_string()),
                now.clone(),
                now,
                vec!["openid".to_string(), "email".to_string()],
                vec![],
            )
            .await
            .unwrap();
        user_id.to_string()
    }

    async fn setup_client(state: &AppState) {
        state
            .db
            .insert_client(ClientTable {
                client_id: "test-client".to_string(),
                redirect_uris: vec!["http://localhost/callback".to_string()],
                allowed_scopes: vec![
                    "openid".to_string(),
                    "email".to_string(),
                    "profile".to_string(),
                ],
                client_name: "Test App".to_string(),
            })
            .await
            .unwrap();
    }

    /// Create an auth code with PKCE. Returns (raw_code, code_verifier).
    async fn setup_auth_code(state: &AppState, user_id: &str, scope: &str) -> (String, String) {
        // Generate a code verifier
        let mut verifier_bytes = [0u8; 32];
        getrandom::fill(&mut verifier_bytes).unwrap();
        let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

        // Compute challenge
        let challenge_hash = Sha256::new().chain(code_verifier.as_bytes()).finalize();
        let code_challenge = URL_SAFE_NO_PAD.encode(challenge_hash);

        // Generate raw code
        let mut code_bytes = [0u8; 32];
        getrandom::fill(&mut code_bytes).unwrap();
        let raw_code = URL_SAFE_NO_PAD.encode(code_bytes);
        let code_hash = hex::encode(Sha256::new().chain(raw_code.as_bytes()).finalize());

        let now = chrono::Utc::now().timestamp();

        let auth_code = AuthCodeTable {
            code: code_hash,
            client_id: "test-client".to_string(),
            user_id: user_id.to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
            scope: scope.to_string(),
            code_challenge,
            nonce: Some("test-nonce".to_string()),
            auth_time: now,
            expires_at: now + 600,
            used_at: None,
        };

        state.db.insert_auth_code(&auth_code).await.unwrap();
        (raw_code, code_verifier)
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
    async fn test_authorization_code_grant_success() {
        let state = test_state();
        let user_id = setup_user(&state).await;
        setup_client(&state).await;
        let (raw_code, code_verifier) = setup_auth_code(&state, &user_id, "openid email").await;
        let app = test_router(state);

        let body = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
            raw_code,
            urlencoding::encode("http://localhost/callback"),
            "test-client",
            code_verifier,
        );
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
        // ID token should be present since scope includes "openid"
        assert!(json["id_token"].is_string());
    }

    #[tokio::test]
    async fn test_authorization_code_single_use() {
        let state = test_state();
        let user_id = setup_user(&state).await;
        setup_client(&state).await;
        let (raw_code, code_verifier) = setup_auth_code(&state, &user_id, "openid email").await;

        // First use should succeed
        let app = test_router(state.clone());
        let body = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
            raw_code,
            urlencoding::encode("http://localhost/callback"),
            "test-client",
            code_verifier,
        );
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Second use should fail
        let app2 = test_router(state);
        let body2 = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
            raw_code,
            urlencoding::encode("http://localhost/callback"),
            "test-client",
            code_verifier,
        );
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
    async fn test_authorization_code_wrong_pkce() {
        let state = test_state();
        let user_id = setup_user(&state).await;
        setup_client(&state).await;
        let (raw_code, _code_verifier) = setup_auth_code(&state, &user_id, "openid email").await;
        let app = test_router(state);

        let body = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
            raw_code,
            urlencoding::encode("http://localhost/callback"),
            "test-client",
            "wrong-verifier-value",
        );
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
        assert!(json["error_description"].as_str().unwrap().contains("PKCE"));
    }

    #[tokio::test]
    async fn test_authorization_code_wrong_redirect_uri() {
        let state = test_state();
        let user_id = setup_user(&state).await;
        setup_client(&state).await;
        let (raw_code, code_verifier) = setup_auth_code(&state, &user_id, "openid email").await;
        let app = test_router(state);

        let body = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
            raw_code,
            urlencoding::encode("http://evil.com/callback"),
            "test-client",
            code_verifier,
        );
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
    async fn test_no_jwt_keys_configured() {
        let state = AppState {
            db: Database::memory(),
            jwt_keys: None,
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
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
