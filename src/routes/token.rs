use std::collections::BTreeMap;

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
    audit::{append_event, token_error_code, AuditEventInput, ERROR_CODE_KEY},
    client_credentials,
    db::refresh_token::RefreshTokenTable,
    jwt::{AccessTokenClaims, IdTokenClaims},
    refresh_token::generate_refresh_token,
    state::AppState,
};

const ACCESS_TOKEN_EXPIRY_SECS: i64 = 900; // 15 minutes
const REFRESH_TOKEN_EXPIRY_SECS: i64 = 30 * 24 * 60 * 60; // 30 days
const ID_TOKEN_EXPIRY_SECS: i64 = 3600; // 1 hour

#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    refresh_token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scope: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
}

/// RFC 6749 Section 5.2 error response.
fn token_error(error: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

fn invalid_client_error(description: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        "WWW-Authenticate",
        HeaderValue::from_static(
            "Basic realm=\"token\", error=\"invalid_client\", error_description=\"client authentication failed\"",
        ),
    );

    (
        StatusCode::UNAUTHORIZED,
        headers,
        Json(json!({
            "error": "invalid_client",
            "error_description": description,
        })),
    )
        .into_response()
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
) -> Result<Response, Response> {
    let grant_type = body.grant_type.clone();
    let client_id = body.client_id.clone();
    let client_ip = None;
    let user_agent = None;
    let audit_db = state.db.clone();

    let response = match body.grant_type.as_str() {
        "refresh_token" => handle_refresh_token(state, body)
            .await
            .map(|r| r.into_response()),
        "authorization_code" => handle_authorization_code(state, body)
            .await
            .map(|r| r.into_response()),
        "client_credentials" => handle_client_credentials(state, body)
            .await
            .map(|r| r.into_response()),
        _ => Err(token_error(
            "unsupported_grant_type",
            &format!("grant_type '{}' is not supported", body.grant_type),
        )),
    };

    let audit_event =
        build_token_audit_event(&response, grant_type, client_id, client_ip, user_agent);
    if let Err(error) = append_event(audit_db.as_ref(), audit_event).await {
        tracing::warn!(error = %error, "Failed to append token audit event");
    }

    response
}

fn build_token_audit_event(
    response: &Result<Response, Response>,
    grant_type: String,
    client_id: Option<String>,
    client_ip: Option<String>,
    user_agent: Option<String>,
) -> AuditEventInput {
    let mut metadata = BTreeMap::new();
    metadata.insert("route".to_string(), "/token".to_string());
    metadata.insert("grant_type".to_string(), grant_type);

    let (outcome, status_code) = match response {
        Ok(success) => ("success".to_string(), success.status()),
        Err(failure) => ("failure".to_string(), failure.status()),
    };

    if outcome == "failure" {
        let mapped_code = if status_code == StatusCode::UNAUTHORIZED {
            token_error_code(Some("invalid_client"))
        } else {
            token_error_code(None)
        };
        metadata.insert(ERROR_CODE_KEY.to_string(), mapped_code.to_string());
        metadata.insert("http_status".to_string(), status_code.as_u16().to_string());
    }

    AuditEventInput {
        event_type: "oauth.token".to_string(),
        outcome,
        actor: client_id,
        client_ip,
        user_agent,
        metadata,
    }
}

async fn handle_client_credentials(
    state: AppState,
    body: TokenRequest,
) -> Result<impl IntoResponse, Response> {
    let client_id = body
        .client_id
        .ok_or_else(|| token_error("invalid_request", "client_id parameter is required"))?;

    let client = state
        .db
        .get_client(&client_id)
        .await
        .map_err(|e| token_error("server_error", &format!("failed to look up client: {e}")))?
        .ok_or_else(|| invalid_client_error("client authentication failed"))?;

    let is_authenticated =
        client_credentials::authenticate_client_secret_post(&client, body.client_secret.as_deref())
            .map_err(|_| token_error("server_error", "failed to verify client secret"))?;
    if !is_authenticated {
        return Err(invalid_client_error("client authentication failed"));
    }

    let scope = client_credentials::resolve_scope(&client, body.scope.as_deref())
        .map_err(|e| token_error("invalid_scope", e))?;

    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| token_error("server_error", "JWT signing is not configured"))?;

    let now = chrono::Utc::now().timestamp() as usize;
    let access_claims = AccessTokenClaims {
        iss: state.issuer_url,
        sub: client_id.clone(),
        aud: client_id,
        exp: now + ACCESS_TOKEN_EXPIRY_SECS as usize,
        iat: now,
        scope: scope.clone(),
        email: String::new(),
    };

    let access_token = jwt_keys
        .sign_access_token(&access_claims)
        .map_err(|e| token_error("server_error", &format!("failed to sign access token: {e}")))?;

    let response_body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRY_SECS,
        "scope": scope,
    });

    Ok((StatusCode::OK, cache_control_headers(), Json(response_body)))
}

async fn handle_authorization_code(
    state: AppState,
    body: TokenRequest,
) -> Result<impl IntoResponse, Response> {
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
        iss: state.issuer_url.clone(),
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
            iss: state.issuer_url.clone(),
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
) -> Result<impl IntoResponse, Response> {
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
        iss: state.issuer_url.clone(),
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
        db::{auth_code::AuthCodeTable, client::ClientTable, refresh_token::RefreshTokenTable},
        jwt::{generate_es256_keypair, JwtKeys},
        password::hash_password,
        state::AppState,
    };

    fn test_state() -> AppState {
        let (private_pem, _) = generate_es256_keypair().unwrap();
        let jwt_keys = JwtKeys::from_pem(private_pem.as_bytes(), "test-kid").unwrap();
        AppState {
            db: crate::db::memory(),
            jwt_keys: Some(jwt_keys),
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
            issuer_url: "https://auth.test.example.com".to_string(),
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
                client_secret_hash: None,
                token_endpoint_auth_method: "none".to_string(),
            })
            .await
            .unwrap();
    }

    async fn setup_machine_client_with_secret(
        state: &AppState,
        auth_method: &str,
        allowed_scopes: Vec<&str>,
    ) -> String {
        let client_secret = "machine-secret".to_string();
        let secret_hash = hash_password(&client_secret).unwrap();

        state
            .db
            .insert_client(ClientTable {
                client_id: "machine-client".to_string(),
                redirect_uris: vec![],
                allowed_scopes: allowed_scopes.iter().map(|s| s.to_string()).collect(),
                client_name: "Machine Client".to_string(),
                client_secret_hash: Some(secret_hash),
                token_endpoint_auth_method: auth_method.to_string(),
            })
            .await
            .unwrap();

        client_secret
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

        let body = "grant_type=password";
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
    async fn test_client_credentials_grant_success() {
        let state = test_state();
        let client_secret =
            setup_machine_client_with_secret(&state, "client_secret_post", vec!["api:read"]).await;
        let app = test_router(state);

        let body = format!(
            "grant_type=client_credentials&client_id=machine-client&client_secret={}&scope=api%3Aread",
            urlencoding::encode(&client_secret)
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
        assert_eq!(json["scope"], "api:read");
        assert!(json["access_token"].is_string());
        assert!(json.get("refresh_token").is_none());
    }

    #[tokio::test]
    async fn test_client_credentials_missing_client_id() {
        let state = test_state();
        let app = test_router(state);

        let body = "grant_type=client_credentials&scope=email";
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
    async fn test_client_credentials_invalid_secret_returns_401() {
        let state = test_state();
        setup_machine_client_with_secret(&state, "client_secret_post", vec!["api:read"]).await;
        let app = test_router(state);

        let body =
            "grant_type=client_credentials&client_id=machine-client&client_secret=wrong&scope=api%3Aread";
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key("WWW-Authenticate"));

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_client");
    }

    #[tokio::test]
    async fn test_client_credentials_missing_secret_returns_401() {
        let state = test_state();
        setup_machine_client_with_secret(&state, "client_secret_post", vec!["api:read"]).await;
        let app = test_router(state);

        let body = "grant_type=client_credentials&client_id=machine-client&scope=api%3Aread";
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key("WWW-Authenticate"));

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_client");
    }

    #[tokio::test]
    async fn test_client_credentials_unsupported_auth_method_returns_401() {
        let state = test_state();
        let client_secret =
            setup_machine_client_with_secret(&state, "none", vec!["api:read"]).await;
        let app = test_router(state);

        let body = format!(
            "grant_type=client_credentials&client_id=machine-client&client_secret={}&scope=api%3Aread",
            urlencoding::encode(&client_secret)
        );
        let request = Request::builder()
            .method("POST")
            .uri("/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "invalid_client");
    }

    #[tokio::test]
    async fn test_client_credentials_invalid_scope() {
        let state = test_state();
        let client_secret =
            setup_machine_client_with_secret(&state, "client_secret_post", vec!["api:read"]).await;
        let app = test_router(state);

        let body = format!(
            "grant_type=client_credentials&client_id=machine-client&client_secret={}&scope=admin",
            urlencoding::encode(&client_secret)
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
        assert_eq!(json["error"], "invalid_scope");
    }

    #[tokio::test]
    async fn test_client_credentials_rejects_openid_scope() {
        let state = test_state();
        let client_secret = setup_machine_client_with_secret(
            &state,
            "client_secret_post",
            vec!["api:read", "openid"],
        )
        .await;
        let app = test_router(state);

        let body = format!(
            "grant_type=client_credentials&client_id=machine-client&client_secret={}&scope=openid",
            urlencoding::encode(&client_secret)
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
        assert_eq!(json["error"], "invalid_scope");
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
            db: crate::db::memory(),
            jwt_keys: None,
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
            issuer_url: "https://auth.test.example.com".to_string(),
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
