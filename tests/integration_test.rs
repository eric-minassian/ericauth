use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use lambda_http::tower::ServiceExt;
use sha2::{digest::Update, Digest, Sha256};

use ericauth::{
    db::{refresh_token::RefreshTokenTable, Database},
    jwt::{generate_es256_keypair, JwtKeys},
    refresh_token::generate_refresh_token,
    routes,
    state::AppState,
};

fn test_state() -> AppState {
    let (private_pem, _) = generate_es256_keypair().unwrap();
    let jwt_keys = JwtKeys::from_pem(private_pem.as_bytes(), "test-kid").unwrap();
    let webauthn = std::sync::Arc::new(
        ericauth::webauthn_config::build_webauthn().expect("Failed to initialize WebAuthn"),
    );
    AppState {
        db: Database::memory(),
        jwt_keys: Some(jwt_keys),
        webauthn,
    }
}

fn test_router(state: AppState) -> axum::Router {
    routes::router(state)
}

/// CSRF cookie value used in tests. The CSRF middleware checks that the
/// `__csrf` cookie matches the `csrf_token` form field.
const CSRF_TOKEN: &str = "test-csrf-token";
const CSRF_COOKIE: &str = "__csrf=test-csrf-token";

/// Build a form-urlencoded body for signup/login with CSRF token included.
fn form_body(email: &str, password: &str) -> String {
    format!(
        "email={}&password={}&csrf_token={}",
        urlencoding::encode(email),
        urlencoding::encode(password),
        CSRF_TOKEN,
    )
}

// --- Health endpoint ---

#[tokio::test]
async fn test_health_endpoint() {
    let state = test_state();
    let app = test_router(state);

    let request = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// --- Signup flow ---

#[tokio::test]
async fn test_signup_creates_session() {
    let state = test_state();
    let app = test_router(state);

    let request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body("user@example.com", "StrongP@ss123")))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Should have a session cookie
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(set_cookie.starts_with("session="));
}

#[tokio::test]
async fn test_signup_duplicate_email_fails() {
    let state = test_state();

    // First signup
    let app = test_router(state.clone());
    let request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body("dup@example.com", "StrongP@ss123")))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Second signup with same email should fail
    let app = test_router(state);
    let request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body("dup@example.com", "StrongP@ss123")))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_signup_missing_forwarded_for_fails() {
    let state = test_state();
    let app = test_router(state);

    let request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .body(Body::from(form_body("noip@example.com", "StrongP@ss123")))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_signup_weak_password_fails() {
    let state = test_state();
    let app = test_router(state);

    let request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body("weak@example.com", "short")))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// --- Login flow ---

#[tokio::test]
async fn test_signup_then_login() {
    let state = test_state();

    // Signup
    let app = test_router(state.clone());
    let request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body("login@example.com", "StrongP@ss123")))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Login with same credentials
    let app = test_router(state);
    let request = Request::builder()
        .method("POST")
        .uri("/login")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body("login@example.com", "StrongP@ss123")))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Should have a session cookie
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(set_cookie.starts_with("session="));
}

#[tokio::test]
async fn test_login_wrong_password_fails() {
    let state = test_state();

    // Signup
    let app = test_router(state.clone());
    let request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body(
            "wrongpw@example.com",
            "StrongP@ss123",
        )))
        .unwrap();

    app.oneshot(request).await.unwrap();

    // Login with wrong password
    let app = test_router(state);
    let request = Request::builder()
        .method("POST")
        .uri("/login")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body(
            "wrongpw@example.com",
            "WrongP@ssword1",
        )))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_login_nonexistent_user_fails() {
    let state = test_state();
    let app = test_router(state);

    let request = Request::builder()
        .method("POST")
        .uri("/login")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body(
            "noexist@example.com",
            "StrongP@ss123",
        )))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// --- Session validation ---

#[tokio::test]
async fn test_session_cookie_grants_access_to_protected_route() {
    let state = test_state();

    // Signup to get a session
    let app = test_router(state.clone());
    let request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body(
            "session@example.com",
            "StrongP@ss123",
        )))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Extract session cookie
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    let session_value = set_cookie.split(';').next().unwrap(); // "session=..."

    // Use session to access /passkeys/manage (requires AuthenticatedUser)
    let app = test_router(state);
    let request = Request::builder()
        .uri("/passkeys/manage")
        .header("Cookie", session_value)
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_no_session_returns_unauthorized() {
    let state = test_state();
    let app = test_router(state);

    // Access protected route without session
    let request = Request::builder()
        .uri("/passkeys/manage")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// --- Logout ---

#[tokio::test]
async fn test_logout_invalidates_session() {
    let state = test_state();

    // Signup to get a session
    let app = test_router(state.clone());
    let request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body("logout@example.com", "StrongP@ss123")))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    let session_value = set_cookie.split(';').next().unwrap();

    // Logout
    let app = test_router(state.clone());
    let request = Request::builder()
        .method("POST")
        .uri("/logout")
        .header("Cookie", session_value)
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Session should now be invalid
    let app = test_router(state);
    let request = Request::builder()
        .uri("/passkeys/manage")
        .header("Cookie", session_value)
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// --- Refresh token rotation ---

#[tokio::test]
async fn test_refresh_token_rotation() {
    let state = test_state();

    // Create a user and a refresh token directly
    let now = chrono::Utc::now().to_rfc3339();
    let user_id = state
        .db
        .insert_user(
            "refresh@example.com".to_string(),
            "hashed_pw".to_string(),
            now.clone(),
            now,
            vec!["openid".to_string()],
            vec![],
        )
        .await
        .unwrap();

    let raw_token = generate_refresh_token().unwrap();
    let token_hash = hex::encode(Sha256::new().chain(raw_token.as_bytes()).finalize());
    let entry = RefreshTokenTable {
        token_hash,
        user_id: user_id.to_string(),
        scope: "openid".to_string(),
        expires_at: chrono::Utc::now().timestamp() + 86400,
        revoked: false,
    };
    state.db.insert_refresh_token(&entry).await.unwrap();

    // Exchange the refresh token
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

    let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&response_body).unwrap();
    assert!(json["access_token"].is_string());
    assert!(json["refresh_token"].is_string());
    assert_eq!(json["token_type"], "Bearer");
    let new_refresh = json["refresh_token"].as_str().unwrap();

    // Old token should be revoked -- using it again should fail
    let app = test_router(state.clone());
    let body = format!("grant_type=refresh_token&refresh_token={raw_token}");
    let request = Request::builder()
        .method("POST")
        .uri("/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // New token should work
    let app = test_router(state);
    let body = format!("grant_type=refresh_token&refresh_token={new_refresh}");
    let request = Request::builder()
        .method("POST")
        .uri("/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// --- Token revocation ---

#[tokio::test]
async fn test_token_revocation() {
    let state = test_state();

    // Create a refresh token directly
    let now = chrono::Utc::now().to_rfc3339();
    let user_id = state
        .db
        .insert_user(
            "revoke@example.com".to_string(),
            "hashed_pw".to_string(),
            now.clone(),
            now,
            vec!["openid".to_string()],
            vec![],
        )
        .await
        .unwrap();

    let raw_token = generate_refresh_token().unwrap();
    let token_hash = hex::encode(Sha256::new().chain(raw_token.as_bytes()).finalize());
    let entry = RefreshTokenTable {
        token_hash,
        user_id: user_id.to_string(),
        scope: "openid".to_string(),
        expires_at: chrono::Utc::now().timestamp() + 86400,
        revoked: false,
    };
    state.db.insert_refresh_token(&entry).await.unwrap();

    // Revoke the token
    let app = test_router(state.clone());
    let body = format!("token={raw_token}");
    let request = Request::builder()
        .method("POST")
        .uri("/token/revoke")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Using the revoked token should fail
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
}

// --- Login page serves HTML ---

#[tokio::test]
async fn test_login_page_returns_html() {
    let state = test_state();
    let app = test_router(state);

    let request = Request::builder()
        .uri("/login")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("text/html"));
}

#[tokio::test]
async fn test_signup_page_returns_html() {
    let state = test_state();
    let app = test_router(state);

    let request = Request::builder()
        .uri("/signup")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("text/html"));
}

// --- JWKS endpoint ---

#[tokio::test]
async fn test_jwks_endpoint() {
    let state = test_state();
    let app = test_router(state);

    let request = Request::builder()
        .uri("/.well-known/jwks.json")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let keys = json["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "EC");
    assert_eq!(keys[0]["crv"], "P-256");
    assert_eq!(keys[0]["alg"], "ES256");
}
