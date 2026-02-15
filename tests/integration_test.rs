use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use lambda_http::tower::ServiceExt;
use sha2::{digest::Update, Digest, Sha256};

use ericauth::{
    db::refresh_token::RefreshTokenTable,
    jwt::{generate_es256_keypair, JwtKeys},
    refresh_token::generate_refresh_token,
    routes,
    session::{create_session, generate_session_token},
    state::AppState,
};

fn test_state() -> AppState {
    let (private_pem, _) = generate_es256_keypair().unwrap();
    let jwt_keys = JwtKeys::from_pem(private_pem.as_bytes(), "test-kid").unwrap();
    let webauthn = std::sync::Arc::new(
        ericauth::webauthn_config::build_webauthn().expect("Failed to initialize WebAuthn"),
    );
    AppState {
        db: ericauth::db::memory(),
        jwt_keys: Some(jwt_keys),
        webauthn,
        issuer_url: "https://auth.test.example.com".to_string(),
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

fn extract_session_cookie(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_string()
}

fn session_id_from_cookie(session_cookie: &str) -> String {
    let token = session_cookie
        .strip_prefix("session=")
        .expect("session cookie should start with session=");
    hex::encode(Sha256::new().chain(token.as_bytes()).finalize())
}

async fn create_admin_session_cookie(state: &AppState) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let user_id = state
        .db
        .insert_user(
            "audit-admin@example.com".to_string(),
            Some("hashed_pw".to_string()),
            now.clone(),
            now,
            vec!["admin".to_string()],
            vec![],
        )
        .await
        .unwrap();

    let token = generate_session_token().unwrap();
    create_session(
        state.db.as_ref(),
        token.clone(),
        user_id,
        "127.0.0.1".to_string(),
        Some("integration-test".to_string()),
    )
    .await
    .unwrap();

    format!("session={token}")
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
    assert_eq!(response.status(), StatusCode::OK);

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
    assert_eq!(response.status(), StatusCode::OK);

    // Second signup with same email should redirect with error
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
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("error="));
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
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("error="));
    assert!(location.contains("email=weak%40example.com"));
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
    assert_eq!(response.status(), StatusCode::OK);

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
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(location, "/account");

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
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("error="));
    assert!(location.contains("email=wrongpw%40example.com"));
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
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("error="));
}

#[tokio::test]
async fn test_recover_wrong_code_preserves_email() {
    let state = test_state();

    // Create a user first.
    let app = test_router(state.clone());
    let signup_request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body(
            "recover@example.com",
            "StrongP@ss123",
        )))
        .unwrap();
    let signup_response = app.oneshot(signup_request).await.unwrap();
    assert_eq!(signup_response.status(), StatusCode::OK);

    // Recover with wrong code should redirect and keep email.
    let app = test_router(state);
    let recover_body = format!(
        "email={}&recovery_code={}&csrf_token={}",
        urlencoding::encode("recover@example.com"),
        urlencoding::encode("WRONGCODE123"),
        CSRF_TOKEN,
    );
    let recover_request = Request::builder()
        .method("POST")
        .uri("/recover")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(recover_body))
        .unwrap();

    let response = app.oneshot(recover_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("error="));
    assert!(location.contains("email=recover%40example.com"));
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
    assert_eq!(response.status(), StatusCode::OK);

    // Extract session cookie
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    let session_value = set_cookie.split(';').next().unwrap(); // "session=..."

    // Use session to access /account (requires AuthenticatedUser)
    let app = test_router(state);
    let request = Request::builder()
        .uri("/account")
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
        .uri("/account")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_audit_events_rejects_anonymous_read_and_write() {
    let state = test_state();

    let app = test_router(state.clone());
    let read_request = Request::builder()
        .method("GET")
        .uri("/audit/events")
        .body(Body::empty())
        .unwrap();
    let read_response = app.oneshot(read_request).await.unwrap();
    assert_eq!(read_response.status(), StatusCode::UNAUTHORIZED);

    let app = test_router(state);
    let write_request = Request::builder()
        .method("POST")
        .uri("/audit/events")
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"event_type":"manual.test","outcome":"success"}"#,
        ))
        .unwrap();
    let write_response = app.oneshot(write_request).await.unwrap();
    assert_eq!(write_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_login_failure_audit_metadata_is_sanitized() {
    let state = test_state();
    let email = "audit-sanitize@example.com";

    let app = test_router(state.clone());
    let signup_request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body(email, "StrongP@ss123")))
        .unwrap();
    let signup_response = app.oneshot(signup_request).await.unwrap();
    assert_eq!(signup_response.status(), StatusCode::OK);

    let app = test_router(state.clone());
    let failed_login = Request::builder()
        .method("POST")
        .uri("/login")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body(email, "WrongP@ssword1")))
        .unwrap();
    let failed_login_response = app.oneshot(failed_login).await.unwrap();
    assert_eq!(failed_login_response.status(), StatusCode::SEE_OTHER);

    let admin_session_cookie = create_admin_session_cookie(&state).await;

    let app = test_router(state);
    let list_request = Request::builder()
        .method("GET")
        .uri("/audit/events")
        .header("Cookie", admin_session_cookie)
        .body(Body::empty())
        .unwrap();
    let list_response = app.oneshot(list_request).await.unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(list_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let events: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let event = events
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|entry| {
            entry["event_type"] == "auth.login"
                && entry["outcome"] == "failure"
                && entry["actor"] == email
        })
        .unwrap();

    assert!(event["metadata"]["error_code"].is_string());
    assert!(event["metadata"].get("error").is_none());
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
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(location, "/login");

    // Session should now be invalid
    let app = test_router(state);
    let request = Request::builder()
        .uri("/account")
        .header("Cookie", session_value)
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_revoke_other_sessions_keeps_current_session() {
    let state = test_state();

    // Signup creates initial session.
    let app = test_router(state.clone());
    let signup_request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body(
            "multisession@example.com",
            "StrongP@ss123",
        )))
        .unwrap();
    let signup_response = app.oneshot(signup_request).await.unwrap();
    let signup_cookie = extract_session_cookie(
        signup_response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap(),
    );

    // Login creates a second session that will become current.
    let app = test_router(state.clone());
    let login_request = Request::builder()
        .method("POST")
        .uri("/login")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body(
            "multisession@example.com",
            "StrongP@ss123",
        )))
        .unwrap();
    let login_response = app.oneshot(login_request).await.unwrap();
    let current_cookie = extract_session_cookie(
        login_response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap(),
    );

    // Revoke all other sessions from current session.
    let app = test_router(state.clone());
    let revoke_request = Request::builder()
        .method("POST")
        .uri("/account/sessions/revoke-others")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", format!("{current_cookie}; {CSRF_COOKIE}"))
        .body(Body::from(format!("csrf_token={}", CSRF_TOKEN)))
        .unwrap();
    let revoke_response = app.oneshot(revoke_request).await.unwrap();
    assert_eq!(revoke_response.status(), StatusCode::SEE_OTHER);

    // Original session should be invalid now.
    let app = test_router(state.clone());
    let old_session_request = Request::builder()
        .uri("/account")
        .header("Cookie", signup_cookie)
        .body(Body::empty())
        .unwrap();
    let old_session_response = app.oneshot(old_session_request).await.unwrap();
    assert_eq!(old_session_response.status(), StatusCode::UNAUTHORIZED);

    // Current session remains valid.
    let app = test_router(state);
    let current_request = Request::builder()
        .uri("/account")
        .header("Cookie", current_cookie)
        .body(Body::empty())
        .unwrap();
    let current_response = app.oneshot(current_request).await.unwrap();
    assert_eq!(current_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_revoke_single_session_by_id() {
    let state = test_state();

    // Signup creates initial session.
    let app = test_router(state.clone());
    let signup_request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body(
            "single-revoke@example.com",
            "StrongP@ss123",
        )))
        .unwrap();
    let signup_response = app.oneshot(signup_request).await.unwrap();
    let old_cookie = extract_session_cookie(
        signup_response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap(),
    );
    let old_session_id = session_id_from_cookie(&old_cookie);

    // Login creates the current session.
    let app = test_router(state.clone());
    let login_request = Request::builder()
        .method("POST")
        .uri("/login")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body(
            "single-revoke@example.com",
            "StrongP@ss123",
        )))
        .unwrap();
    let login_response = app.oneshot(login_request).await.unwrap();
    let current_cookie = extract_session_cookie(
        login_response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap(),
    );

    // Revoke old session by id.
    let app = test_router(state.clone());
    let revoke_request = Request::builder()
        .method("POST")
        .uri("/account/sessions/revoke")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", format!("{current_cookie}; {CSRF_COOKIE}"))
        .body(Body::from(format!(
            "session_id={}&csrf_token={}",
            urlencoding::encode(&old_session_id),
            CSRF_TOKEN
        )))
        .unwrap();
    let revoke_response = app.oneshot(revoke_request).await.unwrap();
    assert_eq!(revoke_response.status(), StatusCode::SEE_OTHER);

    // Revoked session should no longer be usable.
    let app = test_router(state.clone());
    let old_request = Request::builder()
        .uri("/account")
        .header("Cookie", old_cookie)
        .body(Body::empty())
        .unwrap();
    let old_response = app.oneshot(old_request).await.unwrap();
    assert_eq!(old_response.status(), StatusCode::UNAUTHORIZED);

    // Current session remains valid.
    let app = test_router(state);
    let current_request = Request::builder()
        .uri("/account")
        .header("Cookie", current_cookie)
        .body(Body::empty())
        .unwrap();
    let current_response = app.oneshot(current_request).await.unwrap();
    assert_eq!(current_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_change_password_invalidates_old_password_login() {
    let state = test_state();

    // Signup first user and get a session.
    let app = test_router(state.clone());
    let signup_request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body(
            "password-change@example.com",
            "StrongP@ss123",
        )))
        .unwrap();
    let signup_response = app.oneshot(signup_request).await.unwrap();
    let current_cookie = extract_session_cookie(
        signup_response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap(),
    );

    // Change password while authenticated.
    let app = test_router(state.clone());
    let change_password_body = format!(
        "current_password={}&new_password={}&confirm_password={}&csrf_token={}",
        urlencoding::encode("StrongP@ss123"),
        urlencoding::encode("NewStrongP@ss456!"),
        urlencoding::encode("NewStrongP@ss456!"),
        CSRF_TOKEN,
    );
    let change_password_request = Request::builder()
        .method("POST")
        .uri("/account/password")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", format!("{current_cookie}; {CSRF_COOKIE}"))
        .body(Body::from(change_password_body))
        .unwrap();
    let change_password_response = app.oneshot(change_password_request).await.unwrap();
    assert_eq!(change_password_response.status(), StatusCode::SEE_OTHER);

    // Old password should fail.
    let app = test_router(state.clone());
    let old_login_request = Request::builder()
        .method("POST")
        .uri("/login")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body(
            "password-change@example.com",
            "StrongP@ss123",
        )))
        .unwrap();
    let old_login_response = app.oneshot(old_login_request).await.unwrap();
    assert_eq!(old_login_response.status(), StatusCode::SEE_OTHER);
    let old_login_location = old_login_response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(old_login_location.contains("error="));

    // New password should succeed.
    let app = test_router(state);
    let new_login_request = Request::builder()
        .method("POST")
        .uri("/login")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body(
            "password-change@example.com",
            "NewStrongP@ss456!",
        )))
        .unwrap();
    let new_login_response = app.oneshot(new_login_request).await.unwrap();
    assert_eq!(new_login_response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn test_regenerate_recovery_codes_updates_stored_codes() {
    let state = test_state();

    // Signup first user and get a session.
    let app = test_router(state.clone());
    let signup_request = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", CSRF_COOKIE)
        .header("X-Forwarded-For", "1.2.3.4")
        .body(Body::from(form_body(
            "recovery-rotate@example.com",
            "StrongP@ss123",
        )))
        .unwrap();
    let signup_response = app.oneshot(signup_request).await.unwrap();
    let current_cookie = extract_session_cookie(
        signup_response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap(),
    );
    let user_before = state
        .db
        .get_user_by_email("recovery-rotate@example.com".to_string())
        .await
        .unwrap()
        .unwrap();

    // Regenerate recovery codes.
    let app = test_router(state.clone());
    let regenerate_request = Request::builder()
        .method("POST")
        .uri("/account/recovery-codes/regenerate")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cookie", format!("{current_cookie}; {CSRF_COOKIE}"))
        .body(Body::from(format!("csrf_token={}", CSRF_TOKEN)))
        .unwrap();
    let regenerate_response = app.oneshot(regenerate_request).await.unwrap();
    assert_eq!(regenerate_response.status(), StatusCode::OK);

    // Stored hashed codes should have changed and still contain expected number.
    let user_after = state
        .db
        .get_user_by_email("recovery-rotate@example.com".to_string())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(user_after.recovery_codes.len(), 8);
    assert_ne!(user_before.recovery_codes, user_after.recovery_codes);
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
            Some("hashed_pw".to_string()),
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
        client_id: "test-client".to_string(),
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
            Some("hashed_pw".to_string()),
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
        client_id: "test-client".to_string(),
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

#[tokio::test]
async fn test_favicon_route_returns_svg() {
    let state = test_state();
    let app = test_router(state);

    let request = Request::builder()
        .uri("/favicon.ico")
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
    assert!(content_type.contains("image/svg+xml"));
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
