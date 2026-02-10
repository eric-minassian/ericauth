use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

use crate::{
    password::verify_password_strength,
    session::{create_session, generate_session_token, session_cookie},
    state::AppState,
    user::create_user,
    validation::verify_email,
};

#[derive(Deserialize)]
pub struct SignupPayload {
    email: String,
    password: String,
}

pub async fn handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SignupPayload>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Check client IP
    let client_ip = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if client_ip.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "missing X-Forwarded-For header".to_string(),
        ));
    }

    // Validate input
    if body.email.is_empty() || body.password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "missing email or password".to_string(),
        ));
    }

    if !verify_email(&body.email) {
        return Err((StatusCode::BAD_REQUEST, "invalid email".to_string()));
    }

    // Check if email already in use
    if db_get_user_exists(&state, &body.email).await? {
        return Err((StatusCode::BAD_REQUEST, "email already in use".to_string()));
    }

    if !verify_password_strength(&body.password) {
        return Err((StatusCode::BAD_REQUEST, "password too weak".to_string()));
    }

    // Create user and session
    let user = create_user(&state.db, body.email, body.password)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let session_token = generate_session_token()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let session = create_session(&state.db, session_token.clone(), user.id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Build response with session cookie
    let (cookie_name, cookie_value) = session_cookie(&session_token, session.expires_at);
    let mut response_headers = HeaderMap::new();
    response_headers.insert(cookie_name, cookie_value.parse().unwrap());

    Ok((StatusCode::CREATED, response_headers))
}

async fn db_get_user_exists(state: &AppState, email: &str) -> Result<bool, (StatusCode, String)> {
    state
        .db
        .get_user_by_email(email.to_string())
        .await
        .map(|user| user.is_some())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))
}
