use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

use crate::{
    error::AuthError,
    password::verify_password_hash,
    session::{create_session, generate_session_token, session_cookie},
    state::AppState,
    validation::verify_email,
};

#[derive(Deserialize)]
pub struct LoginPayload {
    email: String,
    password: String,
}

pub async fn handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginPayload>,
) -> Result<impl IntoResponse, AuthError> {
    // Check client IP
    let client_ip = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if client_ip.is_empty() {
        return Err(AuthError::BadRequest(
            "missing X-Forwarded-For header".to_string(),
        ));
    }

    // Validate input
    if body.email.is_empty() || body.password.is_empty() {
        return Err(AuthError::BadRequest(
            "missing email or password".to_string(),
        ));
    }

    if !verify_email(&body.email) {
        return Err(AuthError::BadRequest("invalid email".to_string()));
    }

    // Look up user
    let user = state
        .db
        .get_user_by_email(body.email)
        .await?
        .ok_or(AuthError::Unauthorized(
            "invalid email or password".to_string(),
        ))?;

    // Verify password
    let valid = verify_password_hash(&body.password, &user.password_hash)
        .map_err(|e| AuthError::Internal(e.to_string()))?;

    if !valid {
        return Err(AuthError::Unauthorized(
            "invalid email or password".to_string(),
        ));
    }

    // Create session
    let session_token = generate_session_token()?;

    let session = create_session(&state.db, session_token.clone(), user.id).await?;

    // Build response with session cookie
    let (cookie_name, cookie_value) = session_cookie(&session_token, session.expires_at);
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        cookie_name,
        cookie_value
            .parse()
            .map_err(|e| AuthError::Internal(format!("Failed to build cookie header: {e}")))?,
    );

    Ok((StatusCode::NO_CONTENT, response_headers))
}
