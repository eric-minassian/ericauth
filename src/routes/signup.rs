use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

use crate::{
    error::AuthError,
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

    // Check if email already in use
    if state
        .db
        .get_user_by_email(body.email.clone())
        .await?
        .is_some()
    {
        return Err(AuthError::Conflict("email already in use".to_string()));
    }

    if !verify_password_strength(&body.password) {
        return Err(AuthError::BadRequest("password too weak".to_string()));
    }

    // Create user and session
    let user = create_user(&state.db, body.email, body.password).await?;

    let session_token = generate_session_token()?;

    let session = create_session(
        &state.db,
        session_token.clone(),
        user.id,
        client_ip.to_string(),
    )
    .await?;

    // Build response with session cookie
    let (cookie_name, cookie_value) = session_cookie(&session_token, session.expires_at);
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        cookie_name,
        cookie_value
            .parse()
            .map_err(|e| AuthError::Internal(format!("Failed to build cookie header: {e}")))?,
    );

    Ok((StatusCode::CREATED, response_headers))
}
