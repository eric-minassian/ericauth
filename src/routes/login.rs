use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

use crate::{
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

    // Look up user
    let user = state
        .db
        .get_user_by_email(body.email)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "invalid email or password".to_string(),
        ))?;

    // Verify password
    let valid = verify_password_hash(&body.password, &user.password_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            "invalid email or password".to_string(),
        ));
    }

    // Create session
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

    Ok((StatusCode::NO_CONTENT, response_headers))
}
