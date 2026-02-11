use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    error::AuthError,
    session::{create_session, generate_session_token, session_cookie},
    state::AppState,
    validation::verify_email,
};

#[derive(Deserialize)]
pub struct RecoverPayload {
    email: String,
    recovery_code: String,
}

pub async fn handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RecoverPayload>,
) -> Result<impl IntoResponse, AuthError> {
    if body.email.is_empty() || body.recovery_code.is_empty() {
        return Err(AuthError::BadRequest(
            "missing email or recovery_code".to_string(),
        ));
    }

    if !verify_email(&body.email) {
        return Err(AuthError::BadRequest("invalid email".to_string()));
    }

    // Look up user by email
    let user = state
        .db
        .get_user_by_email(body.email)
        .await?
        .ok_or_else(|| AuthError::Unauthorized("invalid email or recovery code".into()))?;

    // Hash the provided recovery code and check against stored hashes
    let code_hash = hex::encode(Sha256::digest(body.recovery_code.as_bytes()));

    if !user.recovery_codes.contains(&code_hash) {
        return Err(AuthError::Unauthorized(
            "invalid email or recovery code".into(),
        ));
    }

    // Remove the used recovery code
    state
        .db
        .remove_recovery_code(&user.id.to_string(), &code_hash)
        .await?;

    // Extract client IP
    let client_ip = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Create session
    let session_token = generate_session_token()?;
    let session = create_session(&state.db, session_token.clone(), user.id, client_ip).await?;

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
