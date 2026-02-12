use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    error::AuthError,
    session::{create_session, generate_session_token, session_cookie},
    state::AppState,
    validation::{normalize_email, verify_email},
};

#[derive(Deserialize)]
pub struct RecoverPayload {
    email: String,
    recovery_code: String,
    #[serde(rename = "csrf_token")]
    _csrf_token: Option<String>,
}

pub async fn handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<RecoverPayload>,
) -> Response {
    match try_recover(state, headers, body).await {
        Ok(resp) => resp,
        Err(err) => {
            let msg = match &err {
                AuthError::Internal(_) => "An unexpected error occurred",
                AuthError::BadRequest(m)
                | AuthError::Unauthorized(m)
                | AuthError::Conflict(m)
                | AuthError::NotFound(m)
                | AuthError::TooManyRequests(m) => m,
            };
            let redirect_url = format!("/recover?error={}", urlencoding::encode(msg));
            Redirect::to(&redirect_url).into_response()
        }
    }
}

async fn try_recover(
    state: AppState,
    headers: HeaderMap,
    body: RecoverPayload,
) -> Result<Response, AuthError> {
    let normalized_email = normalize_email(&body.email);

    if body.email.is_empty() || body.recovery_code.is_empty() {
        return Err(AuthError::BadRequest(
            "Email and recovery code are required".to_string(),
        ));
    }

    if !verify_email(&normalized_email) {
        return Err(AuthError::BadRequest("Invalid email address".to_string()));
    }

    // Look up user by email
    let user = state
        .db
        .get_user_by_email(normalized_email)
        .await?
        .ok_or_else(|| AuthError::Unauthorized("Invalid email or recovery code".into()))?;

    // Hash the provided recovery code and check against stored hashes
    let code_hash = hex::encode(Sha256::digest(body.recovery_code.as_bytes()));

    if !user.recovery_codes.contains(&code_hash) {
        return Err(AuthError::Unauthorized(
            "Invalid email or recovery code".into(),
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

    // Redirect to passkeys management page
    Ok((response_headers, Redirect::to("/passkeys/manage")).into_response())
}
