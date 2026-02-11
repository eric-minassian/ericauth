use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    Form, Json,
};
use serde::{Deserialize, Serialize};

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
    // OAuth2 pass-through fields
    client_id: Option<String>,
    redirect_uri: Option<String>,
    response_type: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

#[derive(Serialize)]
pub struct SignupResponse {
    recovery_codes: Vec<String>,
}

pub async fn handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<SignupPayload>,
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

    // If OAuth2 params are present, redirect to /authorize
    if body.client_id.is_some() && body.redirect_uri.is_some() {
        let mut authorize_url = "/authorize?".to_string();
        authorize_url.push_str(&format!(
            "client_id={}&redirect_uri={}",
            urlencoding::encode(body.client_id.as_deref().unwrap_or("")),
            urlencoding::encode(body.redirect_uri.as_deref().unwrap_or("")),
        ));
        if let Some(rt) = &body.response_type {
            authorize_url.push_str(&format!("&response_type={}", urlencoding::encode(rt)));
        }
        if let Some(sc) = &body.scope {
            authorize_url.push_str(&format!("&scope={}", urlencoding::encode(sc)));
        }
        if let Some(s) = &body.state {
            authorize_url.push_str(&format!("&state={}", urlencoding::encode(s)));
        }
        if let Some(cc) = &body.code_challenge {
            authorize_url.push_str(&format!("&code_challenge={}", urlencoding::encode(cc)));
        }
        if let Some(ccm) = &body.code_challenge_method {
            authorize_url.push_str(&format!(
                "&code_challenge_method={}",
                urlencoding::encode(ccm)
            ));
        }
        if let Some(n) = &body.nonce {
            authorize_url.push_str(&format!("&nonce={}", urlencoding::encode(n)));
        }

        return Ok((response_headers, Redirect::temporary(&authorize_url)).into_response());
    }

    let response_body = SignupResponse {
        recovery_codes: user.recovery_codes,
    };

    Ok((StatusCode::CREATED, response_headers, Json(response_body)).into_response())
}
