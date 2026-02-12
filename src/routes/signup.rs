use askama::Template;
use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;

use crate::{
    error::AuthError,
    password::verify_password_strength,
    session::{create_session, generate_session_token, session_cookie},
    state::AppState,
    templates::render,
    user::create_user,
    validation::{normalize_email, verify_email},
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

#[derive(Template)]
#[template(path = "recovery_codes.html")]
struct RecoveryCodesTemplate {
    recovery_codes: Vec<String>,
}

pub async fn handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<SignupPayload>,
) -> Response {
    // Build OAuth query string for error redirects before consuming body
    let error_qs = build_oauth_qs(&[
        ("client_id", &body.client_id),
        ("redirect_uri", &body.redirect_uri),
        ("response_type", &body.response_type),
        ("scope", &body.scope),
        ("state", &body.state),
        ("code_challenge", &body.code_challenge),
        ("code_challenge_method", &body.code_challenge_method),
        ("nonce", &body.nonce),
    ]);

    match try_signup(state, headers, body).await {
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
            let redirect_url = if error_qs.is_empty() {
                format!("/signup?error={}", urlencoding::encode(msg))
            } else {
                format!("/signup?error={}&{}", urlencoding::encode(msg), error_qs)
            };
            Redirect::to(&redirect_url).into_response()
        }
    }
}

fn build_oauth_qs(params: &[(&str, &Option<String>)]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for &(key, value) in params {
        if let Some(v) = value {
            parts.push(format!("{}={}", key, urlencoding::encode(v)));
        }
    }
    parts.join("&")
}

async fn try_signup(
    state: AppState,
    headers: HeaderMap,
    body: SignupPayload,
) -> Result<Response, AuthError> {
    let normalized_email = normalize_email(&body.email);

    // Extract client IP
    let client_ip = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Validate input
    if body.email.is_empty() || body.password.is_empty() {
        return Err(AuthError::BadRequest(
            "Email and password are required".to_string(),
        ));
    }

    if !verify_email(&normalized_email) {
        return Err(AuthError::BadRequest("Invalid email address".to_string()));
    }

    // Check if email already in use
    if state
        .db
        .get_user_by_email(normalized_email.clone())
        .await?
        .is_some()
    {
        return Err(AuthError::Conflict(
            "An account with this email already exists".to_string(),
        ));
    }

    if !verify_password_strength(&body.password) {
        return Err(AuthError::BadRequest(
            "Password does not meet requirements".to_string(),
        ));
    }

    // Create user and session
    let user = create_user(&state.db, normalized_email, body.password).await?;

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
        let authorize_url = format!(
            "/authorize?{}",
            super::authorize::build_oauth_query_string(
                body.client_id.as_deref().unwrap_or(""),
                body.redirect_uri.as_deref().unwrap_or(""),
                body.scope.as_deref().unwrap_or(""),
                body.state.as_deref(),
                body.code_challenge.as_deref().unwrap_or(""),
                body.code_challenge_method.as_deref().unwrap_or(""),
                body.nonce.as_deref(),
            )
        );
        return Ok((response_headers, Redirect::to(&authorize_url)).into_response());
    }

    // Render recovery codes page
    let html = render(&RecoveryCodesTemplate {
        recovery_codes: user.recovery_codes,
    })?;

    Ok((response_headers, html).into_response())
}
