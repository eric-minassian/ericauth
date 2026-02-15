use std::collections::BTreeMap;

use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    audit::{append_event, auth_error_code, AuditEventInput, ERROR_CODE_KEY},
    db::Database,
    error::AuthError,
    oauth::build_oauth_qs,
    password::verify_password_strength,
    session::{create_session, generate_session_token, session_cookie},
    state::AppState,
    templates::{render, RecoveryCodesTemplate},
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

pub async fn handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<SignupPayload>,
) -> Response {
    let submitted_email = if body.email.trim().is_empty() {
        None
    } else {
        Some(body.email.trim().to_string())
    };

    // Build OAuth query string for error redirects before consuming body
    let error_qs = build_oauth_qs(&[
        ("email", &submitted_email),
        ("client_id", &body.client_id),
        ("redirect_uri", &body.redirect_uri),
        ("response_type", &body.response_type),
        ("scope", &body.scope),
        ("state", &body.state),
        ("code_challenge", &body.code_challenge),
        ("code_challenge_method", &body.code_challenge_method),
        ("nonce", &body.nonce),
    ]);

    let client_ip = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let audit_db = state.db.clone();

    match try_signup(state, headers, body).await {
        Ok(resp) => {
            emit_signup_audit_event(
                audit_db.as_ref(),
                "success",
                submitted_email.clone(),
                client_ip.clone(),
                user_agent.clone(),
                None,
            )
            .await;
            resp
        }
        Err(err) => {
            emit_signup_audit_event(
                audit_db.as_ref(),
                "failure",
                submitted_email.clone(),
                client_ip.clone(),
                user_agent.clone(),
                Some(auth_error_code(&err).to_string()),
            )
            .await;
            let msg = match &err {
                AuthError::Internal(_) => "An unexpected error occurred",
                AuthError::BadRequest(m)
                | AuthError::Unauthorized(m)
                | AuthError::Forbidden(m)
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

async fn emit_signup_audit_event(
    db: &dyn Database,
    outcome: &str,
    actor: Option<String>,
    client_ip: Option<String>,
    user_agent: Option<String>,
    error_code: Option<String>,
) {
    let mut metadata = BTreeMap::new();
    metadata.insert("route".to_string(), "/signup".to_string());
    if let Some(code) = error_code {
        metadata.insert(ERROR_CODE_KEY.to_string(), code);
    }

    if let Err(error) = append_event(
        db,
        AuditEventInput {
            event_type: "auth.signup".to_string(),
            outcome: outcome.to_string(),
            actor,
            client_ip,
            user_agent,
            metadata,
        },
    )
    .await
    {
        tracing::warn!(error = %error, "Failed to append signup audit event");
    }
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
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);

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
    let user = create_user(state.db.as_ref(), normalized_email, body.password).await?;

    let verification_token = generate_email_verification_token();
    state
        .db
        .insert_email_verification(&verification_token, &user.id.to_string(), 60 * 60 * 24)
        .await?;

    let session_token = generate_session_token()?;

    let session = create_session(
        state.db.as_ref(),
        session_token.clone(),
        user.id,
        client_ip.to_string(),
        user_agent,
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

fn generate_email_verification_token() -> String {
    Uuid::new_v4().simple().to_string()
}
