use askama::Template;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use chrono::Utc;
use serde::Deserialize;

use crate::{
    error::AuthError,
    middleware::{auth::AuthenticatedUser, csrf::CsrfToken},
    password::{hash_password, verify_password_hash, verify_password_strength},
    state::AppState,
    templates::render,
    user::generate_recovery_codes,
};

#[derive(Deserialize)]
pub struct AccountQuery {
    notice: Option<String>,
    error: Option<String>,
}

pub struct SessionEntry {
    pub id: String,
    pub device_name: String,
    pub ip_address: String,
    pub created_at: String,
    pub last_seen_at: String,
    pub expires_at: String,
    pub is_current: bool,
}

#[derive(Template)]
#[template(path = "account.html")]
struct AccountTemplate {
    csrf_token: String,
    email: String,
    has_password_login: bool,
    passkey_count: usize,
    recovery_codes_remaining: usize,
    session_count: usize,
    notice: Option<String>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "account_sessions.html")]
struct AccountSessionsTemplate {
    csrf_token: String,
    sessions: Vec<SessionEntry>,
    notice: Option<String>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "account_password.html")]
struct AccountPasswordTemplate {
    csrf_token: String,
    has_password_login: bool,
    notice: Option<String>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "recovery_codes.html")]
struct RecoveryCodesTemplate {
    recovery_codes: Vec<String>,
}

#[derive(Deserialize)]
pub struct RevokeSessionPayload {
    session_id: String,
    #[serde(rename = "csrf_token")]
    _csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub struct RevokeOthersPayload {
    #[serde(rename = "csrf_token")]
    _csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub struct ChangePasswordPayload {
    current_password: String,
    new_password: String,
    confirm_password: String,
    #[serde(rename = "csrf_token")]
    _csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub struct RegenerateRecoveryCodesPayload {
    #[serde(rename = "csrf_token")]
    _csrf_token: Option<String>,
}

pub async fn handler(
    Extension(csrf): Extension<CsrfToken>,
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<AccountQuery>,
) -> Result<impl IntoResponse, AuthError> {
    let user_record = state
        .db
        .get_user_by_id(&user.user_id.to_string())
        .await?
        .ok_or_else(|| AuthError::NotFound("user not found".to_string()))?;

    let credentials = state
        .db
        .get_credentials_by_user_id(&user.user_id.to_string())
        .await?;

    let session_count = state
        .db
        .get_sessions_by_user_id(&user.user_id.to_string())
        .await?
        .len();

    render(&AccountTemplate {
        csrf_token: csrf.0,
        email: user_record.email,
        has_password_login: user_record.password_hash.is_some(),
        passkey_count: credentials.len(),
        recovery_codes_remaining: user_record.recovery_codes.len(),
        session_count,
        notice: map_notice(query.notice),
        error: map_error(query.error),
    })
}

pub async fn sessions_page_handler(
    Extension(csrf): Extension<CsrfToken>,
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<AccountQuery>,
) -> Result<impl IntoResponse, AuthError> {
    let sessions = load_sessions(&state, &user).await?;

    render(&AccountSessionsTemplate {
        csrf_token: csrf.0,
        sessions,
        notice: map_notice(query.notice),
        error: map_error(query.error),
    })
}

pub async fn password_page_handler(
    Extension(csrf): Extension<CsrfToken>,
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<AccountQuery>,
) -> Result<impl IntoResponse, AuthError> {
    let user_record = state
        .db
        .get_user_by_id(&user.user_id.to_string())
        .await?
        .ok_or_else(|| AuthError::NotFound("user not found".to_string()))?;

    render(&AccountPasswordTemplate {
        csrf_token: csrf.0,
        has_password_login: user_record.password_hash.is_some(),
        notice: map_notice(query.notice),
        error: map_error(query.error),
    })
}

pub async fn revoke_session_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Form(body): Form<RevokeSessionPayload>,
) -> Response {
    match try_revoke_session(state, user, body).await {
        Ok(()) => Redirect::to("/account/sessions?notice=session_revoked").into_response(),
        Err(message) => Redirect::to(&format!(
            "/account/sessions?error={}",
            urlencoding::encode(&message)
        ))
        .into_response(),
    }
}

pub async fn revoke_other_sessions_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Form(_body): Form<RevokeOthersPayload>,
) -> Response {
    match try_revoke_other_sessions(state, user).await {
        Ok(revoked_count) => {
            let notice = if revoked_count == 0 {
                "no_other_sessions"
            } else {
                "other_sessions_revoked"
            };
            Redirect::to(&format!("/account/sessions?notice={notice}")).into_response()
        }
        Err(message) => Redirect::to(&format!(
            "/account/sessions?error={}",
            urlencoding::encode(&message)
        ))
        .into_response(),
    }
}

pub async fn change_password_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Form(body): Form<ChangePasswordPayload>,
) -> Response {
    match try_change_password(state, user, body).await {
        Ok(()) => Redirect::to("/account/password?notice=password_updated").into_response(),
        Err(message) => Redirect::to(&format!(
            "/account/password?error={}",
            urlencoding::encode(&message)
        ))
        .into_response(),
    }
}

pub async fn regenerate_recovery_codes_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Form(_body): Form<RegenerateRecoveryCodesPayload>,
) -> Response {
    match try_regenerate_recovery_codes(state, user).await {
        Ok(codes) => match render(&RecoveryCodesTemplate {
            recovery_codes: codes,
        }) {
            Ok(html) => html.into_response(),
            Err(_) => Redirect::to("/account?error=Failed%20to%20render%20recovery%20codes")
                .into_response(),
        },
        Err(message) => Redirect::to(&format!("/account?error={}", urlencoding::encode(&message)))
            .into_response(),
    }
}

async fn load_sessions(
    state: &AppState,
    user: &AuthenticatedUser,
) -> Result<Vec<SessionEntry>, AuthError> {
    let mut sessions = state
        .db
        .get_sessions_by_user_id(&user.user_id.to_string())
        .await?;
    sessions.sort_by_key(|session| std::cmp::Reverse(session.last_seen_at));

    Ok(sessions
        .into_iter()
        .map(|session| SessionEntry {
            id: session.id.clone(),
            device_name: device_name(session.user_agent.as_deref()),
            ip_address: session.ip_address,
            created_at: format_timestamp(session.created_at),
            last_seen_at: format_timestamp(session.last_seen_at),
            expires_at: format_timestamp(session.expires_at),
            is_current: session.id == user.session_id,
        })
        .collect())
}

async fn try_revoke_session(
    state: AppState,
    user: AuthenticatedUser,
    body: RevokeSessionPayload,
) -> Result<(), String> {
    if body.session_id == user.session_id {
        return Err("Use Log Out to end your current session".to_string());
    }

    let sessions = state
        .db
        .get_sessions_by_user_id(&user.user_id.to_string())
        .await
        .map_err(|_| "Failed to load sessions".to_string())?;

    let owns_session = sessions.iter().any(|session| session.id == body.session_id);
    if !owns_session {
        return Err("Session not found".to_string());
    }

    state
        .db
        .delete_session(&body.session_id)
        .await
        .map_err(|_| "Failed to revoke session".to_string())?;

    Ok(())
}

async fn try_revoke_other_sessions(
    state: AppState,
    user: AuthenticatedUser,
) -> Result<usize, String> {
    let sessions = state
        .db
        .get_sessions_by_user_id(&user.user_id.to_string())
        .await
        .map_err(|_| "Failed to load sessions".to_string())?;

    let other_session_ids: Vec<String> = sessions
        .into_iter()
        .filter(|session| session.id != user.session_id)
        .map(|session| session.id)
        .collect();

    for session_id in &other_session_ids {
        state
            .db
            .delete_session(session_id)
            .await
            .map_err(|_| "Failed to revoke sessions".to_string())?;
    }

    Ok(other_session_ids.len())
}

async fn try_change_password(
    state: AppState,
    user: AuthenticatedUser,
    body: ChangePasswordPayload,
) -> Result<(), String> {
    if body.current_password.trim().is_empty()
        || body.new_password.trim().is_empty()
        || body.confirm_password.trim().is_empty()
    {
        return Err("All password fields are required".to_string());
    }

    if body.new_password != body.confirm_password {
        return Err("New password and confirmation do not match".to_string());
    }

    if !verify_password_strength(&body.new_password) {
        return Err("New password does not meet requirements".to_string());
    }

    let user_record = state
        .db
        .get_user_by_id(&user.user_id.to_string())
        .await
        .map_err(|_| "Failed to load user".to_string())?
        .ok_or_else(|| "User not found".to_string())?;

    let existing_hash = user_record
        .password_hash
        .ok_or_else(|| "Password login is not enabled for this account".to_string())?;

    let valid_current = verify_password_hash(&body.current_password, &existing_hash)
        .map_err(|_| "Failed to verify current password".to_string())?;
    if !valid_current {
        return Err("Current password is incorrect".to_string());
    }

    let new_hash =
        hash_password(&body.new_password).map_err(|_| "Failed to update password".to_string())?;
    let updated_at = Utc::now().to_rfc3339();

    state
        .db
        .update_password_hash(&user.user_id.to_string(), new_hash, &updated_at)
        .await
        .map_err(|_| "Failed to persist password update".to_string())?;

    let _ = try_revoke_other_sessions(state, user).await;

    Ok(())
}

async fn try_regenerate_recovery_codes(
    state: AppState,
    user: AuthenticatedUser,
) -> Result<Vec<String>, String> {
    let codes = generate_recovery_codes(8).map_err(|_| "Failed to generate recovery codes")?;
    let updated_at = Utc::now().to_rfc3339();

    state
        .db
        .replace_recovery_codes(&user.user_id.to_string(), codes.hashed_codes, &updated_at)
        .await
        .map_err(|_| "Failed to update recovery codes".to_string())?;

    Ok(codes.plaintext_codes)
}

fn map_notice(notice: Option<String>) -> Option<String> {
    match notice.as_deref() {
        Some("session_revoked") => Some("The selected session has been signed out.".to_string()),
        Some("other_sessions_revoked") => Some("Other sessions have been signed out.".to_string()),
        Some("no_other_sessions") => Some("No other active sessions found.".to_string()),
        Some("password_updated") => {
            Some("Password updated. Other devices were signed out.".to_string())
        }
        _ => None,
    }
}

fn map_error(error: Option<String>) -> Option<String> {
    error.filter(|e| !e.trim().is_empty())
}

fn format_timestamp(timestamp: i64) -> String {
    if timestamp <= 0 {
        return "Unknown".to_string();
    }

    chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

fn device_name(user_agent: Option<&str>) -> String {
    let ua = match user_agent {
        Some(value) if !value.trim().is_empty() => value.to_ascii_lowercase(),
        _ => return "Unknown device".to_string(),
    };

    let platform = if ua.contains("iphone") || ua.contains("ipad") {
        "iOS"
    } else if ua.contains("android") {
        "Android"
    } else if ua.contains("mac os") || ua.contains("macintosh") {
        "macOS"
    } else if ua.contains("windows") {
        "Windows"
    } else if ua.contains("linux") {
        "Linux"
    } else {
        "Device"
    };

    let browser = if ua.contains("edg/") {
        "Edge"
    } else if ua.contains("chrome/") && !ua.contains("edg/") {
        "Chrome"
    } else if ua.contains("firefox/") {
        "Firefox"
    } else if ua.contains("safari/") && !ua.contains("chrome/") {
        "Safari"
    } else {
        "Browser"
    };

    format!("{platform} - {browser}")
}
