use axum::{
    extract::{Request, State},
    http::Method,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    admin_rbac::{has_admin_permission, AdminPermission},
    db,
    error::AuthError,
    state::AppState,
};

pub async fn admin_auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let permission = required_permission(request.method(), request.uri().path())
        .map_err(IntoResponse::into_response)?;

    let session_token = extract_session_token(&request).map_err(IntoResponse::into_response)?;
    let session = db::get_session_by_token(state.db.as_ref(), session_token)
        .await
        .map_err(IntoResponse::into_response)?;

    let user = state
        .db
        .get_user_by_id(&session.user_id.to_string())
        .await
        .map_err(IntoResponse::into_response)?
        .ok_or_else(|| AuthError::Unauthorized("user not found".to_string()).into_response())?;

    if has_admin_permission(&user.scopes, permission) {
        return Ok(next.run(request).await);
    }

    Err(AuthError::Forbidden("insufficient_scope".to_string()).into_response())
}

fn required_permission(method: &Method, path: &str) -> Result<AdminPermission, AuthError> {
    match (method, path) {
        (&Method::GET, "/audit/events") => Ok(AdminPermission::ReadAuditEvents),
        (&Method::POST, "/audit/events") => Ok(AdminPermission::WriteAuditEvents),
        _ => Err(AuthError::Forbidden("insufficient_scope".to_string())),
    }
}

fn extract_session_token(request: &Request) -> Result<&str, AuthError> {
    let cookie_header = request
        .headers()
        .get(axum::http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AuthError::Unauthorized("missing session cookie".to_string()))?;

    let token = cookie_header
        .split(';')
        .map(str::trim)
        .find_map(|cookie| cookie.strip_prefix("session="))
        .ok_or_else(|| AuthError::Unauthorized("missing session cookie".to_string()))?;

    if token.is_empty() {
        return Err(AuthError::Unauthorized(
            "missing session cookie".to_string(),
        ));
    }

    Ok(token)
}
