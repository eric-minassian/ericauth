use axum::http::{header, HeaderMap};

use crate::error::AuthError;

pub(super) fn require_scim_admin_token(headers: &HeaderMap) -> Result<(), AuthError> {
    let expected = expected_scim_admin_token()
        .ok_or_else(|| AuthError::Unauthorized("SCIM admin token is not configured".into()))?;

    let provided = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| AuthError::Unauthorized("missing or invalid bearer token".into()))?;

    if provided != expected {
        return Err(AuthError::Unauthorized("invalid SCIM admin token".into()));
    }

    Ok(())
}

fn expected_scim_admin_token() -> Option<String> {
    expected_scim_admin_token_impl()
}

#[cfg(test)]
fn expected_scim_admin_token_impl() -> Option<String> {
    Some(std::env::var("SCIM_ADMIN_TOKEN").unwrap_or_else(|_| "test-scim-admin-token".to_string()))
}

#[cfg(not(test))]
fn expected_scim_admin_token_impl() -> Option<String> {
    std::env::var("SCIM_ADMIN_TOKEN").ok()
}
