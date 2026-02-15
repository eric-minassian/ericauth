use askama::Template;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use chrono::Utc;
use getrandom::fill;
use serde::Deserialize;

use crate::{
    error::AuthError,
    middleware::csrf::CsrfToken,
    password::{hash_password, verify_password_strength},
    state::AppState,
    templates::render,
    validation::normalize_email,
};

#[derive(Deserialize)]
pub struct ResetPasswordQuery {
    token: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct ResetPasswordPayload {
    token: String,
    new_password: String,
    confirm_password: String,
    #[serde(rename = "csrf_token")]
    _csrf_token: Option<String>,
}

#[derive(Template)]
#[template(path = "reset_password.html")]
struct ResetPasswordTemplate {
    csrf_token: String,
    token: String,
    error: Option<String>,
}

pub async fn get_handler(
    Extension(csrf): Extension<CsrfToken>,
    Query(query): Query<ResetPasswordQuery>,
) -> Result<impl IntoResponse, AuthError> {
    let token = query.token.unwrap_or_default();
    render(&ResetPasswordTemplate {
        csrf_token: csrf.0,
        token,
        error: query.error,
    })
}

pub async fn post_handler(
    State(state): State<AppState>,
    Form(payload): Form<ResetPasswordPayload>,
) -> Response {
    match consume_reset_token(
        &state,
        &payload.token,
        &payload.new_password,
        &payload.confirm_password,
    )
    .await
    {
        Ok(()) => Redirect::to("/login?notice=Password%20updated").into_response(),
        Err(message) => Redirect::to(&format!(
            "/reset-password?token={}&error={}",
            urlencoding::encode(payload.token.trim()),
            urlencoding::encode(&message)
        ))
        .into_response(),
    }
}

pub async fn issue_reset_token(state: &AppState, email: &str) -> Result<Option<String>, AuthError> {
    let normalized_email = normalize_email(email);
    let user = match state.db.get_user_by_email(normalized_email).await? {
        Some(user) => user,
        None => return Ok(None),
    };

    let mut token_bytes = [0u8; 24];
    fill(&mut token_bytes)
        .map_err(|e| AuthError::Internal(format!("token generation failed: {e}")))?;
    let token = hex::encode(token_bytes);

    state
        .db
        .insert_password_reset_token(&token, &user.id.to_string(), 3600)
        .await?;

    Ok(Some(token))
}

pub async fn consume_reset_token(
    state: &AppState,
    token: &str,
    new_password: &str,
    confirm_password: &str,
) -> Result<(), String> {
    if token.trim().is_empty() {
        return Err("Invalid or expired reset token".to_string());
    }

    if new_password.trim().is_empty() || confirm_password.trim().is_empty() {
        return Err("Both password fields are required".to_string());
    }

    if new_password != confirm_password {
        return Err("New password and confirmation do not match".to_string());
    }

    if !verify_password_strength(new_password) {
        return Err("New password does not meet requirements".to_string());
    }

    let reset = state
        .db
        .redeem_password_reset_token(token.trim())
        .await
        .map_err(|_| "Invalid or expired reset token".to_string())?
        .ok_or_else(|| "Invalid or expired reset token".to_string())?;

    let password_hash =
        hash_password(new_password).map_err(|_| "Failed to update password".to_string())?;
    let updated_at = Utc::now().to_rfc3339();

    state
        .db
        .update_password_hash(&reset.user_id, password_hash, &updated_at)
        .await
        .map_err(|_| "Failed to persist password update".to_string())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{password::verify_password_hash, state::AppState, user::create_user};

    #[tokio::test]
    async fn test_issue_reset_token_for_existing_user() {
        let state = AppState {
            db: crate::db::memory(),
            jwt_keys: None,
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
            issuer_url: "https://auth.test.example.com".to_string(),
        };

        let user = create_user(
            state.db.as_ref(),
            "forgot.user@example.com".to_string(),
            "Password123!".to_string(),
        )
        .await
        .unwrap();

        let token = super::issue_reset_token(&state, "forgot.user@example.com")
            .await
            .unwrap()
            .expect("expected token to be issued");

        let redeemed = state
            .db
            .redeem_password_reset_token(&token)
            .await
            .unwrap()
            .expect("expected token to redeem once");
        assert_eq!(redeemed.user_id, user.id.to_string());
    }

    #[tokio::test]
    async fn test_token_is_single_use() {
        let state = AppState {
            db: crate::db::memory(),
            jwt_keys: None,
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
            issuer_url: "https://auth.test.example.com".to_string(),
        };

        create_user(
            state.db.as_ref(),
            "single.use.reset@example.com".to_string(),
            "Password123!".to_string(),
        )
        .await
        .unwrap();

        let token = super::issue_reset_token(&state, "single.use.reset@example.com")
            .await
            .unwrap()
            .expect("expected token to be issued");

        let first =
            super::consume_reset_token(&state, &token, "Password456!", "Password456!").await;
        assert!(first.is_ok());

        let second =
            super::consume_reset_token(&state, &token, "Password789!", "Password789!").await;
        assert!(second.is_err());
    }

    #[tokio::test]
    async fn test_consume_token_updates_password_hash() {
        let state = AppState {
            db: crate::db::memory(),
            jwt_keys: None,
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
            issuer_url: "https://auth.test.example.com".to_string(),
        };

        let user = create_user(
            state.db.as_ref(),
            "reset.password@example.com".to_string(),
            "Password123!".to_string(),
        )
        .await
        .unwrap();

        let token = super::issue_reset_token(&state, "reset.password@example.com")
            .await
            .unwrap()
            .expect("expected token to be issued");

        super::consume_reset_token(&state, &token, "Password456!", "Password456!")
            .await
            .expect("expected reset to succeed");

        let updated_user = state
            .db
            .get_user_by_id(&user.id.to_string())
            .await
            .unwrap()
            .expect("expected user to exist");

        let valid = verify_password_hash(
            "Password456!",
            updated_user
                .password_hash
                .as_deref()
                .expect("password hash missing"),
        )
        .unwrap();
        assert!(valid);
    }
}
