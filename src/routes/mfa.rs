use askama::Template;
use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    encryption,
    error::AuthError,
    mfa::{
        generate_totp_secret, hash_backup_code, verify_totp_code, TOTP_STEP_SECONDS, TOTP_WINDOW,
    },
    middleware::{auth::AuthenticatedUser, csrf::CsrfToken},
    session::{create_session, generate_session_token, session_cookie},
    state::AppState,
    templates::{render, RecoveryCodesTemplate},
    user::generate_recovery_codes,
};

const MAX_MFA_CHALLENGE_ATTEMPTS: u8 = 5;

#[derive(Serialize, Deserialize, Clone)]
pub struct OauthContext {
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub response_type: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct LoginMfaChallengeState {
    user_id: String,
    oauth: OauthContext,
    failed_attempts: u8,
}

#[derive(Serialize, Deserialize)]
struct SetupMfaChallengeState {
    user_id: String,
    secret: String,
}

#[derive(Template)]
#[template(path = "mfa_setup.html")]
struct MfaSetupTemplate {
    csrf_token: String,
    challenge_id: String,
    secret: String,
    otpauth_uri: String,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "mfa_challenge.html")]
struct MfaChallengeTemplate {
    csrf_token: String,
    challenge_id: String,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct MfaSetupQuery {
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct MfaChallengeQuery {
    challenge_id: String,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct MfaSetupPayload {
    challenge_id: String,
    code: String,
    #[serde(rename = "csrf_token")]
    _csrf_token: Option<String>,
}

#[derive(Deserialize)]
pub struct MfaChallengePayload {
    challenge_id: String,
    code: String,
    #[serde(rename = "csrf_token")]
    _csrf_token: Option<String>,
}

pub async fn setup_get_handler(
    Extension(csrf): Extension<CsrfToken>,
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<MfaSetupQuery>,
) -> Result<impl IntoResponse, AuthError> {
    let user_record = state
        .db
        .get_user_by_id(&user.user_id.to_string())
        .await?
        .ok_or_else(|| AuthError::NotFound("user not found".to_string()))?;

    let secret = generate_totp_secret().map_err(|e| AuthError::Internal(e.to_string()))?;
    let setup_state = SetupMfaChallengeState {
        user_id: user.user_id.to_string(),
        secret: secret.clone(),
    };

    let challenge_id = Uuid::new_v4().to_string();
    let challenge_data = serde_json::to_string(&setup_state)
        .map_err(|e| AuthError::Internal(format!("Failed to serialize MFA setup state: {e}")))?;
    state
        .db
        .insert_challenge(&challenge_id, &challenge_data, 300)
        .await?;

    let label = format!("EricAuth:{}", user_record.email);
    let otpauth_uri = format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period={}",
        urlencoding::encode(&label),
        secret,
        urlencoding::encode("EricAuth"),
        TOTP_STEP_SECONDS
    );

    render(&MfaSetupTemplate {
        csrf_token: csrf.0,
        challenge_id,
        secret,
        otpauth_uri,
        error: query.error,
    })
}

pub async fn setup_post_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Form(body): Form<MfaSetupPayload>,
) -> Response {
    match try_setup_post(state, user, body).await {
        Ok(resp) => resp,
        Err(err) => {
            let msg = match &err {
                AuthError::Internal(_) => "An unexpected error occurred",
                AuthError::BadRequest(m)
                | AuthError::Unauthorized(m)
                | AuthError::Forbidden(m)
                | AuthError::Conflict(m)
                | AuthError::NotFound(m)
                | AuthError::TooManyRequests(m) => m,
            };
            Redirect::to(&format!("/mfa/setup?error={}", urlencoding::encode(msg))).into_response()
        }
    }
}

pub async fn challenge_get_handler(
    Extension(csrf): Extension<CsrfToken>,
    Query(query): Query<MfaChallengeQuery>,
) -> Result<impl IntoResponse, AuthError> {
    render(&MfaChallengeTemplate {
        csrf_token: csrf.0,
        challenge_id: query.challenge_id,
        error: query.error,
    })
}

pub async fn challenge_post_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<MfaChallengePayload>,
) -> Response {
    match try_challenge_post(state, headers, body).await {
        Ok(resp) => resp,
        Err(err) => {
            let msg = match &err {
                AuthError::Internal(_) => "An unexpected error occurred",
                AuthError::BadRequest(m)
                | AuthError::Unauthorized(m)
                | AuthError::Forbidden(m)
                | AuthError::Conflict(m)
                | AuthError::NotFound(m)
                | AuthError::TooManyRequests(m) => m,
            };
            Redirect::to(&format!("/login?error={}", urlencoding::encode(msg))).into_response()
        }
    }
}

pub fn serialize_login_challenge_state(
    user_id: Uuid,
    oauth: OauthContext,
) -> Result<String, AuthError> {
    serde_json::to_string(&LoginMfaChallengeState {
        user_id: user_id.to_string(),
        oauth,
        failed_attempts: 0,
    })
    .map_err(|e| AuthError::Internal(format!("Failed to serialize MFA challenge state: {e}")))
}

async fn try_setup_post(
    state: AppState,
    user: AuthenticatedUser,
    body: MfaSetupPayload,
) -> Result<Response, AuthError> {
    let challenge_data = state
        .db
        .get_and_delete_challenge(&body.challenge_id)
        .await?;

    let challenge_state: SetupMfaChallengeState = serde_json::from_str(&challenge_data)
        .map_err(|e| AuthError::Internal(format!("Failed to deserialize MFA setup state: {e}")))?;

    if challenge_state.user_id != user.user_id.to_string() {
        return Err(AuthError::Unauthorized("invalid MFA setup state".into()));
    }

    let valid = verify_totp_code(
        &challenge_state.secret,
        &body.code,
        Utc::now().timestamp(),
        TOTP_STEP_SECONDS,
        TOTP_WINDOW,
    )
    .map_err(|e| AuthError::BadRequest(e.to_string()))?;

    if !valid {
        return Err(AuthError::BadRequest(
            "Invalid authentication code".to_string(),
        ));
    }

    let encrypted = encryption::encrypt_str(&challenge_state.secret)
        .map_err(|e| AuthError::Internal(e.to_string()))?;
    let encrypted_hex = hex::encode(encrypted);
    let recovery_codes =
        generate_recovery_codes(8).map_err(|e| AuthError::Internal(e.to_string()))?;
    let updated_at = Utc::now().to_rfc3339();

    state
        .db
        .update_mfa_totp_secret(&user.user_id.to_string(), Some(encrypted_hex), &updated_at)
        .await?;

    state
        .db
        .replace_recovery_codes(
            &user.user_id.to_string(),
            recovery_codes.hashed_codes,
            &updated_at,
        )
        .await?;

    render(&RecoveryCodesTemplate {
        recovery_codes: recovery_codes.plaintext_codes,
    })
    .map(IntoResponse::into_response)
}

async fn try_challenge_post(
    state: AppState,
    headers: HeaderMap,
    body: MfaChallengePayload,
) -> Result<Response, AuthError> {
    let challenge_data = state
        .db
        .get_and_delete_challenge(&body.challenge_id)
        .await?;
    let mut challenge_state: LoginMfaChallengeState = serde_json::from_str(&challenge_data)
        .map_err(|e| {
            AuthError::Internal(format!("Failed to deserialize MFA challenge state: {e}"))
        })?;

    let user = state
        .db
        .get_user_by_id(&challenge_state.user_id)
        .await?
        .ok_or_else(|| AuthError::Unauthorized("invalid MFA challenge".to_string()))?;

    let encrypted_secret = user.mfa_totp_secret.ok_or_else(|| {
        AuthError::Unauthorized("MFA is not configured for this account".to_string())
    })?;
    let encrypted_bytes = hex::decode(encrypted_secret)
        .map_err(|_| AuthError::Internal("Invalid stored MFA secret".to_string()))?;
    let secret = encryption::decrypt_str(&encrypted_bytes)
        .map_err(|_| AuthError::Internal("Failed to decrypt MFA secret".to_string()))?;

    let now = Utc::now().timestamp();
    let valid_totp = verify_totp_code(&secret, &body.code, now, TOTP_STEP_SECONDS, TOTP_WINDOW)
        .map_err(|e| AuthError::BadRequest(e.to_string()))?;
    let backup_code_hash = hash_backup_code(&body.code);
    let used_backup_code = user.recovery_codes.contains(&backup_code_hash);

    if !valid_totp && !used_backup_code {
        let next_attempts = challenge_state.failed_attempts.saturating_add(1);
        if next_attempts >= MAX_MFA_CHALLENGE_ATTEMPTS {
            return Err(AuthError::TooManyRequests(
                "Too many invalid MFA attempts. Please sign in again.".to_string(),
            ));
        }

        challenge_state.failed_attempts = next_attempts;
        let retry_state = serde_json::to_string(&challenge_state).map_err(|e| {
            AuthError::Internal(format!("Failed to serialize MFA challenge state: {e}"))
        })?;
        let retry_challenge_id = Uuid::new_v4().to_string();
        state
            .db
            .insert_challenge(&retry_challenge_id, &retry_state, 300)
            .await?;

        return Ok(Redirect::to(&format!(
            "/mfa/challenge?challenge_id={}&error={}",
            urlencoding::encode(&retry_challenge_id),
            urlencoding::encode("Invalid authentication or backup code")
        ))
        .into_response());
    }

    if used_backup_code {
        state
            .db
            .remove_recovery_code(&user.id.to_string(), &backup_code_hash)
            .await?;
    }

    let client_ip = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);

    let session_token = generate_session_token()?;
    let session = create_session(
        state.db.as_ref(),
        session_token.clone(),
        user.id,
        client_ip,
        user_agent,
    )
    .await?;

    let (cookie_name, cookie_value) = session_cookie(&session_token, session.expires_at);
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        cookie_name,
        cookie_value
            .parse()
            .map_err(|e| AuthError::Internal(format!("Failed to build cookie header: {e}")))?,
    );

    if challenge_state.oauth.client_id.is_some() && challenge_state.oauth.redirect_uri.is_some() {
        let authorize_url = format!(
            "/authorize?{}",
            super::authorize::build_oauth_query_string(
                challenge_state.oauth.client_id.as_deref().unwrap_or(""),
                challenge_state.oauth.redirect_uri.as_deref().unwrap_or(""),
                challenge_state.oauth.scope.as_deref().unwrap_or(""),
                challenge_state.oauth.state.as_deref(),
                challenge_state
                    .oauth
                    .code_challenge
                    .as_deref()
                    .unwrap_or(""),
                challenge_state
                    .oauth
                    .code_challenge_method
                    .as_deref()
                    .unwrap_or(""),
                challenge_state.oauth.nonce.as_deref(),
            )
        );

        return Ok((response_headers, Redirect::to(&authorize_url)).into_response());
    }

    Ok((response_headers, Redirect::to("/account")).into_response())
}

#[cfg(test)]
mod tests {
    use std::env;

    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
    };
    use lambda_http::tower::ServiceExt;

    use super::*;
    use crate::{routes, state::AppState, user::create_user};

    fn test_app_state() -> AppState {
        AppState {
            db: crate::db::memory(),
            jwt_keys: None,
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
            issuer_url: "https://auth.test.example.com".to_string(),
        }
    }

    fn set_test_key() {
        env::set_var("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef");
    }

    fn redirect_location(response: &Response) -> String {
        response
            .headers()
            .get(header::LOCATION)
            .expect("missing location header")
            .to_str()
            .expect("invalid location header")
            .to_string()
    }

    fn next_challenge_id_from_location(location: &str) -> String {
        let parsed = url::Url::parse(&format!("https://auth.test{location}"))
            .expect("valid redirect location url");
        parsed
            .query_pairs()
            .find_map(|(k, v)| {
                if k == "challenge_id" {
                    Some(v.to_string())
                } else {
                    None
                }
            })
            .expect("challenge_id in redirect")
    }

    async fn create_mfa_user(state: &AppState, secret: &str, recovery_codes: Vec<String>) -> Uuid {
        let user = create_user(
            state.db.as_ref(),
            "mfa-user@example.com".to_string(),
            "Password123!".to_string(),
        )
        .await
        .expect("create user");

        let encrypted_secret = encryption::encrypt_str(secret).expect("encrypt secret");
        let updated_at = Utc::now().to_rfc3339();

        state
            .db
            .update_mfa_totp_secret(
                &user.id.to_string(),
                Some(hex::encode(encrypted_secret)),
                &updated_at,
            )
            .await
            .expect("store mfa secret");

        state
            .db
            .replace_recovery_codes(&user.id.to_string(), recovery_codes, &updated_at)
            .await
            .expect("store recovery codes");

        user.id
    }

    async fn insert_login_challenge(
        state: &AppState,
        user_id: Uuid,
        failed_attempts: u8,
    ) -> String {
        let challenge_id = Uuid::new_v4().to_string();
        let challenge_state = serde_json::to_string(&LoginMfaChallengeState {
            user_id: user_id.to_string(),
            oauth: OauthContext {
                client_id: None,
                redirect_uri: None,
                response_type: None,
                scope: None,
                state: None,
                code_challenge: None,
                code_challenge_method: None,
                nonce: None,
            },
            failed_attempts,
        })
        .expect("serialize challenge");

        state
            .db
            .insert_challenge(&challenge_id, &challenge_state, 300)
            .await
            .expect("insert challenge");

        challenge_id
    }

    #[tokio::test]
    async fn test_csrf_enforced_for_mfa_setup_post() {
        let app = routes::router(test_app_state());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mfa/setup")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("challenge_id=fake&code=123456"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_csrf_enforced_for_mfa_challenge_post() {
        let app = routes::router(test_app_state());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mfa/challenge")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("challenge_id=fake&code=123456"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_mfa_challenge_is_single_use() {
        set_test_key();
        let state = test_app_state();
        let secret = "JBSWY3DPEHPK3PXP";
        let backup_code = "SINGLE-USE-CODE";
        let user_id = create_mfa_user(&state, secret, vec![hash_backup_code(backup_code)]).await;
        let challenge_id = insert_login_challenge(&state, user_id, 0).await;

        let first = try_challenge_post(
            state.clone(),
            HeaderMap::new(),
            MfaChallengePayload {
                challenge_id: challenge_id.clone(),
                code: backup_code.to_string(),
                _csrf_token: None,
            },
        )
        .await;
        assert!(first.is_ok());

        let second = try_challenge_post(
            state,
            HeaderMap::new(),
            MfaChallengePayload {
                challenge_id,
                code: backup_code.to_string(),
                _csrf_token: None,
            },
        )
        .await;

        assert!(matches!(second, Err(AuthError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_backup_code_is_one_time_use() {
        set_test_key();
        let state = test_app_state();
        let secret = "JBSWY3DPEHPK3PXP";
        let backup_code = "RECOVERY-CODE-1";
        let backup_hash = hash_backup_code(backup_code);
        let user_id = create_mfa_user(&state, secret, vec![backup_hash.clone()]).await;

        let first_challenge_id = insert_login_challenge(&state, user_id, 0).await;
        let first = try_challenge_post(
            state.clone(),
            HeaderMap::new(),
            MfaChallengePayload {
                challenge_id: first_challenge_id,
                code: backup_code.to_string(),
                _csrf_token: None,
            },
        )
        .await
        .expect("first backup code use succeeds");
        assert_eq!(first.status(), StatusCode::SEE_OTHER);

        let user_after_first = state
            .db
            .get_user_by_id(&user_id.to_string())
            .await
            .expect("load user")
            .expect("user exists");
        assert!(!user_after_first.recovery_codes.contains(&backup_hash));

        let second_challenge_id = insert_login_challenge(&state, user_id, 0).await;
        let second = try_challenge_post(
            state,
            HeaderMap::new(),
            MfaChallengePayload {
                challenge_id: second_challenge_id,
                code: backup_code.to_string(),
                _csrf_token: None,
            },
        )
        .await
        .expect("handler response");

        assert_eq!(second.status(), StatusCode::SEE_OTHER);
        let location = redirect_location(&second);
        assert!(location.starts_with("/mfa/challenge?"));
        assert!(location.contains("error="));
    }

    #[tokio::test]
    async fn test_mfa_failed_attempts_are_throttled_per_challenge_lifecycle() {
        set_test_key();
        let state = test_app_state();
        let secret = "JBSWY3DPEHPK3PXP";
        let user_id = create_mfa_user(&state, secret, vec![]).await;

        let mut challenge_id = insert_login_challenge(&state, user_id, 0).await;

        for _ in 1..MAX_MFA_CHALLENGE_ATTEMPTS {
            let response = try_challenge_post(
                state.clone(),
                HeaderMap::new(),
                MfaChallengePayload {
                    challenge_id,
                    code: "not-a-valid-code".to_string(),
                    _csrf_token: None,
                },
            )
            .await
            .expect("retry response");

            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let location = redirect_location(&response);
            assert!(location.starts_with("/mfa/challenge?"));
            challenge_id = next_challenge_id_from_location(&location);
        }

        let blocked = try_challenge_post(
            state,
            HeaderMap::new(),
            MfaChallengePayload {
                challenge_id,
                code: "not-a-valid-code".to_string(),
                _csrf_token: None,
            },
        )
        .await;

        assert!(matches!(blocked, Err(AuthError::TooManyRequests(_))));
    }
}
