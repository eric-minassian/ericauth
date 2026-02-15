use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use crate::{error::AuthError, state::AppState};

const INVALID_TOKEN_MESSAGE: &str = "Invalid or expired verification token";

#[derive(Deserialize)]
pub struct VerifyEmailQuery {
    token: String,
}

pub async fn handler(
    State(state): State<AppState>,
    Query(query): Query<VerifyEmailQuery>,
) -> Response {
    match try_verify_email(state, query).await {
        Ok(resp) => resp,
        Err(err) => {
            let msg = match &err {
                AuthError::Internal(_) => "An unexpected error occurred",
                AuthError::BadRequest(_)
                | AuthError::Unauthorized(_)
                | AuthError::Forbidden(_)
                | AuthError::Conflict(_)
                | AuthError::NotFound(_)
                | AuthError::TooManyRequests(_) => INVALID_TOKEN_MESSAGE,
            };

            Redirect::to(&format!("/login?error={}", urlencoding::encode(msg))).into_response()
        }
    }
}

async fn try_verify_email(state: AppState, query: VerifyEmailQuery) -> Result<Response, AuthError> {
    let token = query.token.trim().to_string();

    if token.is_empty() {
        return Err(AuthError::BadRequest(INVALID_TOKEN_MESSAGE.to_string()));
    }

    let verification = state
        .db
        .redeem_email_verification(&token)
        .await?
        .ok_or_else(|| AuthError::BadRequest(INVALID_TOKEN_MESSAGE.to_string()))?;

    let user = state
        .db
        .get_user_by_id(&verification.user_id)
        .await?
        .ok_or_else(|| AuthError::BadRequest(INVALID_TOKEN_MESSAGE.to_string()))?;

    if !user.scopes.iter().any(|scope| scope == "email_verified") {
        let mut scopes = user.scopes;
        scopes.push("email_verified".to_string());
        state
            .db
            .update_user_scopes(&verification.user_id, scopes)
            .await?;
    }

    Ok(Redirect::to("/login?notice=email_verified").into_response())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::{get, post},
        Router,
    };
    use lambda_http::tower::ServiceExt;

    use crate::{state::AppState, user::create_user};

    fn test_app_state() -> AppState {
        AppState {
            db: crate::db::memory(),
            jwt_keys: None,
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
            issuer_url: "https://auth.test.example.com".to_string(),
        }
    }

    fn build_router(state: AppState) -> Router {
        Router::new()
            .route("/signup", post(super::super::signup::handler))
            .route("/verify-email", get(super::handler))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_verification_token_created_at_signup() {
        let state = test_app_state();
        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/signup")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "email=new.user%40example.com&password=Password123!",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let user = state
            .db
            .get_user_by_email("new.user@example.com".to_string())
            .await
            .unwrap()
            .unwrap();

        let verification = state
            .db
            .get_email_verification_by_user_id(&user.id.to_string())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(verification.user_id, user.id.to_string());
        assert!(verification.expires_at > chrono::Utc::now().timestamp());
    }

    #[tokio::test]
    async fn test_valid_token_marks_user_verified() {
        let state = test_app_state();
        let user = create_user(
            state.db.as_ref(),
            "verified.user@example.com".to_string(),
            "Password123!".to_string(),
        )
        .await
        .unwrap();

        state
            .db
            .insert_email_verification("valid-token", &user.id.to_string(), 3600)
            .await
            .unwrap();

        let stored = state
            .db
            .get_email_verification_by_user_id(&user.id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_ne!(stored.token, "valid-token");

        let app = build_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/verify-email?token=valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("notice=email_verified"));

        let updated_user = state
            .db
            .get_user_by_id(&user.id.to_string())
            .await
            .unwrap()
            .unwrap();

        assert!(updated_user
            .scopes
            .iter()
            .any(|scope| scope == "email_verified"));
    }

    #[tokio::test]
    async fn test_expired_or_invalid_token_rejected() {
        let state = test_app_state();
        let user = create_user(
            state.db.as_ref(),
            "pending.user@example.com".to_string(),
            "Password123!".to_string(),
        )
        .await
        .unwrap();

        state
            .db
            .insert_email_verification("expired-token", &user.id.to_string(), -1)
            .await
            .unwrap();

        let app = build_router(state.clone());

        let expired_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/verify-email?token=expired-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(expired_response.status(), StatusCode::SEE_OTHER);

        let invalid_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/verify-email?token=not-a-real-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(invalid_response.status(), StatusCode::SEE_OTHER);

        let unchanged_user = state
            .db
            .get_user_by_id(&user.id.to_string())
            .await
            .unwrap()
            .unwrap();

        assert!(!unchanged_user
            .scopes
            .iter()
            .any(|scope| scope == "email_verified"));
    }

    #[tokio::test]
    async fn test_verification_token_is_single_use() {
        let state = test_app_state();
        let user = create_user(
            state.db.as_ref(),
            "single.use@example.com".to_string(),
            "Password123!".to_string(),
        )
        .await
        .unwrap();

        state
            .db
            .insert_email_verification("single-use-token", &user.id.to_string(), 3600)
            .await
            .unwrap();

        let app = build_router(state);
        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/verify-email?token=single-use-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::SEE_OTHER);

        let second = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/verify-email?token=single-use-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::SEE_OTHER);
        assert!(second
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Invalid%20or%20expired%20verification%20token"));
    }

    #[tokio::test]
    async fn test_missing_user_uses_non_leaky_failure_message() {
        let state = test_app_state();
        state
            .db
            .insert_email_verification("orphan-token", "00000000-0000-0000-0000-000000000000", 3600)
            .await
            .unwrap();

        let app = build_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/verify-email?token=orphan-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("Invalid%20or%20expired%20verification%20token"));
        assert!(!location.contains("user%20not%20found"));
    }

    #[tokio::test]
    async fn test_token_is_trimmed_before_redemption() {
        let state = test_app_state();
        let user = create_user(
            state.db.as_ref(),
            "trimmed.token@example.com".to_string(),
            "Password123!".to_string(),
        )
        .await
        .unwrap();

        state
            .db
            .insert_email_verification("trim-token", &user.id.to_string(), 3600)
            .await
            .unwrap();

        let app = build_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/verify-email?token=%20trim-token%20")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let updated_user = state
            .db
            .get_user_by_id(&user.id.to_string())
            .await
            .unwrap()
            .unwrap();

        assert!(updated_user
            .scopes
            .iter()
            .any(|scope| scope == "email_verified"));
    }
}
