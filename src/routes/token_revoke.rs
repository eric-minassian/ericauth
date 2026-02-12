use axum::{extract::State, http::StatusCode, response::IntoResponse, Form};
use serde::Deserialize;
use sha2::{digest::Update, Digest, Sha256};

use crate::{error::AuthError, state::AppState};

#[derive(Deserialize)]
pub struct RevokeRequest {
    token: String,
    token_type_hint: Option<String>,
}

pub async fn handler(
    State(state): State<AppState>,
    Form(body): Form<RevokeRequest>,
) -> Result<impl IntoResponse, AuthError> {
    if let Some(hint) = body.token_type_hint.as_deref() {
        if !matches!(hint, "refresh_token" | "access_token") {
            tracing::debug!("unknown token_type_hint provided: {hint}");
        }
    }

    let token_hash = hex::encode(Sha256::new().chain(body.token.as_bytes()).finalize());

    if let Some(_token) = state.db.get_refresh_token(&token_hash).await? {
        state.db.revoke_refresh_token(&token_hash).await?;
    }

    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use lambda_http::tower::ServiceExt;

    use crate::{db::Database, state::AppState};

    fn test_app_state() -> AppState {
        AppState {
            db: Database::memory(),
            jwt_keys: None,
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
        }
    }

    fn build_router(state: AppState) -> axum::Router {
        crate::routes::router(state)
    }

    #[tokio::test]
    async fn test_revoke_unknown_token_returns_200() {
        let state = test_app_state();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token/revoke")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("token=unknown_token"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_revoke_valid_token_returns_200() {
        use sha2::{digest::Update, Digest, Sha256};

        use crate::db::refresh_token::RefreshTokenTable;

        let state = test_app_state();
        let raw_token = "test-refresh-token-abc123";
        let token_hash = hex::encode(Sha256::new().chain(raw_token.as_bytes()).finalize());

        let refresh_token = RefreshTokenTable {
            token_hash: token_hash.clone(),
            user_id: "user-1".to_string(),
            client_id: "test-client".to_string(),
            scope: "openid".to_string(),
            expires_at: chrono::Utc::now().timestamp() + 3600,
            revoked: false,
        };
        state.db.insert_refresh_token(&refresh_token).await.unwrap();

        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token/revoke")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!("token={raw_token}")))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the token was actually revoked (get_refresh_token returns None for revoked tokens)
        let result = state.db.get_refresh_token(&token_hash).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_revoke_with_token_type_hint() {
        let state = test_app_state();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token/revoke")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("token=some_token&token_type_hint=refresh_token"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
