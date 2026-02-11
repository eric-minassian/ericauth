use axum::{extract::State, response::IntoResponse, Json};
use serde_json::json;

use crate::{error::AuthError, middleware::bearer::BearerToken, state::AppState};

pub async fn handler(
    State(state): State<AppState>,
    token: BearerToken,
) -> Result<impl IntoResponse, AuthError> {
    let user = state
        .db
        .get_user_by_id(&token.claims.sub)
        .await?
        .ok_or_else(|| AuthError::NotFound("user not found".into()))?;

    let scopes: Vec<&str> = token.claims.scope.split_whitespace().collect();

    let mut response = json!({
        "sub": token.claims.sub,
    });

    if scopes.contains(&"email") {
        response["email"] = json!(user.email);
        response["email_verified"] = json!(true);
    }

    if scopes.contains(&"profile") {
        // We don't have a name field, but include what we can
        response["name"] = json!(user.email);
    }

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use lambda_http::tower::ServiceExt;

    use crate::{
        db::Database,
        jwt::{generate_es256_keypair, AccessTokenClaims, JwtKeys},
        state::AppState,
    };

    fn test_state() -> AppState {
        let (private_pem, _) = generate_es256_keypair().unwrap();
        let jwt_keys = JwtKeys::from_pem(private_pem.as_bytes(), "test-kid").unwrap();
        AppState {
            db: Database::memory(),
            jwt_keys: Some(jwt_keys),
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
        }
    }

    fn test_router(state: AppState) -> Router {
        Router::new()
            .route("/userinfo", get(handler).post(handler))
            .with_state(state)
    }

    async fn setup_user(state: &AppState) -> String {
        let now = chrono::Utc::now().to_rfc3339();
        let user_id = state
            .db
            .insert_user(
                "test@example.com".to_string(),
                Some("hashed_pw".to_string()),
                now.clone(),
                now,
                vec!["openid".to_string(), "email".to_string()],
                vec![],
            )
            .await
            .unwrap();
        user_id.to_string()
    }

    fn sign_token(state: &AppState, user_id: &str, scope: &str) -> String {
        let jwt_keys = state.jwt_keys.as_ref().unwrap();
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = AccessTokenClaims {
            iss: "https://auth.ericminassian.com".to_string(),
            sub: user_id.to_string(),
            aud: "test-client".to_string(),
            exp: now + 900,
            iat: now,
            scope: scope.to_string(),
            email: "test@example.com".to_string(),
        };
        jwt_keys.sign_access_token(&claims).unwrap()
    }

    #[tokio::test]
    async fn test_userinfo_with_email_scope() {
        let state = test_state();
        let user_id = setup_user(&state).await;
        let token = sign_token(&state, &user_id, "openid email");
        let app = test_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/userinfo")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["sub"], user_id);
        assert_eq!(json["email"], "test@example.com");
        assert_eq!(json["email_verified"], true);
    }

    #[tokio::test]
    async fn test_userinfo_without_email_scope() {
        let state = test_state();
        let user_id = setup_user(&state).await;
        let token = sign_token(&state, &user_id, "openid");
        let app = test_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/userinfo")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["sub"], user_id);
        assert!(json.get("email").is_none());
    }

    #[tokio::test]
    async fn test_userinfo_missing_auth_header() {
        let state = test_state();
        let app = test_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/userinfo")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get("WWW-Authenticate").is_some());
    }

    #[tokio::test]
    async fn test_userinfo_invalid_token() {
        let state = test_state();
        let app = test_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/userinfo")
            .header("Authorization", "Bearer invalid.token.here")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
