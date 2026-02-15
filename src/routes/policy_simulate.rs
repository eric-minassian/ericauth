use std::env;

use axum::{extract::State, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    authz::{evaluate_policy, PolicyDecisionRequest},
    error::AuthError,
    middleware::bearer::BearerToken,
    state::AppState,
};

#[derive(Deserialize)]
pub struct PolicySimulatePayload {
    action: String,
    resource: String,
}

#[derive(Serialize)]
pub struct PolicySimulateResponse {
    allowed: bool,
    required_scope: Option<&'static str>,
    reason: &'static str,
}

fn expected_policy_audience(token_subject: &str) -> String {
    env::var("POLICY_SIMULATE_EXPECTED_AUDIENCE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| token_subject.to_string())
}

pub async fn handler(
    State(_state): State<AppState>,
    token: BearerToken,
    Json(payload): Json<PolicySimulatePayload>,
) -> Result<impl IntoResponse, AuthError> {
    let expected_audience = expected_policy_audience(&token.claims.sub);
    if token.claims.aud != expected_audience {
        return Err(AuthError::Unauthorized(
            "token audience does not match policy simulation audience".into(),
        ));
    }

    if token.claims.sub != token.claims.aud || !token.claims.email.is_empty() {
        return Err(AuthError::Unauthorized(
            "policy simulation requires a machine principal token".into(),
        ));
    }

    let scopes = token.claims.scope.split_whitespace().collect::<Vec<_>>();

    let decision = evaluate_policy(&PolicyDecisionRequest {
        principal: &token.claims.sub,
        action: &payload.action,
        resource: &payload.resource,
        scopes: &scopes,
    });

    tracing::info!(
        principal = %token.claims.sub,
        action = %payload.action,
        resource = %payload.resource,
        expected_audience = %expected_audience,
        token_audience = %token.claims.aud,
        token_scope = %token.claims.scope,
        allowed = decision.allowed,
        required_scope = decision.required_scope.unwrap_or("none"),
        decision_reason = decision.reason,
        "Policy simulation evaluated"
    );

    Ok(Json(PolicySimulateResponse {
        allowed: decision.allowed,
        required_scope: decision.required_scope,
        reason: decision.reason,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::post,
        Router,
    };
    use lambda_http::tower::ServiceExt;

    use crate::{
        jwt::{generate_es256_keypair, AccessTokenClaims, JwtKeys},
        state::AppState,
    };

    fn test_state() -> AppState {
        let (private_pem, _) = generate_es256_keypair().unwrap();
        let jwt_keys = JwtKeys::from_pem(private_pem.as_bytes(), "test-kid").unwrap();
        AppState {
            db: crate::db::memory(),
            jwt_keys: Some(jwt_keys),
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
            issuer_url: "https://auth.test.example.com".to_string(),
        }
    }

    fn test_router(state: AppState) -> Router {
        Router::new()
            .route("/policy/simulate", post(handler))
            .with_state(state)
    }

    fn sign_token(state: &AppState, sub: &str, aud: &str, email: &str, scope: &str) -> String {
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = AccessTokenClaims {
            iss: state.issuer_url.clone(),
            sub: sub.to_string(),
            aud: aud.to_string(),
            exp: now + 900,
            iat: now,
            scope: scope.to_string(),
            email: email.to_string(),
        };

        state
            .jwt_keys
            .as_ref()
            .unwrap()
            .sign_access_token(&claims)
            .unwrap()
    }

    #[tokio::test]
    async fn test_policy_simulate_rejects_audience_mismatch() {
        let state = test_state();
        let app = test_router(state.clone());
        let token = sign_token(&state, "machine-client", "wrong-audience", "", "api:read");

        let request = Request::builder()
            .method("POST")
            .uri("/policy/simulate")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(r#"{"action":"read","resource":"account"}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "unauthorized");
    }

    #[tokio::test]
    async fn test_policy_simulate_rejects_user_token() {
        let state = test_state();
        let app = test_router(state.clone());
        let token = sign_token(
            &state,
            "user-123",
            "user-123",
            "user@example.com",
            "api:read",
        );

        let request = Request::builder()
            .method("POST")
            .uri("/policy/simulate")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(r#"{"action":"read","resource":"account"}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "unauthorized");
    }

    #[tokio::test]
    async fn test_policy_simulate_accepts_machine_token_with_matching_audience() {
        let state = test_state();
        let app = test_router(state.clone());
        let token = sign_token(&state, "machine-client", "machine-client", "", "api:read");

        let request = Request::builder()
            .method("POST")
            .uri("/policy/simulate")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(r#"{"action":"read","resource":"account"}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["allowed"], true);
        assert_eq!(json["required_scope"], "api:read");
    }
}
