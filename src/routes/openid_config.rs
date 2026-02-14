use axum::{
    extract::State,
    http::{header, HeaderValue},
    response::IntoResponse,
    Json,
};
use serde_json::json;

use crate::state::AppState;

pub async fn handler(State(state): State<AppState>) -> impl IntoResponse {
    let issuer = &state.issuer_url;
    let config = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "revocation_endpoint": format!("{issuer}/token/revoke"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["none"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "email", "email_verified"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code", "refresh_token"]
    });

    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=86400"),
            ),
        ],
        Json(config),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Router,
    };
    use lambda_http::tower::ServiceExt;

    use crate::db;

    fn test_router() -> Router {
        let state = AppState {
            db: db::memory(),
            jwt_keys: None,
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
            issuer_url: "https://auth.test.example.com".to_string(),
        };
        Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(handler),
            )
            .with_state(state)
    }

    #[tokio::test]
    async fn test_openid_config_returns_json() {
        let app = test_router();

        let request = Request::builder()
            .method("GET")
            .uri("/.well-known/openid-configuration")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("Cache-Control").unwrap(),
            "public, max-age=86400"
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["issuer"], "https://auth.test.example.com");
        assert_eq!(
            json["authorization_endpoint"],
            "https://auth.test.example.com/authorize"
        );
        assert_eq!(
            json["token_endpoint"],
            "https://auth.test.example.com/token"
        );
        assert_eq!(
            json["userinfo_endpoint"],
            "https://auth.test.example.com/userinfo"
        );
        assert_eq!(json["response_types_supported"], json!(["code"]));
        assert_eq!(json["code_challenge_methods_supported"], json!(["S256"]));
    }
}
