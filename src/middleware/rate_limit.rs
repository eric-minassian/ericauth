use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::state::AppState;

/// Create a rate-limiting middleware that allows `max_requests` per `window_seconds`.
///
/// The rate limit key is `{client_ip}#{path}`.
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let max_requests: i64 = 10;
    let window_seconds: i64 = 60;

    let client_ip = request
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|ip| ip.trim())
        .unwrap_or("unknown")
        .to_string();

    let path = request.uri().path().to_string();
    let key = format!("{client_ip}#{path}");

    let count = state
        .db
        .increment_rate_limit(&key, window_seconds)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "rate limit error").into_response())?;

    if count > max_requests {
        let mut response = (StatusCode::TOO_MANY_REQUESTS, "too many requests").into_response();
        response.headers_mut().insert(
            "Retry-After",
            HeaderValue::from_str(&window_seconds.to_string()).unwrap(),
        );
        return Err(response);
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::{body::Body, http::Request, middleware, routing::post, Router};
    use lambda_http::tower::ServiceExt;

    use crate::{jwt::generate_es256_keypair, jwt::JwtKeys};

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

    async fn ok_handler() -> &'static str {
        "ok"
    }

    #[tokio::test]
    async fn test_rate_limit_allows_under_limit() {
        let state = test_state();
        let app = Router::new()
            .route("/login", post(ok_handler))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                rate_limit_middleware,
            ))
            .with_state(state);

        let request = Request::builder()
            .method("POST")
            .uri("/login")
            .header("X-Forwarded-For", "1.2.3.4")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_rate_limit_blocks_over_limit() {
        let state = test_state();

        // Increment the counter to the limit
        for _ in 0..10 {
            state
                .db
                .increment_rate_limit("5.6.7.8#/login", 60)
                .await
                .unwrap();
        }

        let app = Router::new()
            .route("/login", post(ok_handler))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                rate_limit_middleware,
            ))
            .with_state(state);

        let request = Request::builder()
            .method("POST")
            .uri("/login")
            .header("X-Forwarded-For", "5.6.7.8")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().get("Retry-After").is_some());
    }

    #[tokio::test]
    async fn test_rate_limit_parses_first_ip_from_forwarded_for() {
        let state = test_state();

        // Pre-fill the rate limit counter for the first IP
        for _ in 0..10 {
            state
                .db
                .increment_rate_limit("9.9.9.9#/login", 60)
                .await
                .unwrap();
        }

        let app = Router::new()
            .route("/login", post(ok_handler))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                rate_limit_middleware,
            ))
            .with_state(state);

        // Send multi-IP header — only the first IP should be used for rate limiting
        let request = Request::builder()
            .method("POST")
            .uri("/login")
            .header("X-Forwarded-For", "9.9.9.9, 2.2.2.2, 3.3.3.3")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
