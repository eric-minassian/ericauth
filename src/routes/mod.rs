mod consent;
mod health;
mod jwks;
mod login;
mod login_page;
mod logout;
mod passkey;
mod passkeys_page;
mod recover;
mod signup;
mod signup_page;
mod token;
mod token_revoke;

use axum::{
    http::{HeaderValue, Method},
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::cors::CorsLayer;

use crate::{
    middleware::{csrf::csrf_middleware, security_headers::security_headers_middleware},
    state::AppState,
};

pub fn router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(
            "https://auth.ericminassian.com"
                .parse::<HeaderValue>()
                .unwrap(),
        )
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .allow_credentials(true);

    // API routes that need CORS (token endpoints, well-known endpoints)
    let cors_routes = Router::new()
        .route("/token", post(token::handler))
        .route("/token/revoke", post(token_revoke::handler))
        .route("/.well-known/jwks.json", get(jwks::handler))
        .layer(cors);

    // All other routes (UI pages, JSON APIs that don't need CORS)
    let other_routes = Router::new()
        .route("/health", get(health::handler))
        .route("/signup", get(signup_page::handler).post(signup::handler))
        .route("/login", get(login_page::handler).post(login::handler))
        .route("/logout", post(logout::handler))
        .route(
            "/consent",
            get(consent::get_handler).post(consent::post_handler),
        )
        .route("/passkeys/manage", get(passkeys_page::handler))
        .route("/passkeys/register/begin", post(passkey::register_begin))
        .route(
            "/passkeys/register/complete",
            post(passkey::register_complete),
        )
        .route("/passkeys/auth/begin", post(passkey::auth_begin))
        .route("/passkeys/auth/complete", post(passkey::auth_complete))
        .route("/recover", post(recover::handler));

    Router::new()
        .merge(cors_routes)
        .merge(other_routes)
        .layer(middleware::from_fn(csrf_middleware))
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(state)
}
