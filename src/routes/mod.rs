mod account;
pub(crate) mod authorize;
mod consent;
mod favicon;
mod health;
mod jwks;
mod login;
mod login_page;
mod logout;
mod openid_config;
mod passkey;
mod passkeys_page;
mod recover;
mod recover_page;
mod signup;
mod signup_page;
mod token;
mod token_revoke;
mod userinfo;

use axum::{
    http::{HeaderValue, Method},
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::cors::CorsLayer;

use crate::{
    middleware::{
        csrf::csrf_middleware, rate_limit::rate_limit_middleware,
        security_headers::security_headers_middleware,
    },
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

    // API routes that need CORS (token endpoints, well-known endpoints, userinfo)
    let cors_routes = Router::new()
        .route("/token", post(token::handler))
        .route("/token/revoke", post(token_revoke::handler))
        .route("/.well-known/jwks.json", get(jwks::handler))
        .route(
            "/.well-known/openid-configuration",
            get(openid_config::handler),
        )
        .route("/userinfo", get(userinfo::handler).post(userinfo::handler))
        .layer(cors);

    // Rate-limited routes (auth entry points that accept untrusted input)
    let rate_limited_routes = Router::new()
        .route("/signup", get(signup_page::handler).post(signup::handler))
        .route("/login", get(login_page::handler).post(login::handler))
        .route(
            "/recover",
            get(recover_page::handler).post(recover::handler),
        )
        .route("/passkeys/auth/begin", post(passkey::auth_begin))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ));

    // All other routes (no rate limit, no CORS)
    let other_routes = Router::new()
        .route("/favicon.ico", get(favicon::handler))
        .route("/health", get(health::handler))
        .route("/logout", post(logout::handler))
        .route(
            "/consent",
            get(consent::get_handler).post(consent::post_handler),
        )
        .route("/passkeys/manage", get(passkeys_page::handler))
        .route("/account", get(account::handler))
        .route("/account/sessions", get(account::sessions_page_handler))
        .route(
            "/account/sessions/revoke",
            post(account::revoke_session_handler),
        )
        .route(
            "/account/sessions/revoke-others",
            post(account::revoke_other_sessions_handler),
        )
        .route(
            "/account/password",
            get(account::password_page_handler).post(account::change_password_handler),
        )
        .route(
            "/account/recovery-codes/regenerate",
            post(account::regenerate_recovery_codes_handler),
        )
        .route("/passkeys/register/begin", post(passkey::register_begin))
        .route(
            "/passkeys/register/complete",
            post(passkey::register_complete),
        )
        .route("/passkeys/auth/complete", post(passkey::auth_complete))
        .route("/passkeys/delete", post(passkey::delete))
        .route("/authorize", get(authorize::handler));

    Router::new()
        .merge(cors_routes)
        .merge(rate_limited_routes)
        .merge(other_routes)
        .layer(middleware::from_fn(csrf_middleware))
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(state)
}
