pub(crate) mod authorize;
mod consent;
mod health;
mod jwks;
mod login;
mod login_page;
mod logout;
mod openid_config;
mod passkey;
mod passkeys_page;
mod recover;
mod signup;
mod signup_page;
mod token;
mod token_revoke;
mod userinfo;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};

use crate::{
    middleware::{csrf::csrf_middleware, security_headers::security_headers_middleware},
    state::AppState,
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::handler))
        .route("/signup", get(signup_page::handler).post(signup::handler))
        .route("/login", get(login_page::handler).post(login::handler))
        .route("/logout", post(logout::handler))
        .route(
            "/consent",
            get(consent::get_handler).post(consent::post_handler),
        )
        .route("/passkeys/manage", get(passkeys_page::handler))
        .route("/token", post(token::handler))
        .route("/token/revoke", post(token_revoke::handler))
        .route("/.well-known/jwks.json", get(jwks::handler))
        .route("/passkeys/register/begin", post(passkey::register_begin))
        .route(
            "/passkeys/register/complete",
            post(passkey::register_complete),
        )
        .route("/passkeys/auth/begin", post(passkey::auth_begin))
        .route("/passkeys/auth/complete", post(passkey::auth_complete))
        .route("/authorize", get(authorize::handler))
        .route(
            "/.well-known/openid-configuration",
            get(openid_config::handler),
        )
        .route("/userinfo", get(userinfo::handler).post(userinfo::handler))
        .route("/recover", post(recover::handler))
        .layer(middleware::from_fn(csrf_middleware))
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(state)
}
