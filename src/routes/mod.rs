mod health;
mod jwks;
mod login;
mod logout;
mod passkey;
mod signup;
mod token;
mod token_revoke;

use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::handler))
        .route("/signup", post(signup::handler))
        .route("/login", post(login::handler))
        .route("/logout", post(logout::handler))
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
        .with_state(state)
}
