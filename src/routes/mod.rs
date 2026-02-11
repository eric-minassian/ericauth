mod health;
mod jwks;
mod login;
mod login_page;
mod logout;
mod signup;
mod signup_page;
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
        .route("/signup", get(signup_page::handler).post(signup::handler))
        .route("/login", get(login_page::handler).post(login::handler))
        .route("/logout", post(logout::handler))
        .route("/token", post(token::handler))
        .route("/token/revoke", post(token_revoke::handler))
        .route("/.well-known/jwks.json", get(jwks::handler))
        .with_state(state)
}
