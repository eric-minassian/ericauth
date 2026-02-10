mod health;
mod login;
mod signup;

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
        .with_state(state)
}
