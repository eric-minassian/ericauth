pub mod login;
pub mod user;

use axum::{
    routing::{get, post},
    Router,
};

use crate::state;

pub fn routes() -> Router<state::AppState> {
    Router::new()
        .route("/health", get("Ok"))
        .route("/user", post(user::user_handler))
        .route("/login", post(login::login_handler))
}
