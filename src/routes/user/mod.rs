use axum::{routing::post, Router};

pub fn routes() -> Router {
    Router::new().route("/user", post("user"))
}
