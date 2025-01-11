pub mod db;
pub mod routes;
pub mod state;

use axum::{routing::post, Router};
use state::initialize_state;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/user", post(routes::user::user_handler))
        .route("/login", post(routes::login::login_handler))
        .with_state(initialize_state());

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
