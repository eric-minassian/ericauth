pub mod db;
pub mod routes;
pub mod state;

use axum::{routing::post, Router};
use lambda_http::{run, tracing, Error};
use state::initialize_state;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    let app = Router::new()
        .route("/user", post(routes::user::user_handler))
        .route("/login", post(routes::login::login_handler))
        .with_state(initialize_state());

    run(app).await
}
