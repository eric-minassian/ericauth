use ericauth::{routes, state::AppState};

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    // Strip API Gateway stage prefix so routes match without /prod, /dev, etc.
    std::env::set_var("AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH", "true");

    let state = AppState::new().await;
    let app = routes::router(state);

    lambda_http::run(app).await
}
