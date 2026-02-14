use ericauth::{routes, state::AppState};

fn main() -> Result<(), lambda_http::Error> {
    // Set env var before starting async runtime (safe: single-threaded here)
    std::env::set_var("AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH", "true");

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .json()
                .init();

            let state = AppState::new()
                .await
                .expect("Failed to initialize AppState");
            let app = routes::router(state);
            lambda_http::run(app).await
        })
}
