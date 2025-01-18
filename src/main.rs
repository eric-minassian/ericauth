use ericauth::{routes::routes, state::initialize_state};

#[tokio::main]
async fn main() {
    let app = routes().with_state(initialize_state());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// use lambda_http::{run, tracing, Error};
// use std::env::set_var;

// #[tokio::main]
// async fn main() -> Result<(), Error> {
//     tracing::init_default_subscriber();

//     set_var("AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH", "true");

//     let app = routes().with_state(initialize_state());

//     run(app).await
// }
