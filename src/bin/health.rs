use std::env::set_var;

use lambda_http::{run, service_fn, tracing, Error, IntoResponse, Request};

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    set_var("AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH", "true");

    run(service_fn(function_handler)).await
}

async fn function_handler(_event: Request) -> Result<impl IntoResponse, Error> {
    Ok("OK")
}
