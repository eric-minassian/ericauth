use std::env::set_var;

use ericauth::{routes::routes, state::initialize_state};
use lambda_http::{run, tracing, Error};

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    set_var("AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH", "true");

    let app = routes().with_state(initialize_state());

    run(app).await
}
