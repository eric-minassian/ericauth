use std::env::set_var;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use ericauth::get_user;
use lambda_http::{
    http::StatusCode, run, service_fn, tracing, Error, IntoResponse, Request, RequestPayloadExt,
};
use serde::Deserialize;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    set_var("AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH", "true");

    run(service_fn(function_handler)).await
}

#[derive(Deserialize)]
pub struct LoginPayload {
    email: String,
    password: String,
}

async fn function_handler(event: Request) -> Result<impl IntoResponse, Error> {
    let Some(client_ip) = event.headers().get("X-Forwarded-For") else {
        return Ok((StatusCode::BAD_REQUEST, "missing X-Forwarded-For header"));
    };

    if client_ip.is_empty() {
        return Ok((StatusCode::BAD_REQUEST, "empty X-Forwarded-For header"));
    }

    let body = event
        .payload::<LoginPayload>()?
        .ok_or_else(|| Error::from("missing request body"))?;

    if body.email.is_empty() || body.password.is_empty() {
        return Ok((StatusCode::BAD_REQUEST, "missing email or password"));
    }

    if !verify_email(&body.email) {
        return Ok((StatusCode::BAD_REQUEST, "invalid email"));
    }

    let config = aws_config::load_from_env().await;
    let ddb_client = aws_sdk_dynamodb::Client::new(&config);

    match get_user(&ddb_client, body.email).await? {
        Some(user) => {
            if !verify_password_hash(&body.password, &user.password_hash)? {
                return Ok((StatusCode::UNAUTHORIZED, "invalid email or password"));
            }
        }
        None => return Ok((StatusCode::UNAUTHORIZED, "invalid email or password")),
    }

    Ok((StatusCode::NO_CONTENT, ""))
}

fn verify_email(email: &str) -> bool {
    email.contains('@') && email.len() < 256
}

fn verify_password_hash(password: &str, password_hash: &str) -> Result<bool, Error> {
    let parsed_hash =
        PasswordHash::new(password_hash).map_err(|_| Error::from("invalid password hash in db"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
