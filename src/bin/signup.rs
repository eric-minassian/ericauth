use std::env::set_var;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use ericauth::{get_user, insert_user};
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
pub struct SignupPayload {
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
        .payload::<SignupPayload>()?
        .ok_or_else(|| Error::from("missing request body"))?;

    if body.email.is_empty() || body.password.is_empty() {
        return Ok((StatusCode::BAD_REQUEST, "missing email or password"));
    }

    if !verify_email(&body.email) {
        return Ok((StatusCode::BAD_REQUEST, "invalid email"));
    }

    let config = aws_config::load_from_env().await;
    let ddb_client = aws_sdk_dynamodb::Client::new(&config);

    if !get_user(&ddb_client, body.email.clone()).await?.is_none() {
        return Ok((StatusCode::BAD_REQUEST, "email already in use"));
    }

    if !verify_password_strength(&body.password) {
        return Ok((StatusCode::BAD_REQUEST, "password too weak"));
    }

    let password_hash = hash_password(&body.password)?;

    insert_user(&ddb_client, body.email, password_hash).await?;

    Ok((StatusCode::NO_CONTENT, ""))
}

fn verify_email(email: &str) -> bool {
    email.contains('@') && email.len() < 256
}

fn verify_password_strength(password: &str) -> bool {
    password.len() > 8
}

fn hash_password(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| Error::from("Failed to hash password"))?
        .to_string();

    Ok(password_hash)
}
