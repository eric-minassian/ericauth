use std::env::set_var;

use ericauth::{
    db::Database,
    error_response,
    password::verify_password_hash,
    session::{create_session, generate_session_token, SessionResponse},
};
use lambda_http::{
    http::StatusCode, run, service_fn, tracing, Body, Error, IntoResponse, Request,
    RequestPayloadExt, Response,
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
    // Check client IP
    let Some(client_ip) = event.headers().get("X-Forwarded-For") else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "missing X-Forwarded-For header",
        ));
    };

    if client_ip.is_empty() {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "empty X-Forwarded-For header",
        ));
    }

    // Parse and validate request body
    let body = match event.payload::<LoginPayload>()? {
        Some(payload) => payload,
        None => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "missing request body",
            ))
        }
    };

    if body.email.is_empty() || body.password.is_empty() {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "missing email or password",
        ));
    }

    if !verify_email(&body.email) {
        return Ok(error_response(StatusCode::BAD_REQUEST, "invalid email"));
    }

    // Database operations
    let db = Database::new().await;

    let user = match db.get_user_by_email(body.email).await? {
        Some(user) => user,
        None => {
            return Ok(error_response(
                StatusCode::UNAUTHORIZED,
                "invalid email or password",
            ))
        }
    };

    if !verify_password_hash(&body.password, &user.password_hash)? {
        return Ok(error_response(
            StatusCode::UNAUTHORIZED,
            "invalid email or password",
        ));
    }

    // Create session
    let session_token = generate_session_token().await?;
    let session = create_session(&db, session_token.clone(), user.id)
        .await
        .unwrap();

    // Success response
    let response = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .set_session_token(session_token, session.expires_at)
        .body(Body::Empty)
        .unwrap();

    Ok(response)
}

fn verify_email(email: &str) -> bool {
    email.contains('@') && email.len() < 256
}
