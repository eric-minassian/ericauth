use lambda_http::{http::StatusCode, Body, Response};

pub mod db;
pub mod encryption;
pub mod password;
pub mod session;
pub mod user;

pub fn generate_random_recovery_code() -> Result<String, &'static str> {
    let mut recovery_code_bytes = [0u8; 10];
    getrandom::fill(&mut recovery_code_bytes).map_err(|_| "Invalid Recovery Code")?;

    Ok(base32::encode(
        base32::Alphabet::Rfc4648 { padding: false },
        &recovery_code_bytes,
    )
    .to_uppercase())
}

pub fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::from(message))
        .unwrap()
}
