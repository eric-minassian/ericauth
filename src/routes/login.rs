use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state;

#[derive(Serialize, Deserialize)]
pub struct LoginPayload {
    email: String,
    password: String,
}

pub async fn login_handler(
    State(state): State<state::AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginPayload>,
) -> impl IntoResponse {
    let Some(client_ip) = headers.get("X-Forwarded-For") else {
        return (StatusCode::BAD_REQUEST, "missing X-Forwarded-For header");
    };

    if client_ip.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty X-Forwarded-For header");
    }

    // TODO: Rate limit the client

    if payload.email.is_empty() || payload.password.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing email or password");
    }

    if !verify_email(&payload.email) {
        return (StatusCode::BAD_REQUEST, "invalid email");
    }

    match &state
        .lock()
        .await
        .db
        .get_user(&payload.email)
        .await
        .unwrap()
    {
        Some(user) => {
            if !verify_password_hash(&payload.password, &user.password_hash) {
                return (StatusCode::UNAUTHORIZED, "invalid email or password");
            }
        }
        None => return (StatusCode::UNAUTHORIZED, "invalid email or password"),
    }

    (StatusCode::NO_CONTENT, "")
}

fn verify_email(email: &str) -> bool {
    email.contains('@') && email.len() < 256
}

fn verify_password_hash(password: &str, password_hash: &str) -> bool {
    let parsed_hash = PasswordHash::new(password_hash).unwrap();
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}
