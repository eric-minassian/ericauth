use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{db::Database, state};

#[derive(Serialize, Deserialize)]
pub struct UserPayload {
    email: String,
    password: String,
}

pub async fn user_handler(
    State(state): State<state::AppState>,
    headers: HeaderMap,
    Json(payload): Json<UserPayload>,
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

    {
        let db = &state.lock().await.db;
        if !check_email_availability(db, &payload.email).await {
            return (StatusCode::BAD_REQUEST, "email already in use");
        }
    }

    if !verify_password_strength(&payload.password) {
        return (StatusCode::BAD_REQUEST, "password too weak");
    }

    {
        create_user(&mut state.lock().await.db, payload.email, &payload.password).await;
    }

    (StatusCode::NO_CONTENT, "")
}

fn verify_email(email: &str) -> bool {
    email.contains('@') && email.len() < 256
}

async fn check_email_availability(db: &Database, email: &str) -> bool {
    db.get_user(email).await.unwrap().is_none()
}

fn verify_password_strength(password: &str) -> bool {
    password.len() > 8
}

async fn create_user(db: &mut Database, email: String, password: &str) {
    let password_hash = hash_password(password);

    db.insert_user(email, password_hash).await;
}

fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string();

    password_hash
}
