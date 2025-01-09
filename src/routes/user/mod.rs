use std::ops::DerefMut;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state;

#[derive(Serialize, Deserialize)]
pub struct UserPayload {
    email: String,
    username: String,
    password: String,
}

pub async fn user(
    State(state): State<state::State>,
    headers: HeaderMap,
    Json(payload): Json<UserPayload>,
) -> impl IntoResponse {
    let Some(client_ip) = headers.get("X-Forwarded-For") else {
        return (StatusCode::BAD_REQUEST, "missing X-Forwarded-For header");
    };

    if client_ip.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty X-Forwarded-For header");
    }

    if payload.email.is_empty() || payload.username.is_empty() || payload.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "missing email, username or password",
        );
    }

    if !payload.email.contains('@') || payload.email.len() >= 256 {
        return (StatusCode::BAD_REQUEST, "invalid email");
    }

    let mut pool = state.lock().await;
    pool.deref_mut()
        .kv
        .insert("eric".to_string(), "Auth".to_string());
    drop(pool);

    (StatusCode::NO_CONTENT, "")
}
