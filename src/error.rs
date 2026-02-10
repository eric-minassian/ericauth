use std::fmt;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Unified error type for the authentication service.
///
/// Each variant maps to an HTTP status code and produces a JSON response
/// body of the form `{"error": "<kind>", "message": "<details>"}`.
#[derive(Debug)]
pub enum AuthError {
    BadRequest(String),
    Unauthorized(String),
    NotFound(String),
    Conflict(String),
    Internal(String),
    TooManyRequests(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::BadRequest(msg) => write!(f, "Bad Request: {msg}"),
            AuthError::Unauthorized(msg) => write!(f, "Unauthorized: {msg}"),
            AuthError::NotFound(msg) => write!(f, "Not Found: {msg}"),
            AuthError::Conflict(msg) => write!(f, "Conflict: {msg}"),
            AuthError::Internal(msg) => write!(f, "Internal Server Error: {msg}"),
            AuthError::TooManyRequests(msg) => write!(f, "Too Many Requests: {msg}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_kind) = match &self {
            AuthError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AuthError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AuthError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            AuthError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            AuthError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
            AuthError::TooManyRequests(_) => (StatusCode::TOO_MANY_REQUESTS, "too_many_requests"),
        };

        let message = match &self {
            AuthError::BadRequest(msg)
            | AuthError::Unauthorized(msg)
            | AuthError::NotFound(msg)
            | AuthError::Conflict(msg)
            | AuthError::Internal(msg)
            | AuthError::TooManyRequests(msg) => msg.clone(),
        };

        let body = json!({
            "error": error_kind,
            "message": message,
        });

        (status, Json(body)).into_response()
    }
}
