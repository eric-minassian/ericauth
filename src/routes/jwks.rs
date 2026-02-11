use axum::{extract::State, http::header, response::IntoResponse, Json};

use crate::{error::AuthError, jwt::JwkSet, state::AppState};

pub async fn handler(State(state): State<AppState>) -> Result<impl IntoResponse, AuthError> {
    let jwt_keys = state
        .jwt_keys
        .as_ref()
        .ok_or_else(|| AuthError::Internal("JWT keys not configured".into()))?;

    let jwk = jwt_keys.to_jwk()?;
    let jwks = JwkSet { keys: vec![jwk] };

    Ok((
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        Json(jwks),
    ))
}
