use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use uuid::Uuid;

use crate::{error::AuthError, state::AppState};

pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub session_id: String,
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);

        let cookie_header = parts
            .headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AuthError::Unauthorized("missing session cookie".into()))?;

        let token = cookie_header
            .split(';')
            .map(|s| s.trim())
            .find_map(|s| s.strip_prefix("session="))
            .ok_or_else(|| AuthError::Unauthorized("missing session cookie".into()))?;

        if token.is_empty() {
            return Err(AuthError::Unauthorized("missing session cookie".into()));
        }

        let session = state.db.get_session_by_token(token).await?;

        Ok(AuthenticatedUser {
            user_id: session.user_id,
            session_id: session.id,
        })
    }
}
