use axum::http::header;
use chrono::{DateTime, Utc};
use sha2::{digest::Update, Digest, Sha256};
use uuid::Uuid;

use crate::{db::Database, error::AuthError};

pub struct Session {
    pub id: String,
    pub user_id: Uuid,
    pub expires_at: i64,
}

pub fn generate_session_token() -> Result<String, AuthError> {
    let mut token_bytes = [0u8; 20];
    getrandom::fill(&mut token_bytes)
        .map_err(|e| AuthError::Internal(format!("Failed to generate session token: {e}")))?;
    let token =
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &token_bytes).to_lowercase();
    Ok(token)
}

pub async fn create_session(
    db: &Database,
    token: String,
    user_id: Uuid,
) -> Result<Session, AuthError> {
    let hasher = Sha256::new();
    let session_id = hex::encode(hasher.chain(token.as_bytes()).finalize());

    let expires_at = (Utc::now() + chrono::Duration::days(30)).timestamp();

    let session = Session {
        id: session_id.clone(),
        user_id,
        expires_at,
    };

    db.insert_session(session_id, user_id, expires_at).await?;

    Ok(session)
}

/// Build a Set-Cookie header value for a session token.
pub fn session_cookie(token: &str, expires_at: i64) -> (header::HeaderName, String) {
    let expires_dt = DateTime::<Utc>::from_timestamp(expires_at, 0)
        .unwrap_or_else(|| Utc::now() + chrono::Duration::days(30));
    let cookie = format!(
        "session={}; HttpOnly; Path=/; Secure; SameSite=Lax; Expires={}",
        token,
        expires_dt.format("%a, %d %b %Y %H:%M:%S GMT")
    );
    (header::SET_COOKIE, cookie)
}
