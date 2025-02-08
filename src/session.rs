use lambda_http::http::{header, response};
use sha2::{digest::Update, Digest, Sha256};
use uuid::Uuid;

use crate::db::Database;

pub struct Session {
    pub id: String,
    pub user_id: Uuid,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

pub async fn generate_session_token() -> Result<String, &'static str> {
    let mut token_bytes = [0u8; 20];
    getrandom::fill(&mut token_bytes).map_err(|_| "Invalid Token")?;
    let token =
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &token_bytes).to_lowercase();
    Ok(token)
}

pub async fn create_session(
    db: &Database,
    token: String,
    user_id: Uuid,
) -> Result<Session, &'static str> {
    let hasher = Sha256::new();
    let session_id = hex::encode(hasher.chain(token.as_bytes()).finalize());

    let expires_at = chrono::Utc::now() + chrono::Duration::days(30);

    let session = Session {
        id: session_id.clone(),
        user_id: user_id.clone(),
        expires_at,
    };

    db.insert_session(session_id, user_id, expires_at)
        .await
        .unwrap();

    Ok(session)
}

pub trait SessionResponse {
    fn set_session_token(
        self,
        token: String,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> response::Builder;
}

impl SessionResponse for response::Builder {
    fn set_session_token(
        self,
        token: String,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> response::Builder {
        let cookie = format!(
            "session={}; HttpOnly; Path=/; Secure; SameSite=Lax; Expires={}",
            token,
            // Format the expires date in the correct format for cookies
            expires_at.format("%a, %d %b %Y %H:%M:%S GMT")
        );

        self.header(header::SET_COOKIE, cookie)
    }
}
