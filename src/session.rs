use aws_sdk_dynamodb::{types::AttributeValue, Client};
use sha2::{digest::Update, Digest, Sha256};

use crate::SESSIONS_TABLE_NAME;

#[derive(Debug)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub flags: SessionFlags,
}

#[derive(Debug, Clone)]
pub struct SessionFlags {
    pub two_factor_verified: bool,
}

pub async fn generate_session_token() -> Result<String, &'static str> {
    let mut token_bytes = [0u8; 20];
    getrandom::fill(&mut token_bytes).map_err(|_| "Invalid Token")?;
    let token =
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &token_bytes).to_lowercase();
    Ok(token)
}

// const sessionId = encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
// 	const session: Session = {
// 		id: sessionId,
// 		userId,
// 		expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
// 		twoFactorVerified: flags.twoFactorVerified
// 	};
// 	db.execute("INSERT INTO session (id, user_id, expires_at, two_factor_verified) VALUES (?, ?, ?, ?)", [
// 		session.id,
// 		session.userId,
// 		Math.floor(session.expiresAt.getTime() / 1000),
// 		Number(session.twoFactorVerified)
// 	]);
// 	return session;

pub async fn create_session(
    client: &Client,
    token: String,
    user_id: String,
    flags: SessionFlags,
) -> Result<Session, &'static str> {
    let hasher = Sha256::new();
    let session_id = hex::encode(hasher.chain(token.as_bytes()).finalize());

    let expires_at = chrono::Utc::now() + chrono::Duration::days(30);
    let expires_at_timestamp = expires_at.timestamp();

    let session = Session {
        id: session_id.clone(),
        user_id: user_id.clone(),
        expires_at,
        flags: flags.clone(),
    };

    client
        .put_item()
        .table_name(SESSIONS_TABLE_NAME)
        .item("id", AttributeValue::S(session.id.clone()))
        .item("user_id", AttributeValue::S(session.user_id.clone()))
        .item(
            "expires_at",
            AttributeValue::N(expires_at_timestamp.to_string()),
        )
        .item(
            "two_factor_verified",
            AttributeValue::Bool(session.flags.two_factor_verified),
        )
        .send()
        .await
        .map_err(|_| "Failed to create session")?;

    Ok(session)
}
