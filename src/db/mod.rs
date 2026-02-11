pub mod memory;
pub mod refresh_token;
pub mod session;
pub mod user;

use std::env;

use uuid::Uuid;

use crate::error::AuthError;

use self::refresh_token::RefreshTokenTable;
use self::user::UserTable;

/// Database abstraction that can be backed by DynamoDB (production) or
/// an in-memory store (local dev / tests).
#[derive(Clone)]
pub enum Database {
    Dynamo(DynamoDb),
    Memory(memory::MemoryDb),
}

/// DynamoDB-backed storage for production use.
#[derive(Clone)]
pub struct DynamoDb {
    pub(crate) client: aws_sdk_dynamodb::Client,
    pub users_table: String,
    pub users_email_index: String,
    pub sessions_table: String,
    pub refresh_tokens_table: String,
}

impl Database {
    /// Create a DynamoDB-backed database, loading config from the environment.
    pub async fn dynamo() -> Self {
        let config = aws_config::load_from_env().await;
        let client = aws_sdk_dynamodb::Client::new(&config);
        Database::Dynamo(DynamoDb {
            client,
            users_table: env::var("USERS_TABLE_NAME").unwrap_or_else(|_| "UsersTable".to_string()),
            users_email_index: env::var("USERS_TABLE_EMAIL_INDEX_NAME")
                .unwrap_or_else(|_| "emailIndex".to_string()),
            sessions_table: env::var("SESSIONS_TABLE_NAME")
                .unwrap_or_else(|_| "SessionsTable".to_string()),
            refresh_tokens_table: env::var("REFRESH_TOKENS_TABLE_NAME")
                .unwrap_or_else(|_| "RefreshTokensTable".to_string()),
        })
    }

    /// Create an in-memory database for local development and testing.
    pub fn memory() -> Self {
        Database::Memory(memory::MemoryDb::new())
    }

    pub async fn get_user_by_email(&self, email: String) -> Result<Option<UserTable>, AuthError> {
        match self {
            Database::Dynamo(db) => db.get_user_by_email(email).await,
            Database::Memory(db) => db.get_user_by_email(email).await,
        }
    }

    pub async fn insert_user(
        &self,
        email: String,
        password_hash: String,
        created_at: String,
        updated_at: String,
        scopes: Vec<String>,
    ) -> Result<Uuid, AuthError> {
        match self {
            Database::Dynamo(db) => {
                db.insert_user(email, password_hash, created_at, updated_at, scopes)
                    .await
            }
            Database::Memory(db) => {
                db.insert_user(email, password_hash, created_at, updated_at, scopes)
                    .await
            }
        }
    }

    pub async fn update_user_scopes(
        &self,
        user_id: &str,
        scopes: Vec<String>,
    ) -> Result<(), AuthError> {
        match self {
            Database::Dynamo(db) => db.update_user_scopes(user_id, scopes).await,
            Database::Memory(db) => db.update_user_scopes(user_id, scopes).await,
        }
    }

    pub async fn insert_session(
        &self,
        id: String,
        user_id: Uuid,
        expires_at: i64,
        ip_address: String,
    ) -> Result<(), AuthError> {
        match self {
            Database::Dynamo(db) => db.insert_session(id, user_id, expires_at, ip_address).await,
            Database::Memory(db) => db.insert_session(id, user_id, expires_at, ip_address).await,
        }
    }

    pub async fn delete_session(&self, session_id: &str) -> Result<(), AuthError> {
        match self {
            Database::Dynamo(db) => db.delete_session(session_id).await,
            Database::Memory(db) => db.delete_session(session_id).await,
        }
    }

    pub async fn get_session_by_token(
        &self,
        token: &str,
    ) -> Result<session::SessionTable, AuthError> {
        use sha2::{digest::Update, Digest, Sha256};

        let session_id = hex::encode(Sha256::new().chain(token.as_bytes()).finalize());

        let session = match self {
            Database::Dynamo(db) => db.get_session_by_id(&session_id).await?,
            Database::Memory(db) => db.get_session_by_id(&session_id).await?,
        };

        let session = session.ok_or_else(|| AuthError::Unauthorized("invalid session".into()))?;

        if session.expires_at <= chrono::Utc::now().timestamp() {
            return Err(AuthError::Unauthorized("session expired".into()));
        }

        Ok(session)
    }

    pub async fn insert_refresh_token(&self, token: &RefreshTokenTable) -> Result<(), AuthError> {
        match self {
            Database::Dynamo(db) => db.insert_refresh_token(token).await,
            Database::Memory(db) => db.insert_refresh_token(token).await,
        }
    }

    pub async fn get_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenTable>, AuthError> {
        match self {
            Database::Dynamo(db) => db.get_refresh_token(token_hash).await,
            Database::Memory(db) => db.get_refresh_token(token_hash).await,
        }
    }

    pub async fn revoke_refresh_token(&self, token_hash: &str) -> Result<(), AuthError> {
        match self {
            Database::Dynamo(db) => db.revoke_refresh_token(token_hash).await,
            Database::Memory(db) => db.revoke_refresh_token(token_hash).await,
        }
    }
}
