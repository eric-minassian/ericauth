pub mod memory;
pub mod session;
pub mod user;

use std::env;

use chrono::DateTime;
use uuid::Uuid;

use crate::error::AuthError;

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
    ) -> Result<Uuid, AuthError> {
        match self {
            Database::Dynamo(db) => db.insert_user(email, password_hash).await,
            Database::Memory(db) => db.insert_user(email, password_hash).await,
        }
    }

    pub async fn insert_session(
        &self,
        id: String,
        user_id: Uuid,
        expires_at: DateTime<chrono::Utc>,
    ) -> Result<(), AuthError> {
        match self {
            Database::Dynamo(db) => db.insert_session(id, user_id, expires_at).await,
            Database::Memory(db) => db.insert_session(id, user_id, expires_at).await,
        }
    }
}
