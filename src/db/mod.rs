pub mod auth_code;
pub mod challenge;
pub mod client;
pub mod credential;
pub mod memory;
pub mod refresh_token;
pub mod session;
pub mod user;

use std::env;

use uuid::Uuid;

use crate::error::AuthError;

use self::auth_code::AuthCodeTable;
use self::client::ClientTable;
use self::credential::CredentialTable;
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
    pub credentials_table: String,
    pub credentials_user_id_index: String,
    pub challenges_table: String,
    pub clients_table: String,
    pub auth_codes_table: String,
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
            credentials_table: env::var("CREDENTIALS_TABLE_NAME")
                .unwrap_or_else(|_| "CredentialsTable".to_string()),
            credentials_user_id_index: env::var("CREDENTIALS_USER_ID_INDEX_NAME")
                .unwrap_or_else(|_| "userIdIndex".to_string()),
            challenges_table: env::var("CHALLENGES_TABLE_NAME")
                .unwrap_or_else(|_| "ChallengesTable".to_string()),
            clients_table: env::var("CLIENTS_TABLE_NAME")
                .unwrap_or_else(|_| "ClientsTable".to_string()),
            auth_codes_table: env::var("AUTH_CODES_TABLE_NAME")
                .unwrap_or_else(|_| "AuthCodesTable".to_string()),
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
        recovery_codes: Vec<String>,
    ) -> Result<Uuid, AuthError> {
        match self {
            Database::Dynamo(db) => {
                db.insert_user(
                    email,
                    password_hash,
                    created_at,
                    updated_at,
                    scopes,
                    recovery_codes,
                )
                .await
            }
            Database::Memory(db) => {
                db.insert_user(
                    email,
                    password_hash,
                    created_at,
                    updated_at,
                    scopes,
                    recovery_codes,
                )
                .await
            }
        }
    }

    pub async fn get_user_by_id(&self, user_id: &str) -> Result<Option<UserTable>, AuthError> {
        match self {
            Database::Dynamo(db) => db.get_user_by_id(user_id).await,
            Database::Memory(db) => db.get_user_by_id(user_id).await,
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

    // --- Credential operations ---

    pub async fn insert_credential(
        &self,
        credential_id: &str,
        user_id: &str,
        passkey_json: &str,
    ) -> Result<(), AuthError> {
        match self {
            Database::Dynamo(db) => {
                db.insert_credential(credential_id, user_id, passkey_json)
                    .await
            }
            Database::Memory(db) => {
                db.insert_credential(credential_id, user_id, passkey_json)
                    .await
            }
        }
    }

    pub async fn get_credentials_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Vec<CredentialTable>, AuthError> {
        match self {
            Database::Dynamo(db) => db.get_credentials_by_user_id(user_id).await,
            Database::Memory(db) => db.get_credentials_by_user_id(user_id).await,
        }
    }

    pub async fn update_credential(
        &self,
        credential_id: &str,
        passkey_json: &str,
    ) -> Result<(), AuthError> {
        match self {
            Database::Dynamo(db) => db.update_credential(credential_id, passkey_json).await,
            Database::Memory(db) => db.update_credential(credential_id, passkey_json).await,
        }
    }

    pub async fn delete_credential(&self, credential_id: &str) -> Result<(), AuthError> {
        match self {
            Database::Dynamo(db) => db.delete_credential(credential_id).await,
            Database::Memory(db) => db.delete_credential(credential_id).await,
        }
    }

    // --- Challenge operations ---

    pub async fn insert_challenge(
        &self,
        challenge_id: &str,
        challenge_data: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError> {
        match self {
            Database::Dynamo(db) => {
                db.insert_challenge(challenge_id, challenge_data, ttl_seconds)
                    .await
            }
            Database::Memory(db) => {
                db.insert_challenge(challenge_id, challenge_data, ttl_seconds)
                    .await
            }
        }
    }

    pub async fn get_and_delete_challenge(&self, challenge_id: &str) -> Result<String, AuthError> {
        match self {
            Database::Dynamo(db) => db.get_and_delete_challenge(challenge_id).await,
            Database::Memory(db) => db.get_and_delete_challenge(challenge_id).await,
        }
    }

    // --- Client operations ---

    pub async fn get_client(&self, client_id: &str) -> Result<Option<ClientTable>, AuthError> {
        match self {
            Database::Dynamo(db) => db.get_client(client_id).await,
            Database::Memory(db) => db.get_client(client_id).await,
        }
    }

    /// Insert a client (only supported by Memory backend, for testing).
    pub async fn insert_client(&self, client: ClientTable) -> Result<(), AuthError> {
        match self {
            Database::Dynamo(_) => Err(AuthError::Internal(
                "insert_client not supported on DynamoDB backend".into(),
            )),
            Database::Memory(db) => db.insert_client(client).await,
        }
    }

    // --- Auth code operations ---

    pub async fn insert_auth_code(&self, auth_code: &AuthCodeTable) -> Result<(), AuthError> {
        match self {
            Database::Dynamo(db) => db.insert_auth_code(auth_code).await,
            Database::Memory(db) => db.insert_auth_code(auth_code).await,
        }
    }

    pub async fn redeem_auth_code(&self, code: &str) -> Result<Option<AuthCodeTable>, AuthError> {
        match self {
            Database::Dynamo(db) => db.redeem_auth_code(code).await,
            Database::Memory(db) => db.redeem_auth_code(code).await,
        }
    }
}
