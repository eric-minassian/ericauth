use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use uuid::Uuid;

use crate::error::AuthError;

use super::credential::CredentialTable;
use super::refresh_token::RefreshTokenTable;
use super::session::SessionTable;
use super::user::UserTable;

/// In-memory challenge record.
#[derive(Clone)]
pub struct ChallengeRecord {
    pub challenge_data: String,
    pub expires_at: i64,
}

/// In-memory database backend for local development and testing.
/// Uses `Arc<RwLock<...>>` so it can be `Clone`d across axum handlers.
#[derive(Clone)]
pub struct MemoryDb {
    users: Arc<RwLock<HashMap<Uuid, UserTable>>>,
    sessions: Arc<RwLock<HashMap<String, SessionTable>>>,
    refresh_tokens: Arc<RwLock<HashMap<String, RefreshTokenTable>>>,
    credentials: Arc<RwLock<HashMap<String, CredentialTable>>>,
    challenges: Arc<RwLock<HashMap<String, ChallengeRecord>>>,
}

impl MemoryDb {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            refresh_tokens: Arc::new(RwLock::new(HashMap::new())),
            credentials: Arc::new(RwLock::new(HashMap::new())),
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_user_by_email(&self, email: String) -> Result<Option<UserTable>, AuthError> {
        let users = self
            .users
            .read()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
        Ok(users.values().find(|u| u.email == email).cloned())
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
        // Check uniqueness
        if self.get_user_by_email(email.clone()).await?.is_some() {
            return Err(AuthError::Conflict("email already in use".to_string()));
        }

        let id = Uuid::new_v4();
        let user = UserTable {
            id,
            email,
            password_hash,
            created_at,
            updated_at,
            scopes,
            recovery_codes,
        };

        let mut users = self
            .users
            .write()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
        users.insert(id, user);

        Ok(id)
    }

    pub async fn get_user_by_id(&self, user_id: &str) -> Result<Option<UserTable>, AuthError> {
        let user_uuid = Uuid::parse_str(user_id)
            .map_err(|e| AuthError::Internal(format!("Invalid user ID: {e}")))?;

        let users = self
            .users
            .read()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
        Ok(users.get(&user_uuid).cloned())
    }

    pub async fn update_user_scopes(
        &self,
        user_id: &str,
        scopes: Vec<String>,
    ) -> Result<(), AuthError> {
        let user_uuid = Uuid::parse_str(user_id)
            .map_err(|e| AuthError::Internal(format!("Invalid user ID: {e}")))?;

        let mut users = self
            .users
            .write()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

        let user = users
            .get_mut(&user_uuid)
            .ok_or_else(|| AuthError::NotFound("user not found".to_string()))?;

        user.scopes = scopes;
        Ok(())
    }

    pub async fn insert_session(
        &self,
        id: String,
        user_id: Uuid,
        expires_at: i64,
        ip_address: String,
    ) -> Result<(), AuthError> {
        let session = SessionTable {
            id: id.clone(),
            user_id,
            expires_at,
            ip_address,
        };

        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
        sessions.insert(id, session);

        Ok(())
    }

    pub async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
        sessions.remove(id);

        Ok(())
    }

    pub async fn get_session_by_id(&self, id: &str) -> Result<Option<SessionTable>, AuthError> {
        let sessions = self
            .sessions
            .read()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
        Ok(sessions.get(id).cloned())
    }

    pub async fn insert_refresh_token(&self, token: &RefreshTokenTable) -> Result<(), AuthError> {
        let mut tokens = self
            .refresh_tokens
            .write()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
        tokens.insert(token.token_hash.clone(), token.clone());
        Ok(())
    }

    pub async fn get_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenTable>, AuthError> {
        let tokens = self
            .refresh_tokens
            .read()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

        match tokens.get(token_hash) {
            Some(token) => {
                if token.revoked {
                    return Ok(None);
                }
                if token.expires_at <= chrono::Utc::now().timestamp() {
                    return Ok(None);
                }
                Ok(Some(token.clone()))
            }
            None => Ok(None),
        }
    }

    pub async fn revoke_refresh_token(&self, token_hash: &str) -> Result<(), AuthError> {
        let mut tokens = self
            .refresh_tokens
            .write()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

        if let Some(token) = tokens.get_mut(token_hash) {
            token.revoked = true;
        }

        Ok(())
    }

    // --- Credential operations ---

    pub async fn insert_credential(
        &self,
        credential_id: &str,
        user_id: &str,
        passkey_json: &str,
    ) -> Result<(), AuthError> {
        let mut creds = self
            .credentials
            .write()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

        if creds.contains_key(credential_id) {
            return Err(AuthError::Conflict("credential already exists".to_string()));
        }

        creds.insert(
            credential_id.to_string(),
            CredentialTable {
                credential_id: credential_id.to_string(),
                user_id: user_id.to_string(),
                passkey_json: passkey_json.to_string(),
            },
        );

        Ok(())
    }

    pub async fn get_credentials_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Vec<CredentialTable>, AuthError> {
        let creds = self
            .credentials
            .read()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

        Ok(creds
            .values()
            .filter(|c| c.user_id == user_id)
            .cloned()
            .collect())
    }

    pub async fn update_credential(
        &self,
        credential_id: &str,
        passkey_json: &str,
    ) -> Result<(), AuthError> {
        let mut creds = self
            .credentials
            .write()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

        let cred = creds
            .get_mut(credential_id)
            .ok_or_else(|| AuthError::NotFound("credential not found".to_string()))?;

        cred.passkey_json = passkey_json.to_string();
        Ok(())
    }

    pub async fn delete_credential(&self, credential_id: &str) -> Result<(), AuthError> {
        let mut creds = self
            .credentials
            .write()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
        creds.remove(credential_id);
        Ok(())
    }

    // --- Challenge operations ---

    pub async fn insert_challenge(
        &self,
        challenge_id: &str,
        challenge_data: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError> {
        let expires_at = chrono::Utc::now().timestamp() + ttl_seconds;

        let mut challenges = self
            .challenges
            .write()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

        challenges.insert(
            challenge_id.to_string(),
            ChallengeRecord {
                challenge_data: challenge_data.to_string(),
                expires_at,
            },
        );

        Ok(())
    }

    pub async fn get_and_delete_challenge(&self, challenge_id: &str) -> Result<String, AuthError> {
        let mut challenges = self
            .challenges
            .write()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

        let record = challenges
            .remove(challenge_id)
            .ok_or_else(|| AuthError::NotFound("challenge not found".into()))?;

        if record.expires_at <= chrono::Utc::now().timestamp() {
            return Err(AuthError::NotFound("challenge expired".into()));
        }

        Ok(record.challenge_data)
    }
}

impl Default for MemoryDb {
    fn default() -> Self {
        Self::new()
    }
}
