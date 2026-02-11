use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use uuid::Uuid;

use crate::error::AuthError;

use super::session::SessionTable;
use super::user::UserTable;

/// In-memory database backend for local development and testing.
/// Uses `Arc<RwLock<...>>` so it can be `Clone`d across axum handlers.
#[derive(Clone)]
pub struct MemoryDb {
    users: Arc<RwLock<HashMap<Uuid, UserTable>>>,
    sessions: Arc<RwLock<HashMap<String, SessionTable>>>,
}

impl MemoryDb {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
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
        };

        let mut users = self
            .users
            .write()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
        users.insert(id, user);

        Ok(id)
    }

    pub async fn insert_session(
        &self,
        id: String,
        user_id: Uuid,
        expires_at: i64,
    ) -> Result<(), AuthError> {
        let session = SessionTable {
            id: id.clone(),
            user_id,
            expires_at,
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
}

impl Default for MemoryDb {
    fn default() -> Self {
        Self::new()
    }
}
