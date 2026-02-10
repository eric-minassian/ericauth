use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::DateTime;
use uuid::Uuid;

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

    pub async fn get_user_by_email(&self, email: String) -> Result<Option<UserTable>, String> {
        let users = self
            .users
            .read()
            .map_err(|e| format!("Lock error: {}", e))?;
        Ok(users.values().find(|u| u.email == email).cloned())
    }

    pub async fn insert_user(&self, email: String, password_hash: String) -> Result<Uuid, String> {
        // Check uniqueness
        if self.get_user_by_email(email.clone()).await?.is_some() {
            return Err("Email already in use".to_string());
        }

        let id = Uuid::new_v4();
        let user = UserTable {
            id,
            email,
            password_hash,
        };

        let mut users = self
            .users
            .write()
            .map_err(|e| format!("Lock error: {}", e))?;
        users.insert(id, user);

        Ok(id)
    }

    pub async fn insert_session(
        &self,
        id: String,
        user_id: Uuid,
        expires_at: DateTime<chrono::Utc>,
    ) -> Result<(), String> {
        let session = SessionTable {
            id: id.clone(),
            user_id,
            expires_at,
        };

        let mut sessions = self
            .sessions
            .write()
            .map_err(|e| format!("Lock error: {}", e))?;
        sessions.insert(id, session);

        Ok(())
    }
}

impl Default for MemoryDb {
    fn default() -> Self {
        Self::new()
    }
}
