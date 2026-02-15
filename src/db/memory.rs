use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::audit::AuditEventRecord;
use crate::error::AuthError;

use super::api_key::ApiKeyTable;
use super::auth_code::AuthCodeTable;
use super::client::ClientTable;
use super::credential::CredentialTable;
use super::email_verification::EmailVerificationTable;
use super::password_reset::PasswordResetTable;
use super::refresh_token::RefreshTokenTable;
use super::session::NewSession;
use super::session::SessionTable;
use super::tenant::{ProjectTable, TenantTable};
use super::user::UserTable;

/// In-memory challenge record.
#[derive(Clone, Serialize, Deserialize)]
pub struct ChallengeRecord {
    pub challenge_data: String,
    pub expires_at: i64,
}

/// In-memory rate limit record.
#[derive(Clone, Serialize, Deserialize)]
pub struct RateLimitRecord {
    pub count: i64,
    pub expires_at: i64,
}

#[derive(Default, Serialize, Deserialize)]
struct MemoryDbSnapshot {
    users: HashMap<Uuid, UserTable>,
    sessions: HashMap<String, SessionTable>,
    email_verifications: HashMap<String, EmailVerificationTable>,
    #[serde(default)]
    password_resets: HashMap<String, PasswordResetTable>,
    refresh_tokens: HashMap<String, RefreshTokenTable>,
    audit_events: Vec<AuditEventRecord>,
    credentials: HashMap<String, CredentialTable>,
    challenges: HashMap<String, ChallengeRecord>,
    clients: HashMap<String, ClientTable>,
    tenants: HashMap<String, TenantTable>,
    auth_codes: HashMap<String, AuthCodeTable>,
    api_keys: HashMap<String, ApiKeyTable>,
    rate_limits: HashMap<String, RateLimitRecord>,
}

/// In-memory database backend for local development and testing.
/// Uses `Arc<RwLock<...>>` so it can be `Clone`d across axum handlers.
#[derive(Clone)]
pub struct MemoryDb {
    users: Arc<RwLock<HashMap<Uuid, UserTable>>>,
    sessions: Arc<RwLock<HashMap<String, SessionTable>>>,
    email_verifications: Arc<RwLock<HashMap<String, EmailVerificationTable>>>,
    password_resets: Arc<RwLock<HashMap<String, PasswordResetTable>>>,
    refresh_tokens: Arc<RwLock<HashMap<String, RefreshTokenTable>>>,
    audit_events: Arc<RwLock<Vec<AuditEventRecord>>>,
    credentials: Arc<RwLock<HashMap<String, CredentialTable>>>,
    challenges: Arc<RwLock<HashMap<String, ChallengeRecord>>>,
    clients: Arc<RwLock<HashMap<String, ClientTable>>>,
    tenants: Arc<RwLock<HashMap<String, TenantTable>>>,
    auth_codes: Arc<RwLock<HashMap<String, AuthCodeTable>>>,
    api_keys: Arc<RwLock<HashMap<String, ApiKeyTable>>>,
    rate_limits: Arc<RwLock<HashMap<String, RateLimitRecord>>>,
    persistence_path: Option<PathBuf>,
}

impl MemoryDb {
    pub fn new() -> Self {
        let persistence_path = env::var("MEMORY_DB_FILE").ok().map(PathBuf::from);
        let snapshot = match persistence_path.as_ref() {
            Some(path) => match Self::load_snapshot(path) {
                Ok(snapshot) => snapshot,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "Failed to load memory DB snapshot");
                    MemoryDbSnapshot::default()
                }
            },
            None => MemoryDbSnapshot::default(),
        };

        Self {
            users: Arc::new(RwLock::new(snapshot.users)),
            sessions: Arc::new(RwLock::new(snapshot.sessions)),
            email_verifications: Arc::new(RwLock::new(snapshot.email_verifications)),
            password_resets: Arc::new(RwLock::new(snapshot.password_resets)),
            refresh_tokens: Arc::new(RwLock::new(snapshot.refresh_tokens)),
            audit_events: Arc::new(RwLock::new(snapshot.audit_events)),
            credentials: Arc::new(RwLock::new(snapshot.credentials)),
            challenges: Arc::new(RwLock::new(snapshot.challenges)),
            clients: Arc::new(RwLock::new(snapshot.clients)),
            tenants: Arc::new(RwLock::new(snapshot.tenants)),
            auth_codes: Arc::new(RwLock::new(snapshot.auth_codes)),
            api_keys: Arc::new(RwLock::new(snapshot.api_keys)),
            rate_limits: Arc::new(RwLock::new(snapshot.rate_limits)),
            persistence_path,
        }
    }

    fn load_snapshot(path: &Path) -> Result<MemoryDbSnapshot, AuthError> {
        if !path.exists() {
            return Ok(MemoryDbSnapshot::default());
        }

        let content = fs::read_to_string(path)
            .map_err(|e| AuthError::Internal(format!("Failed to read memory DB snapshot: {e}")))?;

        if content.trim().is_empty() {
            return Ok(MemoryDbSnapshot::default());
        }

        serde_json::from_str(&content)
            .map_err(|e| AuthError::Internal(format!("Failed to parse memory DB snapshot: {e}")))
    }

    fn persist_if_configured(&self) -> Result<(), AuthError> {
        let Some(path) = self.persistence_path.as_ref() else {
            return Ok(());
        };

        let snapshot = MemoryDbSnapshot {
            users: self
                .users
                .read()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?
                .clone(),
            sessions: self
                .sessions
                .read()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?
                .clone(),
            email_verifications: self
                .email_verifications
                .read()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?
                .clone(),
            password_resets: self
                .password_resets
                .read()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?
                .clone(),
            refresh_tokens: self
                .refresh_tokens
                .read()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?
                .clone(),
            audit_events: self
                .audit_events
                .read()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?
                .clone(),
            credentials: self
                .credentials
                .read()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?
                .clone(),
            challenges: self
                .challenges
                .read()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?
                .clone(),
            clients: self
                .clients
                .read()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?
                .clone(),
            tenants: self
                .tenants
                .read()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?
                .clone(),
            auth_codes: self
                .auth_codes
                .read()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?
                .clone(),
            api_keys: self
                .api_keys
                .read()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?
                .clone(),
            rate_limits: self
                .rate_limits
                .read()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?
                .clone(),
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                AuthError::Internal(format!("Failed to create snapshot directory: {e}"))
            })?;
        }

        let json = serde_json::to_string(&snapshot).map_err(|e| {
            AuthError::Internal(format!("Failed to serialize memory DB snapshot: {e}"))
        })?;

        fs::write(path, json)
            .map_err(|e| AuthError::Internal(format!("Failed to write memory DB snapshot: {e}")))
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
        password_hash: Option<String>,
        created_at: String,
        updated_at: String,
        scopes: Vec<String>,
        recovery_codes: Vec<String>,
    ) -> Result<Uuid, AuthError> {
        let id = {
            let mut users = self
                .users
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            if users.values().any(|u| u.email == email) {
                return Err(AuthError::Conflict("email already in use".to_string()));
            }

            let id = Uuid::new_v5(&Uuid::NAMESPACE_DNS, email.as_bytes());
            if users.contains_key(&id) {
                return Err(AuthError::Conflict("email already in use".to_string()));
            }

            users.insert(
                id,
                UserTable {
                    id,
                    email,
                    password_hash,
                    created_at,
                    updated_at,
                    scopes,
                    recovery_codes,
                    mfa_totp_secret: None,
                },
            );

            id
        };

        self.persist_if_configured()?;
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

    pub async fn delete_user_by_id(&self, user_id: &str) -> Result<bool, AuthError> {
        let user_uuid = Uuid::parse_str(user_id)
            .map_err(|e| AuthError::Internal(format!("Invalid user ID: {e}")))?;

        let deleted = {
            let mut users = self
                .users
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
            users.remove(&user_uuid).is_some()
        };

        if deleted {
            self.persist_if_configured()?;
        }

        Ok(deleted)
    }

    pub async fn update_user_scopes(
        &self,
        user_id: &str,
        scopes: Vec<String>,
    ) -> Result<(), AuthError> {
        let user_uuid = Uuid::parse_str(user_id)
            .map_err(|e| AuthError::Internal(format!("Invalid user ID: {e}")))?;

        {
            let mut users = self
                .users
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            let user = users
                .get_mut(&user_uuid)
                .ok_or_else(|| AuthError::NotFound("user not found".to_string()))?;

            user.scopes = scopes;
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn remove_recovery_code(
        &self,
        user_id: &str,
        code_hash: &str,
    ) -> Result<(), AuthError> {
        let user_uuid = Uuid::parse_str(user_id)
            .map_err(|e| AuthError::Internal(format!("Invalid user ID: {e}")))?;

        {
            let mut users = self
                .users
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            let user = users
                .get_mut(&user_uuid)
                .ok_or_else(|| AuthError::NotFound("user not found".to_string()))?;

            user.recovery_codes.retain(|c| c != code_hash);
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn replace_recovery_codes(
        &self,
        user_id: &str,
        recovery_codes: Vec<String>,
        updated_at: &str,
    ) -> Result<(), AuthError> {
        let user_uuid = Uuid::parse_str(user_id)
            .map_err(|e| AuthError::Internal(format!("Invalid user ID: {e}")))?;

        {
            let mut users = self
                .users
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            let user = users
                .get_mut(&user_uuid)
                .ok_or_else(|| AuthError::NotFound("user not found".to_string()))?;

            user.recovery_codes = recovery_codes;
            user.updated_at = updated_at.to_string();
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn update_password_hash(
        &self,
        user_id: &str,
        password_hash: String,
        updated_at: &str,
    ) -> Result<(), AuthError> {
        let user_uuid = Uuid::parse_str(user_id)
            .map_err(|e| AuthError::Internal(format!("Invalid user ID: {e}")))?;

        {
            let mut users = self
                .users
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            let user = users
                .get_mut(&user_uuid)
                .ok_or_else(|| AuthError::NotFound("user not found".to_string()))?;

            user.password_hash = Some(password_hash);
            user.updated_at = updated_at.to_string();
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn update_mfa_totp_secret(
        &self,
        user_id: &str,
        mfa_totp_secret: Option<String>,
        updated_at: &str,
    ) -> Result<(), AuthError> {
        let user_uuid = Uuid::parse_str(user_id)
            .map_err(|e| AuthError::Internal(format!("Invalid user ID: {e}")))?;

        {
            let mut users = self
                .users
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            let user = users
                .get_mut(&user_uuid)
                .ok_or_else(|| AuthError::NotFound("user not found".to_string()))?;

            user.mfa_totp_secret = mfa_totp_secret;
            user.updated_at = updated_at.to_string();
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn insert_email_verification(
        &self,
        token: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError> {
        let expires_at = chrono::Utc::now().timestamp() + ttl_seconds;
        let token_hash = hash_email_verification_token(token);

        {
            let mut verifications = self
                .email_verifications
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            verifications.insert(
                token_hash.clone(),
                EmailVerificationTable {
                    token: token_hash,
                    user_id: user_id.to_string(),
                    expires_at,
                },
            );
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn get_email_verification_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Option<EmailVerificationTable>, AuthError> {
        let verifications = self
            .email_verifications
            .read()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

        Ok(verifications
            .values()
            .find(|record| record.user_id == user_id)
            .cloned())
    }

    pub async fn redeem_email_verification(
        &self,
        token: &str,
    ) -> Result<Option<EmailVerificationTable>, AuthError> {
        let token_hash = hash_email_verification_token(token);
        let record = {
            let mut verifications = self
                .email_verifications
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            verifications.remove(&token_hash)
        };

        if record.is_some() {
            self.persist_if_configured()?;
        }

        match record {
            Some(verification) if verification.expires_at > chrono::Utc::now().timestamp() => {
                Ok(Some(verification))
            }
            _ => Ok(None),
        }
    }

    pub async fn insert_password_reset_token(
        &self,
        token: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError> {
        let expires_at = chrono::Utc::now().timestamp() + ttl_seconds;
        let token_hash = hash_password_reset_token(token);

        {
            let mut resets = self
                .password_resets
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            resets.insert(
                token_hash.clone(),
                PasswordResetTable {
                    token: token_hash,
                    user_id: user_id.to_string(),
                    expires_at,
                },
            );
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn redeem_password_reset_token(
        &self,
        token: &str,
    ) -> Result<Option<PasswordResetTable>, AuthError> {
        let token_hash = hash_password_reset_token(token);
        let record = {
            let mut resets = self
                .password_resets
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            resets.remove(&token_hash)
        };

        if record.is_some() {
            self.persist_if_configured()?;
        }

        match record {
            Some(reset) if reset.expires_at > chrono::Utc::now().timestamp() => Ok(Some(reset)),
            _ => Ok(None),
        }
    }

    pub async fn insert_session(&self, new_session: NewSession) -> Result<(), AuthError> {
        let session = SessionTable {
            id: new_session.id.clone(),
            user_id: new_session.user_id,
            expires_at: new_session.expires_at,
            ip_address: new_session.ip_address,
            created_at: new_session.created_at,
            last_seen_at: new_session.last_seen_at,
            user_agent: new_session.user_agent,
        };

        {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
            sessions.insert(new_session.id, session);
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn delete_session(&self, id: &str) -> Result<(), AuthError> {
        {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
            sessions.remove(id);
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn get_session_by_id(&self, id: &str) -> Result<Option<SessionTable>, AuthError> {
        let sessions = self
            .sessions
            .read()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
        Ok(sessions.get(id).cloned())
    }

    pub async fn get_sessions_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Vec<SessionTable>, AuthError> {
        let user_uuid = Uuid::parse_str(user_id)
            .map_err(|e| AuthError::Internal(format!("Invalid user ID: {e}")))?;

        let sessions = self
            .sessions
            .read()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

        Ok(sessions
            .values()
            .filter(|session| session.user_id == user_uuid)
            .cloned()
            .collect())
    }

    pub async fn update_session_last_seen(
        &self,
        id: &str,
        last_seen_at: i64,
    ) -> Result<(), AuthError> {
        let updated = {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            if let Some(session) = sessions.get_mut(id) {
                session.last_seen_at = last_seen_at;
                true
            } else {
                false
            }
        };

        if updated {
            self.persist_if_configured()?;
        }

        Ok(())
    }

    pub async fn insert_refresh_token(&self, token: &RefreshTokenTable) -> Result<(), AuthError> {
        {
            let mut tokens = self
                .refresh_tokens
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
            tokens.insert(token.token_hash.clone(), token.clone());
        }

        self.persist_if_configured()?;
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
        let updated = {
            let mut tokens = self
                .refresh_tokens
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            if let Some(token) = tokens.get_mut(token_hash) {
                token.revoked = true;
                true
            } else {
                false
            }
        };

        if updated {
            self.persist_if_configured()?;
        }

        Ok(())
    }

    pub async fn delete_refresh_tokens_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<usize, AuthError> {
        let removed = {
            let mut tokens = self
                .refresh_tokens
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            let before = tokens.len();
            tokens.retain(|_, token| token.user_id != user_id);
            before - tokens.len()
        };

        if removed > 0 {
            self.persist_if_configured()?;
        }

        Ok(removed)
    }

    pub async fn insert_audit_event(&self, event: AuditEventRecord) -> Result<(), AuthError> {
        {
            let mut audit_events = self
                .audit_events
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
            audit_events.push(event);
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn list_audit_events(&self) -> Result<Vec<AuditEventRecord>, AuthError> {
        let audit_events = self
            .audit_events
            .read()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

        Ok(audit_events.clone())
    }

    // --- Credential operations ---

    pub async fn insert_credential(
        &self,
        credential_id: &str,
        user_id: &str,
        passkey_json: &str,
        created_at: &str,
    ) -> Result<(), AuthError> {
        {
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
                    created_at: created_at.to_string(),
                    last_used_at: None,
                },
            );
        }

        self.persist_if_configured()?;
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

    pub async fn get_credential_by_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<CredentialTable>, AuthError> {
        let creds = self
            .credentials
            .read()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

        Ok(creds.get(credential_id).cloned())
    }

    pub async fn update_credential(
        &self,
        credential_id: &str,
        passkey_json: &str,
    ) -> Result<(), AuthError> {
        {
            let mut creds = self
                .credentials
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            let cred = creds
                .get_mut(credential_id)
                .ok_or_else(|| AuthError::NotFound("credential not found".to_string()))?;

            cred.passkey_json = passkey_json.to_string();
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn delete_credential(&self, credential_id: &str) -> Result<(), AuthError> {
        {
            let mut creds = self
                .credentials
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
            creds.remove(credential_id);
        }

        self.persist_if_configured()?;
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

        {
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
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn get_and_delete_challenge(&self, challenge_id: &str) -> Result<String, AuthError> {
        let record = {
            let mut challenges = self
                .challenges
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            challenges
                .remove(challenge_id)
                .ok_or_else(|| AuthError::NotFound("challenge not found".into()))?
        };

        self.persist_if_configured()?;

        if record.expires_at <= chrono::Utc::now().timestamp() {
            return Err(AuthError::NotFound("challenge expired".into()));
        }

        Ok(record.challenge_data)
    }

    // --- Client operations ---

    pub async fn get_client(&self, client_id: &str) -> Result<Option<ClientTable>, AuthError> {
        let clients = self
            .clients
            .read()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
        Ok(clients.get(client_id).cloned())
    }

    pub async fn get_client_for_tenant(
        &self,
        tenant_id: Option<&str>,
        client_id: &str,
    ) -> Result<Option<ClientTable>, AuthError> {
        let Some(client) = self.get_client(client_id).await? else {
            return Ok(None);
        };

        let Some(tenant_id) = tenant_id else {
            return Ok(Some(client));
        };

        let tenants = self
            .tenants
            .read()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

        let Some(tenant) = tenants.get(tenant_id) else {
            return Ok(None);
        };

        let in_tenant = tenant
            .projects
            .iter()
            .any(|project| project.client_ids.iter().any(|id| id == client_id));

        if in_tenant {
            Ok(Some(client))
        } else {
            Ok(None)
        }
    }

    /// Insert a client (for testing purposes).
    pub async fn insert_client(&self, client: ClientTable) -> Result<(), AuthError> {
        {
            let mut clients = self
                .clients
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
            clients.insert(client.client_id.clone(), client);
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn insert_tenant(&self, tenant: TenantTable) -> Result<(), AuthError> {
        {
            let mut tenants = self
                .tenants
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            if tenants.contains_key(&tenant.tenant_id) {
                return Err(AuthError::Conflict("tenant already exists".to_string()));
            }

            tenants.insert(tenant.tenant_id.clone(), tenant);
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn list_tenants(&self) -> Result<Vec<TenantTable>, AuthError> {
        let tenants = self
            .tenants
            .read()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

        let mut result = tenants.values().cloned().collect::<Vec<_>>();
        result.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id));
        Ok(result)
    }

    pub async fn get_tenant(&self, tenant_id: &str) -> Result<Option<TenantTable>, AuthError> {
        let tenants = self
            .tenants
            .read()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
        Ok(tenants.get(tenant_id).cloned())
    }

    pub async fn delete_tenant(&self, tenant_id: &str) -> Result<(), AuthError> {
        {
            let mut tenants = self
                .tenants
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
            tenants.remove(tenant_id);
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn add_project_to_tenant(
        &self,
        tenant_id: &str,
        project: ProjectTable,
    ) -> Result<(), AuthError> {
        {
            let mut tenants = self
                .tenants
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            let tenant = tenants
                .get_mut(tenant_id)
                .ok_or_else(|| AuthError::NotFound("tenant not found".to_string()))?;

            if tenant
                .projects
                .iter()
                .any(|existing| existing.project_id == project.project_id)
            {
                return Err(AuthError::Conflict("project already exists".to_string()));
            }

            tenant.projects.push(project);
        }

        self.persist_if_configured()?;
        Ok(())
    }

    // --- Auth code operations ---

    pub async fn insert_auth_code(&self, auth_code: &AuthCodeTable) -> Result<(), AuthError> {
        {
            let mut codes = self
                .auth_codes
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;
            codes.insert(auth_code.code.clone(), auth_code.clone());
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn redeem_auth_code(&self, code: &str) -> Result<Option<AuthCodeTable>, AuthError> {
        let (redeemed, mutated) = {
            let mut codes = self
                .auth_codes
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            let auth_code = match codes.get(code) {
                Some(ac) => ac.clone(),
                None => return Ok(None),
            };

            if auth_code.used_at.is_some() {
                return Ok(None);
            }

            if auth_code.expires_at <= chrono::Utc::now().timestamp() {
                return Ok(None);
            }

            if let Some(ac) = codes.get_mut(code) {
                ac.used_at = Some(chrono::Utc::now().timestamp());
            }

            (Some(auth_code), true)
        };

        if mutated {
            self.persist_if_configured()?;
        }

        Ok(redeemed)
    }

    // --- API key operations ---

    pub async fn insert_api_key(&self, api_key: &ApiKeyTable) -> Result<(), AuthError> {
        {
            let mut api_keys = self
                .api_keys
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            if api_keys.contains_key(&api_key.key_id) {
                return Err(AuthError::Conflict("api key already exists".to_string()));
            }

            api_keys.insert(api_key.key_id.clone(), api_key.clone());
        }

        self.persist_if_configured()?;
        Ok(())
    }

    pub async fn get_api_keys_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Vec<ApiKeyTable>, AuthError> {
        let api_keys = self
            .api_keys
            .read()
            .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

        Ok(api_keys
            .values()
            .filter(|api_key| api_key.user_id == user_id)
            .cloned()
            .collect())
    }

    pub async fn revoke_api_key(
        &self,
        key_id: &str,
        user_id: &str,
        revoked_at: &str,
    ) -> Result<(), AuthError> {
        {
            let mut api_keys = self
                .api_keys
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            let api_key = api_keys
                .get_mut(key_id)
                .ok_or_else(|| AuthError::NotFound("api key not found".to_string()))?;

            if api_key.user_id != user_id {
                return Err(AuthError::NotFound("api key not found".to_string()));
            }

            if api_key.revoked_at.is_some() {
                return Err(AuthError::NotFound("api key not found".to_string()));
            }

            api_key.revoked_at = Some(revoked_at.to_string());
        }

        self.persist_if_configured()?;
        Ok(())
    }

    // --- Rate limit operations ---

    pub async fn increment_rate_limit(
        &self,
        key: &str,
        window_seconds: i64,
    ) -> Result<i64, AuthError> {
        let now = chrono::Utc::now().timestamp();
        let new_count = {
            let mut limits = self
                .rate_limits
                .write()
                .map_err(|e| AuthError::Internal(format!("Lock error: {e}")))?;

            let existing = limits.get(key).cloned();

            if let Some(record) = existing {
                if record.expires_at > now {
                    let new_count = record.count + 1;
                    limits.insert(
                        key.to_string(),
                        RateLimitRecord {
                            count: new_count,
                            expires_at: record.expires_at,
                        },
                    );
                    new_count
                } else {
                    limits.insert(
                        key.to_string(),
                        RateLimitRecord {
                            count: 1,
                            expires_at: now + window_seconds,
                        },
                    );
                    1
                }
            } else {
                limits.insert(
                    key.to_string(),
                    RateLimitRecord {
                        count: 1,
                        expires_at: now + window_seconds,
                    },
                );
                1
            }
        };

        self.persist_if_configured()?;
        Ok(new_count)
    }
}

fn hash_email_verification_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn hash_password_reset_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

impl Default for MemoryDb {
    fn default() -> Self {
        Self::new()
    }
}
