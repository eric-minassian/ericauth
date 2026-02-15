pub mod api_key;
pub mod audit_event;
pub mod auth_code;
pub mod challenge;
pub mod client;
pub mod credential;
pub mod email_verification;
pub mod memory;
pub mod password_reset;
pub mod rate_limit;
pub mod refresh_token;
pub mod session;
pub mod tenant;
pub mod user;

use std::env;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use crate::{audit::AuditEventRecord, error::AuthError, saml::SamlConfig};

use self::api_key::ApiKeyTable;
use self::auth_code::AuthCodeTable;
use self::client::ClientTable;
use self::credential::CredentialTable;
use self::email_verification::EmailVerificationTable;
use self::password_reset::PasswordResetTable;
use self::refresh_token::RefreshTokenTable;
use self::session::{NewSession, SessionTable};
use self::tenant::{ProjectTable, TenantTable};
use self::user::UserTable;

/// Database abstraction trait for storage backends.
#[async_trait]
pub trait Database: Send + Sync {
    // User operations
    async fn get_user_by_email(&self, email: String) -> Result<Option<UserTable>, AuthError>;
    async fn insert_user(
        &self,
        email: String,
        password_hash: Option<String>,
        created_at: String,
        updated_at: String,
        scopes: Vec<String>,
        recovery_codes: Vec<String>,
    ) -> Result<Uuid, AuthError>;
    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<UserTable>, AuthError>;
    async fn update_user_scopes(&self, user_id: &str, scopes: Vec<String>)
        -> Result<(), AuthError>;
    async fn remove_recovery_code(&self, user_id: &str, code_hash: &str) -> Result<(), AuthError>;
    async fn replace_recovery_codes(
        &self,
        user_id: &str,
        recovery_codes: Vec<String>,
        updated_at: &str,
    ) -> Result<(), AuthError>;
    async fn update_password_hash(
        &self,
        user_id: &str,
        password_hash: String,
        updated_at: &str,
    ) -> Result<(), AuthError>;
    async fn update_mfa_totp_secret(
        &self,
        user_id: &str,
        mfa_totp_secret: Option<String>,
        updated_at: &str,
    ) -> Result<(), AuthError>;
    async fn insert_email_verification(
        &self,
        token: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError>;
    async fn get_email_verification_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Option<EmailVerificationTable>, AuthError>;
    async fn redeem_email_verification(
        &self,
        token: &str,
    ) -> Result<Option<EmailVerificationTable>, AuthError>;
    async fn insert_password_reset_token(
        &self,
        token: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError>;
    async fn redeem_password_reset_token(
        &self,
        token: &str,
    ) -> Result<Option<PasswordResetTable>, AuthError>;
    async fn scim_create_user(&self, email: String, active: bool) -> Result<UserTable, AuthError>;
    async fn scim_update_user(
        &self,
        user_id: &str,
        email: String,
        active: bool,
    ) -> Result<UserTable, AuthError>;
    async fn scim_set_user_active(
        &self,
        user_id: &str,
        active: bool,
    ) -> Result<UserTable, AuthError>;
    async fn delete_user_by_id(&self, user_id: &str) -> Result<bool, AuthError>;

    // Session operations
    async fn insert_session(&self, new_session: NewSession) -> Result<(), AuthError>;
    async fn delete_session(&self, session_id: &str) -> Result<(), AuthError>;
    async fn get_session_by_id(&self, session_id: &str) -> Result<Option<SessionTable>, AuthError>;
    async fn get_sessions_by_user_id(&self, user_id: &str) -> Result<Vec<SessionTable>, AuthError>;
    async fn update_session_last_seen(
        &self,
        session_id: &str,
        last_seen_at: i64,
    ) -> Result<(), AuthError>;

    // Refresh token operations
    async fn insert_refresh_token(&self, token: &RefreshTokenTable) -> Result<(), AuthError>;
    async fn get_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenTable>, AuthError>;
    async fn revoke_refresh_token(&self, token_hash: &str) -> Result<(), AuthError>;
    async fn delete_refresh_tokens_by_user_id(&self, user_id: &str) -> Result<usize, AuthError>;

    // Credential operations
    async fn insert_credential(
        &self,
        credential_id: &str,
        user_id: &str,
        passkey_json: &str,
        created_at: &str,
    ) -> Result<(), AuthError>;
    async fn get_credentials_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Vec<CredentialTable>, AuthError>;
    async fn get_credential_by_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<CredentialTable>, AuthError>;
    async fn update_credential(
        &self,
        credential_id: &str,
        passkey_json: &str,
    ) -> Result<(), AuthError>;
    async fn delete_credential(&self, credential_id: &str) -> Result<(), AuthError>;

    // Challenge operations
    async fn insert_challenge(
        &self,
        challenge_id: &str,
        challenge_data: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError>;
    async fn get_and_delete_challenge(&self, challenge_id: &str) -> Result<String, AuthError>;

    // Client operations
    async fn get_client(&self, client_id: &str) -> Result<Option<ClientTable>, AuthError>;
    async fn get_client_for_tenant(
        &self,
        tenant_id: Option<&str>,
        client_id: &str,
    ) -> Result<Option<ClientTable>, AuthError>;
    async fn insert_client(&self, client: ClientTable) -> Result<(), AuthError>;

    // Tenant operations
    async fn insert_tenant(&self, tenant: TenantTable) -> Result<(), AuthError>;
    async fn list_tenants(&self) -> Result<Vec<TenantTable>, AuthError>;
    async fn get_tenant(&self, tenant_id: &str) -> Result<Option<TenantTable>, AuthError>;
    async fn delete_tenant(&self, tenant_id: &str) -> Result<(), AuthError>;
    async fn add_project_to_tenant(
        &self,
        tenant_id: &str,
        project: ProjectTable,
    ) -> Result<(), AuthError>;

    // Auth code operations
    async fn insert_auth_code(&self, auth_code: &AuthCodeTable) -> Result<(), AuthError>;
    async fn redeem_auth_code(&self, code: &str) -> Result<Option<AuthCodeTable>, AuthError>;

    // API key operations
    async fn insert_api_key(&self, api_key: &ApiKeyTable) -> Result<(), AuthError>;
    async fn get_api_keys_by_user_id(&self, user_id: &str) -> Result<Vec<ApiKeyTable>, AuthError>;
    async fn revoke_api_key(
        &self,
        key_id: &str,
        user_id: &str,
        revoked_at: &str,
    ) -> Result<(), AuthError>;

    // Rate limit operations
    async fn increment_rate_limit(&self, key: &str, window_seconds: i64) -> Result<i64, AuthError>;

    // Audit event operations
    async fn insert_audit_event(&self, event: AuditEventRecord) -> Result<(), AuthError>;
    async fn list_audit_events(&self) -> Result<Vec<AuditEventRecord>, AuthError>;
}

/// DynamoDB-backed storage for production use.
#[derive(Clone)]
pub struct DynamoDb {
    pub(crate) client: aws_sdk_dynamodb::Client,
    pub users_table: String,
    pub users_email_index: String,
    pub sessions_table: String,
    pub sessions_user_id_index: String,
    pub email_verifications_table: String,
    pub password_resets_table: String,
    pub refresh_tokens_table: String,
    pub credentials_table: String,
    pub credentials_user_id_index: String,
    pub challenges_table: String,
    pub clients_table: String,
    pub tenants_table: String,
    pub auth_codes_table: String,
    pub api_keys_table: String,
    pub api_keys_user_id_index: String,
    pub rate_limits_table: String,
    pub audit_events_table: String,
}

#[async_trait]
impl Database for DynamoDb {
    async fn get_user_by_email(&self, email: String) -> Result<Option<UserTable>, AuthError> {
        DynamoDb::get_user_by_email(self, email).await
    }

    async fn insert_user(
        &self,
        email: String,
        password_hash: Option<String>,
        created_at: String,
        updated_at: String,
        scopes: Vec<String>,
        recovery_codes: Vec<String>,
    ) -> Result<Uuid, AuthError> {
        DynamoDb::insert_user(
            self,
            email,
            password_hash,
            created_at,
            updated_at,
            scopes,
            recovery_codes,
        )
        .await
    }

    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<UserTable>, AuthError> {
        DynamoDb::get_user_by_id(self, user_id).await
    }

    async fn update_user_scopes(
        &self,
        user_id: &str,
        scopes: Vec<String>,
    ) -> Result<(), AuthError> {
        DynamoDb::update_user_scopes(self, user_id, scopes).await
    }

    async fn remove_recovery_code(&self, user_id: &str, code_hash: &str) -> Result<(), AuthError> {
        DynamoDb::remove_recovery_code(self, user_id, code_hash).await
    }

    async fn replace_recovery_codes(
        &self,
        user_id: &str,
        recovery_codes: Vec<String>,
        updated_at: &str,
    ) -> Result<(), AuthError> {
        DynamoDb::replace_recovery_codes(self, user_id, recovery_codes, updated_at).await
    }

    async fn update_password_hash(
        &self,
        user_id: &str,
        password_hash: String,
        updated_at: &str,
    ) -> Result<(), AuthError> {
        DynamoDb::update_password_hash(self, user_id, password_hash, updated_at).await
    }

    async fn update_mfa_totp_secret(
        &self,
        user_id: &str,
        mfa_totp_secret: Option<String>,
        updated_at: &str,
    ) -> Result<(), AuthError> {
        DynamoDb::update_mfa_totp_secret(self, user_id, mfa_totp_secret, updated_at).await
    }

    async fn insert_email_verification(
        &self,
        token: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError> {
        DynamoDb::insert_email_verification(self, token, user_id, ttl_seconds).await
    }

    async fn get_email_verification_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Option<EmailVerificationTable>, AuthError> {
        DynamoDb::get_email_verification_by_user_id(self, user_id).await
    }

    async fn redeem_email_verification(
        &self,
        token: &str,
    ) -> Result<Option<EmailVerificationTable>, AuthError> {
        DynamoDb::redeem_email_verification(self, token).await
    }

    async fn insert_password_reset_token(
        &self,
        token: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError> {
        DynamoDb::insert_password_reset_token(self, token, user_id, ttl_seconds).await
    }

    async fn redeem_password_reset_token(
        &self,
        token: &str,
    ) -> Result<Option<PasswordResetTable>, AuthError> {
        DynamoDb::redeem_password_reset_token(self, token).await
    }

    async fn scim_create_user(&self, email: String, active: bool) -> Result<UserTable, AuthError> {
        let now = Utc::now().to_rfc3339();
        let user_id = DynamoDb::insert_user(
            self,
            email,
            None,
            now.clone(),
            now,
            scim_active_scopes(active),
            vec![],
        )
        .await?;

        DynamoDb::get_user_by_id(self, &user_id.to_string())
            .await?
            .ok_or_else(|| AuthError::Internal("SCIM-created user missing after insert".into()))
    }

    async fn scim_update_user(
        &self,
        user_id: &str,
        email: String,
        active: bool,
    ) -> Result<UserTable, AuthError> {
        let user = DynamoDb::get_user_by_id(self, user_id)
            .await?
            .ok_or_else(|| AuthError::NotFound("user not found".into()))?;

        if user.email != email {
            return Err(AuthError::BadRequest(
                "SCIM userName updates are not supported".into(),
            ));
        }

        DynamoDb::update_user_scopes(self, user_id, scim_active_scopes(active)).await?;

        DynamoDb::get_user_by_id(self, user_id)
            .await?
            .ok_or_else(|| AuthError::Internal("SCIM-updated user missing after update".into()))
    }

    async fn scim_set_user_active(
        &self,
        user_id: &str,
        active: bool,
    ) -> Result<UserTable, AuthError> {
        let _user = DynamoDb::get_user_by_id(self, user_id)
            .await?
            .ok_or_else(|| AuthError::NotFound("user not found".into()))?;

        DynamoDb::update_user_scopes(self, user_id, scim_active_scopes(active)).await?;

        DynamoDb::get_user_by_id(self, user_id)
            .await?
            .ok_or_else(|| AuthError::Internal("SCIM-updated user missing after update".into()))
    }

    async fn delete_user_by_id(&self, user_id: &str) -> Result<bool, AuthError> {
        DynamoDb::delete_user_by_id(self, user_id).await
    }

    async fn insert_session(&self, new_session: NewSession) -> Result<(), AuthError> {
        DynamoDb::insert_session(self, new_session).await
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), AuthError> {
        DynamoDb::delete_session(self, session_id).await
    }

    async fn get_session_by_id(&self, session_id: &str) -> Result<Option<SessionTable>, AuthError> {
        DynamoDb::get_session_by_id(self, session_id).await
    }

    async fn get_sessions_by_user_id(&self, user_id: &str) -> Result<Vec<SessionTable>, AuthError> {
        DynamoDb::get_sessions_by_user_id(self, user_id).await
    }

    async fn update_session_last_seen(
        &self,
        session_id: &str,
        last_seen_at: i64,
    ) -> Result<(), AuthError> {
        DynamoDb::update_session_last_seen(self, session_id, last_seen_at).await
    }

    async fn insert_refresh_token(&self, token: &RefreshTokenTable) -> Result<(), AuthError> {
        DynamoDb::insert_refresh_token(self, token).await
    }

    async fn get_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenTable>, AuthError> {
        DynamoDb::get_refresh_token(self, token_hash).await
    }

    async fn revoke_refresh_token(&self, token_hash: &str) -> Result<(), AuthError> {
        DynamoDb::revoke_refresh_token(self, token_hash).await
    }

    async fn delete_refresh_tokens_by_user_id(&self, user_id: &str) -> Result<usize, AuthError> {
        DynamoDb::delete_refresh_tokens_by_user_id(self, user_id).await
    }

    async fn insert_credential(
        &self,
        credential_id: &str,
        user_id: &str,
        passkey_json: &str,
        created_at: &str,
    ) -> Result<(), AuthError> {
        DynamoDb::insert_credential(self, credential_id, user_id, passkey_json, created_at).await
    }

    async fn get_credentials_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Vec<CredentialTable>, AuthError> {
        DynamoDb::get_credentials_by_user_id(self, user_id).await
    }

    async fn get_credential_by_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<CredentialTable>, AuthError> {
        DynamoDb::get_credential_by_id(self, credential_id).await
    }

    async fn update_credential(
        &self,
        credential_id: &str,
        passkey_json: &str,
    ) -> Result<(), AuthError> {
        DynamoDb::update_credential(self, credential_id, passkey_json).await
    }

    async fn delete_credential(&self, credential_id: &str) -> Result<(), AuthError> {
        DynamoDb::delete_credential(self, credential_id).await
    }

    async fn insert_challenge(
        &self,
        challenge_id: &str,
        challenge_data: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError> {
        DynamoDb::insert_challenge(self, challenge_id, challenge_data, ttl_seconds).await
    }

    async fn get_and_delete_challenge(&self, challenge_id: &str) -> Result<String, AuthError> {
        DynamoDb::get_and_delete_challenge(self, challenge_id).await
    }

    async fn get_client(&self, client_id: &str) -> Result<Option<ClientTable>, AuthError> {
        DynamoDb::get_client(self, client_id).await
    }

    async fn insert_client(&self, _client: ClientTable) -> Result<(), AuthError> {
        Err(AuthError::Internal(
            "insert_client not supported on DynamoDB backend".into(),
        ))
    }

    async fn get_client_for_tenant(
        &self,
        tenant_id: Option<&str>,
        client_id: &str,
    ) -> Result<Option<ClientTable>, AuthError> {
        DynamoDb::get_client_for_tenant(self, tenant_id, client_id).await
    }

    async fn insert_tenant(&self, tenant: TenantTable) -> Result<(), AuthError> {
        DynamoDb::insert_tenant(self, tenant).await
    }

    async fn list_tenants(&self) -> Result<Vec<TenantTable>, AuthError> {
        DynamoDb::list_tenants(self).await
    }

    async fn get_tenant(&self, tenant_id: &str) -> Result<Option<TenantTable>, AuthError> {
        DynamoDb::get_tenant(self, tenant_id).await
    }

    async fn delete_tenant(&self, tenant_id: &str) -> Result<(), AuthError> {
        DynamoDb::delete_tenant(self, tenant_id).await
    }

    async fn add_project_to_tenant(
        &self,
        tenant_id: &str,
        project: ProjectTable,
    ) -> Result<(), AuthError> {
        DynamoDb::add_project_to_tenant(self, tenant_id, project).await
    }

    async fn insert_auth_code(&self, auth_code: &AuthCodeTable) -> Result<(), AuthError> {
        DynamoDb::insert_auth_code(self, auth_code).await
    }

    async fn redeem_auth_code(&self, code: &str) -> Result<Option<AuthCodeTable>, AuthError> {
        DynamoDb::redeem_auth_code(self, code).await
    }

    async fn insert_api_key(&self, api_key: &ApiKeyTable) -> Result<(), AuthError> {
        DynamoDb::insert_api_key(self, api_key).await
    }

    async fn get_api_keys_by_user_id(&self, user_id: &str) -> Result<Vec<ApiKeyTable>, AuthError> {
        DynamoDb::get_api_keys_by_user_id(self, user_id).await
    }

    async fn revoke_api_key(
        &self,
        key_id: &str,
        user_id: &str,
        revoked_at: &str,
    ) -> Result<(), AuthError> {
        DynamoDb::revoke_api_key(self, key_id, user_id, revoked_at).await
    }

    async fn increment_rate_limit(&self, key: &str, window_seconds: i64) -> Result<i64, AuthError> {
        DynamoDb::increment_rate_limit(self, key, window_seconds).await
    }

    async fn insert_audit_event(&self, event: AuditEventRecord) -> Result<(), AuthError> {
        DynamoDb::insert_audit_event(self, &event).await
    }

    async fn list_audit_events(&self) -> Result<Vec<AuditEventRecord>, AuthError> {
        DynamoDb::list_audit_events(self).await
    }
}

#[async_trait]
impl Database for memory::MemoryDb {
    async fn get_user_by_email(&self, email: String) -> Result<Option<UserTable>, AuthError> {
        memory::MemoryDb::get_user_by_email(self, email).await
    }

    async fn insert_user(
        &self,
        email: String,
        password_hash: Option<String>,
        created_at: String,
        updated_at: String,
        scopes: Vec<String>,
        recovery_codes: Vec<String>,
    ) -> Result<Uuid, AuthError> {
        memory::MemoryDb::insert_user(
            self,
            email,
            password_hash,
            created_at,
            updated_at,
            scopes,
            recovery_codes,
        )
        .await
    }

    async fn get_user_by_id(&self, user_id: &str) -> Result<Option<UserTable>, AuthError> {
        memory::MemoryDb::get_user_by_id(self, user_id).await
    }

    async fn update_user_scopes(
        &self,
        user_id: &str,
        scopes: Vec<String>,
    ) -> Result<(), AuthError> {
        memory::MemoryDb::update_user_scopes(self, user_id, scopes).await
    }

    async fn remove_recovery_code(&self, user_id: &str, code_hash: &str) -> Result<(), AuthError> {
        memory::MemoryDb::remove_recovery_code(self, user_id, code_hash).await
    }

    async fn replace_recovery_codes(
        &self,
        user_id: &str,
        recovery_codes: Vec<String>,
        updated_at: &str,
    ) -> Result<(), AuthError> {
        memory::MemoryDb::replace_recovery_codes(self, user_id, recovery_codes, updated_at).await
    }

    async fn update_password_hash(
        &self,
        user_id: &str,
        password_hash: String,
        updated_at: &str,
    ) -> Result<(), AuthError> {
        memory::MemoryDb::update_password_hash(self, user_id, password_hash, updated_at).await
    }

    async fn update_mfa_totp_secret(
        &self,
        user_id: &str,
        mfa_totp_secret: Option<String>,
        updated_at: &str,
    ) -> Result<(), AuthError> {
        memory::MemoryDb::update_mfa_totp_secret(self, user_id, mfa_totp_secret, updated_at).await
    }

    async fn insert_email_verification(
        &self,
        token: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError> {
        memory::MemoryDb::insert_email_verification(self, token, user_id, ttl_seconds).await
    }

    async fn get_email_verification_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Option<EmailVerificationTable>, AuthError> {
        memory::MemoryDb::get_email_verification_by_user_id(self, user_id).await
    }

    async fn redeem_email_verification(
        &self,
        token: &str,
    ) -> Result<Option<EmailVerificationTable>, AuthError> {
        memory::MemoryDb::redeem_email_verification(self, token).await
    }

    async fn insert_password_reset_token(
        &self,
        token: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError> {
        memory::MemoryDb::insert_password_reset_token(self, token, user_id, ttl_seconds).await
    }

    async fn redeem_password_reset_token(
        &self,
        token: &str,
    ) -> Result<Option<PasswordResetTable>, AuthError> {
        memory::MemoryDb::redeem_password_reset_token(self, token).await
    }

    async fn scim_create_user(&self, email: String, active: bool) -> Result<UserTable, AuthError> {
        let now = Utc::now().to_rfc3339();
        let user_id = memory::MemoryDb::insert_user(
            self,
            email,
            None,
            now.clone(),
            now,
            scim_active_scopes(active),
            vec![],
        )
        .await?;

        memory::MemoryDb::get_user_by_id(self, &user_id.to_string())
            .await?
            .ok_or_else(|| AuthError::Internal("SCIM-created user missing after insert".into()))
    }

    async fn scim_update_user(
        &self,
        user_id: &str,
        email: String,
        active: bool,
    ) -> Result<UserTable, AuthError> {
        let user = memory::MemoryDb::get_user_by_id(self, user_id)
            .await?
            .ok_or_else(|| AuthError::NotFound("user not found".into()))?;

        if user.email != email {
            return Err(AuthError::BadRequest(
                "SCIM userName updates are not supported".into(),
            ));
        }

        memory::MemoryDb::update_user_scopes(self, user_id, scim_active_scopes(active)).await?;

        memory::MemoryDb::get_user_by_id(self, user_id)
            .await?
            .ok_or_else(|| AuthError::Internal("SCIM-updated user missing after update".into()))
    }

    async fn scim_set_user_active(
        &self,
        user_id: &str,
        active: bool,
    ) -> Result<UserTable, AuthError> {
        let _user = memory::MemoryDb::get_user_by_id(self, user_id)
            .await?
            .ok_or_else(|| AuthError::NotFound("user not found".into()))?;

        memory::MemoryDb::update_user_scopes(self, user_id, scim_active_scopes(active)).await?;

        memory::MemoryDb::get_user_by_id(self, user_id)
            .await?
            .ok_or_else(|| AuthError::Internal("SCIM-updated user missing after update".into()))
    }

    async fn delete_user_by_id(&self, user_id: &str) -> Result<bool, AuthError> {
        memory::MemoryDb::delete_user_by_id(self, user_id).await
    }

    async fn insert_session(&self, new_session: NewSession) -> Result<(), AuthError> {
        memory::MemoryDb::insert_session(self, new_session).await
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), AuthError> {
        memory::MemoryDb::delete_session(self, session_id).await
    }

    async fn get_session_by_id(&self, session_id: &str) -> Result<Option<SessionTable>, AuthError> {
        memory::MemoryDb::get_session_by_id(self, session_id).await
    }

    async fn get_sessions_by_user_id(&self, user_id: &str) -> Result<Vec<SessionTable>, AuthError> {
        memory::MemoryDb::get_sessions_by_user_id(self, user_id).await
    }

    async fn update_session_last_seen(
        &self,
        session_id: &str,
        last_seen_at: i64,
    ) -> Result<(), AuthError> {
        memory::MemoryDb::update_session_last_seen(self, session_id, last_seen_at).await
    }

    async fn insert_refresh_token(&self, token: &RefreshTokenTable) -> Result<(), AuthError> {
        memory::MemoryDb::insert_refresh_token(self, token).await
    }

    async fn get_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenTable>, AuthError> {
        memory::MemoryDb::get_refresh_token(self, token_hash).await
    }

    async fn revoke_refresh_token(&self, token_hash: &str) -> Result<(), AuthError> {
        memory::MemoryDb::revoke_refresh_token(self, token_hash).await
    }

    async fn delete_refresh_tokens_by_user_id(&self, user_id: &str) -> Result<usize, AuthError> {
        memory::MemoryDb::delete_refresh_tokens_by_user_id(self, user_id).await
    }

    async fn insert_credential(
        &self,
        credential_id: &str,
        user_id: &str,
        passkey_json: &str,
        created_at: &str,
    ) -> Result<(), AuthError> {
        memory::MemoryDb::insert_credential(self, credential_id, user_id, passkey_json, created_at)
            .await
    }

    async fn get_credentials_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Vec<CredentialTable>, AuthError> {
        memory::MemoryDb::get_credentials_by_user_id(self, user_id).await
    }

    async fn get_credential_by_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<CredentialTable>, AuthError> {
        memory::MemoryDb::get_credential_by_id(self, credential_id).await
    }

    async fn update_credential(
        &self,
        credential_id: &str,
        passkey_json: &str,
    ) -> Result<(), AuthError> {
        memory::MemoryDb::update_credential(self, credential_id, passkey_json).await
    }

    async fn delete_credential(&self, credential_id: &str) -> Result<(), AuthError> {
        memory::MemoryDb::delete_credential(self, credential_id).await
    }

    async fn insert_challenge(
        &self,
        challenge_id: &str,
        challenge_data: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError> {
        memory::MemoryDb::insert_challenge(self, challenge_id, challenge_data, ttl_seconds).await
    }

    async fn get_and_delete_challenge(&self, challenge_id: &str) -> Result<String, AuthError> {
        memory::MemoryDb::get_and_delete_challenge(self, challenge_id).await
    }

    async fn get_client(&self, client_id: &str) -> Result<Option<ClientTable>, AuthError> {
        memory::MemoryDb::get_client(self, client_id).await
    }

    async fn insert_client(&self, client: ClientTable) -> Result<(), AuthError> {
        memory::MemoryDb::insert_client(self, client).await
    }

    async fn get_client_for_tenant(
        &self,
        tenant_id: Option<&str>,
        client_id: &str,
    ) -> Result<Option<ClientTable>, AuthError> {
        memory::MemoryDb::get_client_for_tenant(self, tenant_id, client_id).await
    }

    async fn insert_tenant(&self, tenant: TenantTable) -> Result<(), AuthError> {
        memory::MemoryDb::insert_tenant(self, tenant).await
    }

    async fn list_tenants(&self) -> Result<Vec<TenantTable>, AuthError> {
        memory::MemoryDb::list_tenants(self).await
    }

    async fn get_tenant(&self, tenant_id: &str) -> Result<Option<TenantTable>, AuthError> {
        memory::MemoryDb::get_tenant(self, tenant_id).await
    }

    async fn delete_tenant(&self, tenant_id: &str) -> Result<(), AuthError> {
        memory::MemoryDb::delete_tenant(self, tenant_id).await
    }

    async fn add_project_to_tenant(
        &self,
        tenant_id: &str,
        project: ProjectTable,
    ) -> Result<(), AuthError> {
        memory::MemoryDb::add_project_to_tenant(self, tenant_id, project).await
    }

    async fn insert_auth_code(&self, auth_code: &AuthCodeTable) -> Result<(), AuthError> {
        memory::MemoryDb::insert_auth_code(self, auth_code).await
    }

    async fn redeem_auth_code(&self, code: &str) -> Result<Option<AuthCodeTable>, AuthError> {
        memory::MemoryDb::redeem_auth_code(self, code).await
    }

    async fn insert_api_key(&self, api_key: &ApiKeyTable) -> Result<(), AuthError> {
        memory::MemoryDb::insert_api_key(self, api_key).await
    }

    async fn get_api_keys_by_user_id(&self, user_id: &str) -> Result<Vec<ApiKeyTable>, AuthError> {
        memory::MemoryDb::get_api_keys_by_user_id(self, user_id).await
    }

    async fn revoke_api_key(
        &self,
        key_id: &str,
        user_id: &str,
        revoked_at: &str,
    ) -> Result<(), AuthError> {
        memory::MemoryDb::revoke_api_key(self, key_id, user_id, revoked_at).await
    }

    async fn increment_rate_limit(&self, key: &str, window_seconds: i64) -> Result<i64, AuthError> {
        memory::MemoryDb::increment_rate_limit(self, key, window_seconds).await
    }

    async fn insert_audit_event(&self, event: AuditEventRecord) -> Result<(), AuthError> {
        memory::MemoryDb::insert_audit_event(self, event).await
    }

    async fn list_audit_events(&self) -> Result<Vec<AuditEventRecord>, AuthError> {
        memory::MemoryDb::list_audit_events(self).await
    }
}

/// Create a DynamoDB-backed database, loading config from the environment.
pub async fn dynamo() -> Arc<dyn Database> {
    let config = aws_config::load_from_env().await;
    let client = aws_sdk_dynamodb::Client::new(&config);
    Arc::new(DynamoDb {
        client,
        users_table: env::var("USERS_TABLE_NAME").unwrap_or_else(|_| "UsersTable".to_string()),
        users_email_index: env::var("USERS_TABLE_EMAIL_INDEX_NAME")
            .unwrap_or_else(|_| "emailIndex".to_string()),
        sessions_table: env::var("SESSIONS_TABLE_NAME")
            .unwrap_or_else(|_| "SessionsTable".to_string()),
        sessions_user_id_index: env::var("SESSIONS_USER_ID_INDEX_NAME")
            .unwrap_or_else(|_| "userIdIndex".to_string()),
        email_verifications_table: env::var("EMAIL_VERIFICATIONS_TABLE_NAME")
            .unwrap_or_else(|_| "EmailVerificationsTable".to_string()),
        password_resets_table: env::var("PASSWORD_RESETS_TABLE_NAME")
            .unwrap_or_else(|_| "PasswordResetsTable".to_string()),
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
        tenants_table: env::var("TENANTS_TABLE_NAME")
            .unwrap_or_else(|_| "TenantsTable".to_string()),
        auth_codes_table: env::var("AUTH_CODES_TABLE_NAME")
            .unwrap_or_else(|_| "AuthCodesTable".to_string()),
        api_keys_table: env::var("API_KEYS_TABLE_NAME")
            .unwrap_or_else(|_| "ApiKeysTable".to_string()),
        api_keys_user_id_index: env::var("API_KEYS_USER_ID_INDEX_NAME")
            .unwrap_or_else(|_| "userIdIndex".to_string()),
        rate_limits_table: env::var("RATE_LIMITS_TABLE_NAME")
            .unwrap_or_else(|_| "RateLimitsTable".to_string()),
        audit_events_table: env::var("AUDIT_EVENTS_TABLE_NAME")
            .unwrap_or_else(|_| "AuditEventsTable".to_string()),
    })
}

/// Create an in-memory database for local development and testing.
pub fn memory() -> Arc<dyn Database> {
    Arc::new(memory::MemoryDb::new())
}

pub struct AccountExportData {
    pub user: UserTable,
    pub sessions: Vec<SessionTable>,
    pub credentials: Vec<CredentialTable>,
}

pub struct AccountDeleteSummary {
    pub revoked_sessions: usize,
    pub revoked_credentials: usize,
    pub revoked_refresh_tokens: usize,
    pub account_record_deleted: bool,
}

pub async fn export_account_data(
    db: &dyn Database,
    user_id: &str,
) -> Result<AccountExportData, AuthError> {
    let user = db
        .get_user_by_id(user_id)
        .await?
        .ok_or_else(|| AuthError::NotFound("user not found".to_string()))?;

    let sessions = db.get_sessions_by_user_id(user_id).await?;
    let credentials = db.get_credentials_by_user_id(user_id).await?;

    Ok(AccountExportData {
        user,
        sessions,
        credentials,
    })
}

pub async fn delete_account_data(
    db: &dyn Database,
    user_id: &str,
) -> Result<AccountDeleteSummary, AuthError> {
    let sessions = db.get_sessions_by_user_id(user_id).await?;
    let revoked_sessions = sessions.len();
    for session in sessions {
        db.delete_session(&session.id).await?;
    }

    let credentials = db.get_credentials_by_user_id(user_id).await?;
    let revoked_credentials = credentials.len();
    for credential in credentials {
        db.delete_credential(&credential.credential_id).await?;
    }

    let revoked_refresh_tokens = db.delete_refresh_tokens_by_user_id(user_id).await?;
    let account_record_deleted = db.delete_user_by_id(user_id).await?;

    Ok(AccountDeleteSummary {
        revoked_sessions,
        revoked_credentials,
        revoked_refresh_tokens,
        account_record_deleted,
    })
}

pub async fn load_audit_evidence(db: &dyn Database) -> Result<Vec<AuditEventRecord>, AuthError> {
    db.list_audit_events().await
}

pub fn get_saml_config(_db: &dyn Database, issuer_url: &str) -> Result<SamlConfig, AuthError> {
    let config = SamlConfig::from_env(issuer_url);
    config
        .validate()
        .map_err(|e| AuthError::Internal(e.to_string()))?;

    Ok(config)
}

const SCIM_ACTIVE_SCOPE: &str = "scim:active";

fn scim_active_scopes(active: bool) -> Vec<String> {
    if active {
        vec![SCIM_ACTIVE_SCOPE.to_string()]
    } else {
        vec![]
    }
}

/// Look up a session by raw token, verifying it hasn't expired.
pub async fn get_session_by_token(
    db: &dyn Database,
    token: &str,
) -> Result<SessionTable, AuthError> {
    use sha2::{digest::Update, Digest, Sha256};

    let session_id = hex::encode(Sha256::new().chain(token.as_bytes()).finalize());

    let session = db
        .get_session_by_id(&session_id)
        .await?
        .ok_or_else(|| AuthError::Unauthorized("invalid session".into()))?;

    if session.expires_at <= chrono::Utc::now().timestamp() {
        return Err(AuthError::Unauthorized("session expired".into()));
    }

    Ok(session)
}
