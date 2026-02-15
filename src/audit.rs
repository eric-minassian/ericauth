use std::collections::BTreeMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::routes::events_webhook::{
    deliver_with_retries, delivery_metadata, webhook_sink_from_env,
};
use crate::{db::Database, error::AuthError};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventRecord {
    pub id: String,
    pub event_type: String,
    pub outcome: String,
    pub actor: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventInput {
    pub event_type: String,
    pub outcome: String,
    pub actor: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

pub const ERROR_CODE_KEY: &str = "error_code";

pub async fn append_event(
    db: &dyn Database,
    event: AuditEventInput,
) -> Result<AuditEventRecord, AuthError> {
    let mut record = AuditEventRecord {
        id: Uuid::new_v4().to_string(),
        event_type: event.event_type,
        outcome: event.outcome,
        actor: event.actor,
        client_ip: event.client_ip,
        user_agent: event.user_agent,
        created_at: Utc::now().to_rfc3339(),
        metadata: event.metadata,
    };

    if let Some(config) = webhook_sink_from_env() {
        let delivery = deliver_with_retries(&record, &config).await;
        for (key, value) in delivery_metadata(&delivery) {
            record.metadata.insert(key, value);
        }
    }

    db.insert_audit_event(record.clone()).await?;
    Ok(record)
}

pub async fn list_events(db: &dyn Database) -> Result<Vec<AuditEventRecord>, AuthError> {
    db.list_audit_events().await
}

#[must_use]
pub fn auth_error_code(error: &AuthError) -> &'static str {
    match error {
        AuthError::BadRequest(_) => "bad_request",
        AuthError::Unauthorized(_) => "unauthorized",
        AuthError::Forbidden(_) => "forbidden",
        AuthError::NotFound(_) => "not_found",
        AuthError::Conflict(_) => "conflict",
        AuthError::Internal(_) => "internal_error",
        AuthError::TooManyRequests(_) => "too_many_requests",
    }
}

#[must_use]
pub fn token_error_code(error: Option<&str>) -> &'static str {
    match error {
        Some("invalid_request") => "invalid_request",
        Some("invalid_grant") => "invalid_grant",
        Some("invalid_scope") => "invalid_scope",
        Some("unsupported_grant_type") => "unsupported_grant_type",
        Some("server_error") => "server_error",
        Some(_) => "other_token_error",
        None => "unknown_token_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_creates_a_structured_event_record() {
        let db = crate::db::memory();
        let mut metadata = BTreeMap::new();
        metadata.insert("route".to_string(), "/login".to_string());

        let created = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(append_event(
                db.as_ref(),
                AuditEventInput {
                    event_type: "auth.login".to_string(),
                    outcome: "success".to_string(),
                    actor: Some("user@example.com".to_string()),
                    client_ip: Some("127.0.0.1".to_string()),
                    user_agent: Some("test-agent".to_string()),
                    metadata,
                },
            ))
            .expect("event should be created");

        assert!(!created.id.is_empty());
        assert_eq!(created.event_type, "auth.login");
        assert_eq!(created.outcome, "success");
        assert_eq!(created.actor.as_deref(), Some("user@example.com"));
        assert!(!created.created_at.is_empty());
        assert_eq!(
            created.metadata.get("route").map(String::as_str),
            Some("/login")
        );
    }

    #[test]
    fn test_append_is_append_only_and_keeps_existing_records() {
        let db = crate::db::memory();

        let first = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(append_event(
                db.as_ref(),
                AuditEventInput {
                    event_type: "auth.signup".to_string(),
                    outcome: "success".to_string(),
                    actor: Some("first@example.com".to_string()),
                    client_ip: None,
                    user_agent: None,
                    metadata: BTreeMap::new(),
                },
            ))
            .expect("first event should be created");

        let second = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(append_event(
                db.as_ref(),
                AuditEventInput {
                    event_type: "oauth.token".to_string(),
                    outcome: "failure".to_string(),
                    actor: None,
                    client_ip: Some("10.0.0.1".to_string()),
                    user_agent: None,
                    metadata: BTreeMap::new(),
                },
            ))
            .expect("second event should be created");

        let all = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(list_events(db.as_ref()))
            .expect("list should succeed");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, first.id);
        assert_eq!(all[1].id, second.id);
        assert_ne!(first.id, second.id);
    }

    #[test]
    fn test_auth_error_code_returns_stable_category() {
        assert_eq!(
            auth_error_code(&AuthError::Unauthorized("secret detail".to_string())),
            "unauthorized"
        );
        assert_eq!(
            auth_error_code(&AuthError::Internal("db timeout stacktrace".to_string())),
            "internal_error"
        );
    }

    #[test]
    fn test_token_error_code_maps_unknown_values_to_safe_category() {
        assert_eq!(token_error_code(Some("invalid_grant")), "invalid_grant");
        assert_eq!(
            token_error_code(Some("sensitive_internal_reason")),
            "other_token_error"
        );
        assert_eq!(token_error_code(None), "unknown_token_error");
    }

    #[test]
    fn test_append_and_list_use_database_abstraction() {
        let db = crate::db::memory();

        let created = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(append_event(
                db.as_ref(),
                AuditEventInput {
                    event_type: "auth.login".to_string(),
                    outcome: "success".to_string(),
                    actor: Some("user@example.com".to_string()),
                    client_ip: Some("127.0.0.1".to_string()),
                    user_agent: Some("test-agent".to_string()),
                    metadata: BTreeMap::new(),
                },
            ))
            .expect("event should be persisted");

        let listed = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(list_events(db.as_ref()))
            .expect("list should load from db");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, created.id);
    }
}
