use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;

use crate::{
    admin_rbac::{has_admin_permission, AdminPermission},
    audit::{append_event, AuditEventInput},
    db,
    error::AuthError,
    middleware::auth::AuthenticatedUser,
    state::AppState,
};

#[derive(Serialize)]
pub struct AccountExportResponse {
    user_id: String,
    email: String,
    created_at: String,
    updated_at: String,
    scopes: Vec<String>,
    recovery_codes_remaining: usize,
    sessions: Vec<AccountSessionRecord>,
    credentials: Vec<AccountCredentialRecord>,
}

#[derive(Serialize)]
pub struct AccountSessionRecord {
    id: String,
    ip_address: String,
    created_at: i64,
    last_seen_at: i64,
    expires_at: i64,
    user_agent: Option<String>,
}

#[derive(Serialize)]
pub struct AccountCredentialRecord {
    credential_id: String,
    created_at: String,
    last_used_at: Option<String>,
}

#[derive(Serialize)]
pub struct AccountDeleteResponse {
    status: &'static str,
    revoked_sessions: usize,
    revoked_credentials: usize,
    account_record_deleted: bool,
}

pub async fn account_export_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AuthError> {
    let exported = db::export_account_data(state.db.as_ref(), &user.user_id.to_string()).await?;

    append_event(
        state.db.as_ref(),
        AuditEventInput {
            event_type: "compliance.account.export".to_string(),
            outcome: "success".to_string(),
            actor: Some(user.user_id.to_string()),
            client_ip: None,
            user_agent: None,
            metadata: std::collections::BTreeMap::new(),
        },
    )
    .await?;

    let response = AccountExportResponse {
        user_id: exported.user.id.to_string(),
        email: exported.user.email,
        created_at: exported.user.created_at,
        updated_at: exported.user.updated_at,
        scopes: exported.user.scopes,
        recovery_codes_remaining: exported.user.recovery_codes.len(),
        sessions: exported
            .sessions
            .into_iter()
            .map(|session| AccountSessionRecord {
                id: session.id,
                ip_address: session.ip_address,
                created_at: session.created_at,
                last_seen_at: session.last_seen_at,
                expires_at: session.expires_at,
                user_agent: session.user_agent,
            })
            .collect(),
        credentials: exported
            .credentials
            .into_iter()
            .map(|credential| AccountCredentialRecord {
                credential_id: credential.credential_id,
                created_at: credential.created_at,
                last_used_at: credential.last_used_at,
            })
            .collect(),
    };

    Ok((StatusCode::OK, Json(response)))
}

pub async fn account_delete_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AuthError> {
    let summary = db::delete_account_data(state.db.as_ref(), &user.user_id.to_string()).await?;

    append_event(
        state.db.as_ref(),
        AuditEventInput {
            event_type: "compliance.account.delete".to_string(),
            outcome: "success".to_string(),
            actor: Some(user.user_id.to_string()),
            client_ip: None,
            user_agent: None,
            metadata: std::collections::BTreeMap::new(),
        },
    )
    .await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(AccountDeleteResponse {
            status: "accepted",
            revoked_sessions: summary.revoked_sessions,
            revoked_credentials: summary.revoked_credentials,
            account_record_deleted: summary.account_record_deleted,
        }),
    ))
}

pub async fn audit_evidence_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AuthError> {
    let user_record = state
        .db
        .get_user_by_id(&user.user_id.to_string())
        .await?
        .ok_or_else(|| AuthError::Unauthorized("user not found".to_string()))?;

    if !has_admin_permission(&user_record.scopes, AdminPermission::ReadAuditEvents) {
        return Err(AuthError::Forbidden("insufficient_scope".to_string()));
    }

    Ok(Json(db::load_audit_evidence(state.db.as_ref()).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::{get, post},
        Router,
    };
    use lambda_http::tower::ServiceExt;

    use crate::{
        audit::{append_event, AuditEventInput},
        db::refresh_token::RefreshTokenTable,
        jwt::{generate_es256_keypair, JwtKeys},
        session::{create_session, generate_session_token},
        state::AppState,
    };

    fn test_state() -> AppState {
        let (private_pem, _) = generate_es256_keypair().unwrap();
        let jwt_keys = JwtKeys::from_pem(private_pem.as_bytes(), "test-kid").unwrap();
        AppState {
            db: crate::db::memory(),
            jwt_keys: Some(jwt_keys),
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
            issuer_url: "https://auth.test.example.com".to_string(),
        }
    }

    fn test_router(state: AppState) -> Router {
        Router::new()
            .route("/compliance/account/export", get(account_export_handler))
            .route("/compliance/account/delete", post(account_delete_handler))
            .route("/compliance/audit/evidence", get(audit_evidence_handler))
            .with_state(state)
    }

    async fn create_session_cookie(
        state: &AppState,
        email: &str,
        scopes: Vec<String>,
    ) -> (String, String) {
        let now = chrono::Utc::now().to_rfc3339();
        let user_id = state
            .db
            .insert_user(
                email.to_string(),
                Some("hashed_pw".to_string()),
                now.clone(),
                now,
                scopes,
                vec![],
            )
            .await
            .unwrap();

        let token = generate_session_token().unwrap();
        create_session(
            state.db.as_ref(),
            token.clone(),
            user_id,
            "127.0.0.1".to_string(),
            Some("compliance-tests".to_string()),
        )
        .await
        .unwrap();

        (format!("session={token}"), user_id.to_string())
    }

    #[tokio::test]
    async fn test_account_export_requires_authenticated_session() {
        let state = test_state();
        let app = test_router(state.clone());

        let request = Request::builder()
            .method("GET")
            .uri("/compliance/account/export")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_account_export_and_delete_return_success_for_authenticated_user() {
        let state = test_state();
        let (cookie, user_id) = create_session_cookie(
            &state,
            "compliance-user@example.com",
            vec!["openid".to_string()],
        )
        .await;

        state
            .db
            .insert_credential(
                "cred-1",
                &user_id,
                "{\"type\":\"passkey\"}",
                &chrono::Utc::now().to_rfc3339(),
            )
            .await
            .unwrap();

        state
            .db
            .insert_refresh_token(&RefreshTokenTable {
                token_hash: "refresh-token-user".to_string(),
                user_id: user_id.clone(),
                client_id: "compliance-client".to_string(),
                scope: "openid profile".to_string(),
                expires_at: chrono::Utc::now().timestamp() + 3600,
                revoked: false,
            })
            .await
            .unwrap();

        let (_, other_user_id) =
            create_session_cookie(&state, "other-user@example.com", vec!["openid".to_string()])
                .await;

        state
            .db
            .insert_refresh_token(&RefreshTokenTable {
                token_hash: "refresh-token-other-user".to_string(),
                user_id: other_user_id,
                client_id: "compliance-client".to_string(),
                scope: "openid profile".to_string(),
                expires_at: chrono::Utc::now().timestamp() + 3600,
                revoked: false,
            })
            .await
            .unwrap();

        let app = test_router(state.clone());
        let export_request = Request::builder()
            .method("GET")
            .uri("/compliance/account/export")
            .header("Cookie", cookie.clone())
            .body(Body::empty())
            .unwrap();
        let export_response = app.oneshot(export_request).await.unwrap();
        assert_eq!(export_response.status(), StatusCode::OK);
        let export_body = axum::body::to_bytes(export_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let export_json: serde_json::Value = serde_json::from_slice(&export_body).unwrap();
        assert_eq!(export_json["user_id"], user_id);
        assert_eq!(export_json["credentials"].as_array().unwrap().len(), 1);

        let app = test_router(state.clone());
        let delete_request = Request::builder()
            .method("POST")
            .uri("/compliance/account/delete")
            .header("Cookie", cookie)
            .body(Body::empty())
            .unwrap();
        let delete_response = app.oneshot(delete_request).await.unwrap();
        assert_eq!(delete_response.status(), StatusCode::ACCEPTED);
        let delete_body = axum::body::to_bytes(delete_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let delete_json: serde_json::Value = serde_json::from_slice(&delete_body).unwrap();
        assert_eq!(delete_json["status"], "accepted");
        assert_eq!(delete_json["revoked_sessions"], 1);
        assert_eq!(delete_json["revoked_credentials"], 1);
        assert_eq!(delete_json["account_record_deleted"], true);

        let user_after_delete = state.db.get_user_by_id(&user_id).await.unwrap();
        assert!(user_after_delete.is_none());

        let deleted_users_refresh = state
            .db
            .get_refresh_token("refresh-token-user")
            .await
            .unwrap();
        assert!(deleted_users_refresh.is_none());

        let other_users_refresh = state
            .db
            .get_refresh_token("refresh-token-other-user")
            .await
            .unwrap();
        assert!(other_users_refresh.is_some());
    }

    #[tokio::test]
    async fn test_audit_evidence_requires_admin_scope_and_returns_events() {
        let state = test_state();
        append_event(
            state.db.as_ref(),
            AuditEventInput {
                event_type: "auth.login".to_string(),
                outcome: "success".to_string(),
                actor: Some("compliance-user@example.com".to_string()),
                client_ip: Some("127.0.0.1".to_string()),
                user_agent: Some("test-agent".to_string()),
                metadata: BTreeMap::new(),
            },
        )
        .await
        .unwrap();

        let (non_admin_cookie, _) =
            create_session_cookie(&state, "reader@example.com", vec!["openid".to_string()]).await;
        let app = test_router(state.clone());
        let forbidden_request = Request::builder()
            .method("GET")
            .uri("/compliance/audit/evidence")
            .header("Cookie", non_admin_cookie)
            .body(Body::empty())
            .unwrap();
        let forbidden_response = app.oneshot(forbidden_request).await.unwrap();
        assert_eq!(forbidden_response.status(), StatusCode::FORBIDDEN);

        let (admin_cookie, _) =
            create_session_cookie(&state, "admin@example.com", vec!["audit:read".to_string()])
                .await;
        let app = test_router(state);
        let allowed_request = Request::builder()
            .method("GET")
            .uri("/compliance/audit/evidence")
            .header("Cookie", admin_cookie)
            .body(Body::empty())
            .unwrap();
        let allowed_response = app.oneshot(allowed_request).await.unwrap();
        assert_eq!(allowed_response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(allowed_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let events: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(events.as_array().is_some_and(|items| !items.is_empty()));
    }
}
