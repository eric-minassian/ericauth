use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    db::tenant::{ProjectTable, TenantTable},
    error::AuthError,
    middleware::auth::AuthenticatedUser,
    state::AppState,
};

const ADMIN_SCOPES: &[&str] = &["admin", "admin:tenants"];

#[derive(Deserialize)]
pub struct CreateTenantPayload {
    tenant_id: String,
    name: String,
}

#[derive(Deserialize)]
pub struct CreateProjectPayload {
    project_id: String,
    name: String,
    client_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct TenantListResponse {
    tenants: Vec<TenantTable>,
}

pub async fn list_tenants_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AuthError> {
    require_admin_scope(&state, &user).await?;
    let tenants = state.db.list_tenants().await?;
    Ok(Json(TenantListResponse { tenants }))
}

pub async fn create_tenant_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(payload): Json<CreateTenantPayload>,
) -> Result<impl IntoResponse, AuthError> {
    require_admin_scope(&state, &user).await?;
    let tenant = TenantTable {
        tenant_id: payload.tenant_id,
        name: payload.name,
        projects: Vec::new(),
    };

    state.db.insert_tenant(tenant.clone()).await?;

    Ok((StatusCode::CREATED, Json(tenant)))
}

pub async fn get_tenant_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(tenant_id): Path<String>,
) -> Result<impl IntoResponse, AuthError> {
    require_admin_scope(&state, &user).await?;
    let tenant = state
        .db
        .get_tenant(&tenant_id)
        .await?
        .ok_or_else(|| AuthError::NotFound("tenant not found".to_string()))?;

    Ok(Json(tenant))
}

pub async fn delete_tenant_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(tenant_id): Path<String>,
) -> Result<impl IntoResponse, AuthError> {
    require_admin_scope(&state, &user).await?;
    state.db.delete_tenant(&tenant_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn create_project_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(tenant_id): Path<String>,
    Json(payload): Json<CreateProjectPayload>,
) -> Result<impl IntoResponse, AuthError> {
    require_admin_scope(&state, &user).await?;
    let project = ProjectTable {
        project_id: payload.project_id,
        name: payload.name,
        client_ids: payload.client_ids,
    };

    state
        .db
        .add_project_to_tenant(&tenant_id, project.clone())
        .await?;

    Ok((StatusCode::CREATED, Json(project)))
}

pub async fn get_tenant_client_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((tenant_id, client_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, AuthError> {
    require_admin_scope(&state, &user).await?;
    let client = state
        .db
        .get_client_for_tenant(Some(tenant_id.as_str()), &client_id)
        .await?
        .ok_or_else(|| AuthError::NotFound("client not found".to_string()))?;

    Ok(Json(client))
}

async fn require_admin_scope(state: &AppState, user: &AuthenticatedUser) -> Result<(), AuthError> {
    let user_record = state
        .db
        .get_user_by_id(&user.user_id.to_string())
        .await?
        .ok_or_else(|| AuthError::Unauthorized("user not found".to_string()))?;

    if user_record
        .scopes
        .iter()
        .any(|scope| ADMIN_SCOPES.contains(&scope.as_str()))
    {
        Ok(())
    } else {
        Err(AuthError::Unauthorized("admin scope required".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use lambda_http::tower::ServiceExt;
    use serde_json::Value;
    use uuid::Uuid;

    use crate::{db::client::ClientTable, state::AppState};

    fn test_app_state() -> AppState {
        AppState {
            db: crate::db::memory(),
            jwt_keys: None,
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
            issuer_url: "https://auth.test.example.com".to_string(),
        }
    }

    fn build_router(state: AppState) -> axum::Router {
        crate::routes::router(state)
    }

    async fn create_session_cookie_for_scopes(state: &AppState, scopes: Vec<String>) -> String {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let email = format!("{}@example.com", Uuid::new_v4());

        let user_id = state
            .db
            .insert_user(
                email,
                None,
                timestamp.clone(),
                timestamp,
                scopes,
                Vec::new(),
            )
            .await
            .unwrap();

        let token = format!("session-{}", Uuid::new_v4());
        crate::session::create_session(
            &*state.db,
            token.clone(),
            user_id,
            "127.0.0.1".to_string(),
            Some("test-agent".to_string()),
        )
        .await
        .unwrap();

        format!("session={token}")
    }

    async fn read_json(response: axum::response::Response) -> Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_tenant_crud_and_project_creation() {
        let state = test_app_state();
        let admin_cookie = create_session_cookie_for_scopes(
            &state,
            vec!["openid".to_string(), "admin:tenants".to_string()],
        )
        .await;
        let app = build_router(state);

        let create_tenant_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tenants")
                    .header("cookie", &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tenant_id":"tenant-a","name":"Tenant A"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_tenant_response.status(), StatusCode::CREATED);

        let create_project_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tenants/tenant-a/projects")
                    .header("cookie", &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"project_id":"project-1","name":"Project 1","client_ids":["client-a"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(create_project_response.status(), StatusCode::CREATED);

        let get_tenant_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/tenants/tenant-a")
                    .header("cookie", &admin_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_tenant_response.status(), StatusCode::OK);
        let tenant_json = read_json(get_tenant_response).await;
        assert_eq!(tenant_json["tenant_id"], "tenant-a");
        assert_eq!(tenant_json["projects"].as_array().unwrap().len(), 1);

        let list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/tenants")
                    .header("cookie", &admin_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_json = read_json(list_response).await;
        assert_eq!(list_json["tenants"].as_array().unwrap().len(), 1);

        let delete_response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/admin/tenants/tenant-a")
                    .header("cookie", &admin_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn test_client_lookup_is_tenant_isolated() {
        let state = test_app_state();
        let admin_cookie = create_session_cookie_for_scopes(
            &state,
            vec!["openid".to_string(), "admin:tenants".to_string()],
        )
        .await;
        state
            .db
            .insert_client(ClientTable {
                client_id: "client-a".to_string(),
                redirect_uris: vec!["https://example.com/callback".to_string()],
                allowed_scopes: vec!["openid".to_string()],
                client_name: "Client A".to_string(),
            })
            .await
            .unwrap();
        state
            .db
            .insert_client(ClientTable {
                client_id: "client-b".to_string(),
                redirect_uris: vec!["https://example.com/callback".to_string()],
                allowed_scopes: vec!["openid".to_string()],
                client_name: "Client B".to_string(),
            })
            .await
            .unwrap();

        let app = build_router(state);

        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tenants")
                    .header("cookie", &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tenant_id":"tenant-a","name":"Tenant A"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tenants")
                    .header("cookie", &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tenant_id":"tenant-b","name":"Tenant B"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tenants/tenant-a/projects")
                    .header("cookie", &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"project_id":"project-a","name":"Project A","client_ids":["client-a"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/tenants/tenant-b/projects")
                    .header("cookie", &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"project_id":"project-b","name":"Project B","client_ids":["client-b"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let allowed_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/tenants/tenant-a/clients/client-a")
                    .header("cookie", &admin_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed_response.status(), StatusCode::OK);

        let blocked_response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/tenants/tenant-a/clients/client-b")
                    .header("cookie", &admin_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(blocked_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_admin_tenant_routes_require_authentication() {
        let state = test_app_state();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/tenants")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_admin_tenant_routes_require_admin_scope() {
        let state = test_app_state();
        let cookie = create_session_cookie_for_scopes(&state, vec!["openid".to_string()]).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/tenants")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_admin_users_scope_is_not_enough_for_tenant_management() {
        let state = test_app_state();
        let cookie =
            create_session_cookie_for_scopes(&state, vec!["admin:users".to_string()]).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/tenants")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
