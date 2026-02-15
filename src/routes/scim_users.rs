use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    error::AuthError,
    state::AppState,
    validation::{normalize_email, verify_email},
};

use super::scim_auth::require_scim_admin_token;

const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
#[cfg(test)]
const SCIM_PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

#[derive(Deserialize)]
pub struct ScimUserPayload {
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(default = "default_true")]
    pub active: bool,
}

#[derive(Deserialize)]
pub struct ScimPatchPayload {
    #[serde(default, rename = "Operations")]
    pub operations: Vec<ScimPatchOperation>,
}

#[derive(Deserialize)]
pub struct ScimPatchOperation {
    pub op: String,
    pub path: Option<String>,
    pub value: Option<serde_json::Value>,
}

const fn default_true() -> bool {
    true
}

pub async fn create_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ScimUserPayload>,
) -> Result<impl IntoResponse, AuthError> {
    require_scim_admin_token(&headers)?;

    let normalized_email = validated_scim_email(payload.user_name)?;

    let user = state
        .db
        .scim_create_user(normalized_email, payload.active)
        .await?;

    Ok((StatusCode::CREATED, Json(scim_user_response(&user))))
}

pub async fn update_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ScimUserPayload>,
) -> Result<impl IntoResponse, AuthError> {
    require_scim_admin_token(&headers)?;

    let normalized_email = validated_scim_email(payload.user_name)?;

    let user = state
        .db
        .scim_update_user(&user_id, normalized_email, payload.active)
        .await?;

    Ok((StatusCode::OK, Json(scim_user_response(&user))))
}

pub async fn patch_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ScimPatchPayload>,
) -> Result<impl IntoResponse, AuthError> {
    require_scim_admin_token(&headers)?;

    let active = extract_active_patch(&payload)?;
    let user = state.db.scim_set_user_active(&user_id, active).await?;

    Ok((StatusCode::OK, Json(scim_user_response(&user))))
}

fn validated_scim_email(user_name: String) -> Result<String, AuthError> {
    let normalized = normalize_email(&user_name);
    if !verify_email(&normalized) {
        return Err(AuthError::BadRequest("invalid SCIM userName email".into()));
    }

    Ok(normalized)
}

fn extract_active_patch(payload: &ScimPatchPayload) -> Result<bool, AuthError> {
    for operation in &payload.operations {
        if !operation.op.eq_ignore_ascii_case("replace") {
            continue;
        }

        if let Some(path) = operation.path.as_deref() {
            if path.eq_ignore_ascii_case("active") {
                if let Some(value) = operation
                    .value
                    .as_ref()
                    .and_then(serde_json::Value::as_bool)
                {
                    return Ok(value);
                }
            }
            continue;
        }

        if let Some(value) = operation.value.as_ref() {
            if let Some(active) = value.get("active").and_then(serde_json::Value::as_bool) {
                return Ok(active);
            }
        }
    }

    Err(AuthError::BadRequest(
        "SCIM patch must replace the active attribute".into(),
    ))
}

fn scim_user_response(user: &crate::db::user::UserTable) -> serde_json::Value {
    json!({
        "schemas": [SCIM_USER_SCHEMA],
        "id": user.id.to_string(),
        "userName": user.email,
        "active": is_scim_active(user),
    })
}

fn is_scim_active(user: &crate::db::user::UserTable) -> bool {
    user.scopes.iter().any(|scope| scope == "scim:active")
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::{
        body::Body,
        http::Request,
        routing::{post, put},
        Router,
    };
    use lambda_http::tower::ServiceExt;
    use serde_json::json;

    fn test_state() -> AppState {
        AppState {
            db: crate::db::memory(),
            jwt_keys: None,
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
            issuer_url: "https://auth.test.example.com".to_string(),
        }
    }

    fn test_router(state: AppState) -> Router {
        Router::new()
            .route("/scim/v2/Users", post(create_handler))
            .route(
                "/scim/v2/Users/{id}",
                put(update_handler).patch(patch_handler),
            )
            .with_state(state)
    }

    #[tokio::test]
    async fn test_scim_create_user() {
        let app = test_router(test_state());
        let request = Request::builder()
            .method("POST")
            .uri("/scim/v2/Users")
            .header("Authorization", "Bearer test-scim-admin-token")
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({
                    "schemas": [SCIM_USER_SCHEMA],
                    "userName": "alice@example.com",
                    "active": true
                })
                .to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["schemas"], json!([SCIM_USER_SCHEMA]));
        assert_eq!(json["userName"], "alice@example.com");
        assert_eq!(json["active"], true);
        assert!(json["id"].as_str().is_some_and(|value| !value.is_empty()));
    }

    #[tokio::test]
    async fn test_scim_update_user() {
        let app = test_router(test_state());

        let create_request = Request::builder()
            .method("POST")
            .uri("/scim/v2/Users")
            .header("Authorization", "Bearer test-scim-admin-token")
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({
                    "schemas": [SCIM_USER_SCHEMA],
                    "userName": "alice@example.com",
                    "active": true
                })
                .to_string(),
            ))
            .unwrap();

        let create_response = app.clone().oneshot(create_request).await.unwrap();
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&create_body).unwrap();
        let user_id = created["id"].as_str().unwrap();

        let update_request = Request::builder()
            .method("PUT")
            .uri(format!("/scim/v2/Users/{user_id}"))
            .header("Authorization", "Bearer test-scim-admin-token")
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({
                    "schemas": [SCIM_USER_SCHEMA],
                    "userName": "alice@example.com",
                    "active": true
                })
                .to_string(),
            ))
            .unwrap();

        let update_response = app.oneshot(update_request).await.unwrap();
        assert_eq!(update_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_scim_deactivate_user() {
        let app = test_router(test_state());

        let create_request = Request::builder()
            .method("POST")
            .uri("/scim/v2/Users")
            .header("Authorization", "Bearer test-scim-admin-token")
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({
                    "schemas": [SCIM_USER_SCHEMA],
                    "userName": "alice@example.com",
                    "active": true
                })
                .to_string(),
            ))
            .unwrap();

        let create_response = app.clone().oneshot(create_request).await.unwrap();
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&create_body).unwrap();
        let user_id = created["id"].as_str().unwrap();

        let patch_request = Request::builder()
            .method("PATCH")
            .uri(format!("/scim/v2/Users/{user_id}"))
            .header("Authorization", "Bearer test-scim-admin-token")
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({
                    "schemas": [SCIM_PATCH_OP_SCHEMA],
                    "Operations": [
                        { "op": "Replace", "path": "active", "value": false }
                    ]
                })
                .to_string(),
            ))
            .unwrap();

        let patch_response = app.oneshot(patch_request).await.unwrap();
        assert_eq!(patch_response.status(), StatusCode::OK);

        let patch_body = axum::body::to_bytes(patch_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let patched: serde_json::Value = serde_json::from_slice(&patch_body).unwrap();
        assert_eq!(patched["active"], false);
    }

    #[tokio::test]
    async fn test_scim_rejects_invalid_admin_token() {
        let app = test_router(test_state());
        let request = Request::builder()
            .method("POST")
            .uri("/scim/v2/Users")
            .header("Authorization", "Bearer wrong-token")
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({
                    "schemas": [SCIM_USER_SCHEMA],
                    "userName": "alice@example.com"
                })
                .to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_scim_create_user_rejects_invalid_username_email() {
        let app = test_router(test_state());
        let request = Request::builder()
            .method("POST")
            .uri("/scim/v2/Users")
            .header("Authorization", "Bearer test-scim-admin-token")
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({
                    "schemas": [SCIM_USER_SCHEMA],
                    "userName": "not-an-email"
                })
                .to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "invalid SCIM userName email");
    }

    #[tokio::test]
    async fn test_scim_update_user_normalizes_username_email() {
        let app = test_router(test_state());

        let create_request = Request::builder()
            .method("POST")
            .uri("/scim/v2/Users")
            .header("Authorization", "Bearer test-scim-admin-token")
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({
                    "schemas": [SCIM_USER_SCHEMA],
                    "userName": "alice@example.com",
                    "active": true
                })
                .to_string(),
            ))
            .unwrap();

        let create_response = app.clone().oneshot(create_request).await.unwrap();
        let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&create_body).unwrap();
        let user_id = created["id"].as_str().unwrap();

        let update_request = Request::builder()
            .method("PUT")
            .uri(format!("/scim/v2/Users/{user_id}"))
            .header("Authorization", "Bearer test-scim-admin-token")
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({
                    "schemas": [SCIM_USER_SCHEMA],
                    "userName": " Alice@Example.com ",
                    "active": true
                })
                .to_string(),
            ))
            .unwrap();

        let update_response = app.oneshot(update_request).await.unwrap();
        assert_eq!(update_response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(update_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["userName"], "alice@example.com");
    }
}
