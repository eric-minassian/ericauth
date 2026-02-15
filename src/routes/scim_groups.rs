use axum::{http::HeaderMap, http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

use crate::error::AuthError;

use super::scim_auth::require_scim_admin_token;

pub async fn list_handler(headers: HeaderMap) -> Result<impl IntoResponse, AuthError> {
    require_scim_admin_token(&headers)?;

    Ok((
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({ "message": "SCIM groups provisioning is not implemented" })),
    ))
}

pub async fn create_handler(
    headers: HeaderMap,
    Json(_payload): Json<serde_json::Value>,
) -> Result<impl IntoResponse, AuthError> {
    require_scim_admin_token(&headers)?;

    Ok((
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({ "message": "SCIM groups provisioning is not implemented" })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::{body::Body, http::Request, routing::get, Router};
    use lambda_http::tower::ServiceExt;
    use serde_json::json;

    fn test_router() -> Router {
        Router::new().route("/scim/v2/Groups", get(list_handler).post(create_handler))
    }

    #[tokio::test]
    async fn test_scim_groups_list_returns_not_implemented() {
        let app = test_router();

        let request = Request::builder()
            .method("GET")
            .uri("/scim/v2/Groups")
            .header("Authorization", "Bearer test-scim-admin-token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_scim_groups_create_returns_not_implemented() {
        let app = test_router();

        let request = Request::builder()
            .method("POST")
            .uri("/scim/v2/Groups")
            .header("Authorization", "Bearer test-scim-admin-token")
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                    "displayName": "engineering"
                })
                .to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn test_scim_groups_reject_invalid_admin_token() {
        let app = test_router();

        let request = Request::builder()
            .method("GET")
            .uri("/scim/v2/Groups")
            .header("Authorization", "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
