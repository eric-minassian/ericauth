use askama::Template;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    Extension, Form, Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{digest::Update, Digest, Sha256};
use uuid::Uuid;

use crate::{
    db::api_key::ApiKeyTable,
    error::AuthError,
    middleware::{auth::AuthenticatedUser, csrf::CsrfToken},
    state::AppState,
    templates::render,
};

#[derive(Deserialize)]
pub struct ApiKeysPageQuery {
    notice: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateApiKeyForm {
    pub name: String,
    pub csrf_token: String,
}

#[derive(Deserialize)]
pub struct RevokeApiKeyForm {
    pub key_id: String,
    #[serde(rename = "csrf_token")]
    _csrf_token: Option<String>,
}

#[derive(Template)]
#[template(path = "account_api_keys.html")]
struct ApiKeysTemplate {
    csrf_token: String,
    api_keys: Vec<ApiKeyResponse>,
    newly_created_key: Option<String>,
    notice: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateApiKeyPayload {
    pub name: String,
}

#[derive(Deserialize)]
pub struct RevokeApiKeyPayload {
    pub key_id: String,
}

#[derive(Serialize)]
pub struct ApiKeyResponse {
    pub key_id: String,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

#[derive(Serialize)]
pub struct ApiKeyListResponse {
    pub api_keys: Vec<ApiKeyResponse>,
}

#[derive(Serialize)]
pub struct RevokeApiKeyResponse {
    pub key_id: String,
    pub revoked_at: String,
}

pub async fn page_handler(
    Extension(csrf): Extension<CsrfToken>,
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<ApiKeysPageQuery>,
) -> Result<impl IntoResponse, AuthError> {
    render_page(
        &state,
        &user,
        csrf.0,
        None,
        map_notice(query.notice),
        map_error(query.error),
    )
    .await
}

pub async fn create_form_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Form(body): Form<CreateApiKeyForm>,
) -> Response {
    match try_create_from_form(&state, &user, &body).await {
        Ok(response) => match render_page(
            &state,
            &user,
            body.csrf_token,
            response.api_key,
            Some("API key created. Copy it now - it will not be shown again.".to_string()),
            None,
        )
        .await
        {
            Ok(html) => html.into_response(),
            Err(_) => Redirect::to(
                "/account/api-keys/manage?error=Failed%20to%20render%20API%20keys%20page",
            )
            .into_response(),
        },
        Err(err) => Redirect::to(&format!(
            "/account/api-keys/manage?error={}",
            urlencoding::encode(user_safe_error(&err))
        ))
        .into_response(),
    }
}

pub async fn revoke_form_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Form(body): Form<RevokeApiKeyForm>,
) -> Response {
    let payload = RevokeApiKeyPayload {
        key_id: body.key_id,
    };

    match revoke_from_payload(state, user, payload).await {
        Ok(_) => Redirect::to("/account/api-keys/manage?notice=key_revoked").into_response(),
        Err(err) => Redirect::to(&format!(
            "/account/api-keys/manage?error={}",
            urlencoding::encode(user_safe_error(&err))
        ))
        .into_response(),
    }
}

pub async fn create_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<CreateApiKeyPayload>,
) -> Result<Json<ApiKeyResponse>, AuthError> {
    Ok(Json(create_from_name(&state, &user, &body.name).await?))
}

pub async fn list_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<ApiKeyListResponse>, AuthError> {
    let mut api_keys = state
        .db
        .get_api_keys_by_user_id(&user.user_id.to_string())
        .await?;
    api_keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    let response = api_keys
        .into_iter()
        .map(|api_key| ApiKeyResponse {
            key_id: api_key.key_id,
            name: api_key.name,
            created_at: api_key.created_at,
            last_used_at: api_key.last_used_at,
            revoked_at: api_key.revoked_at,
            api_key: None,
        })
        .collect();

    Ok(Json(ApiKeyListResponse { api_keys: response }))
}

pub async fn revoke_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<RevokeApiKeyPayload>,
) -> Result<Json<RevokeApiKeyResponse>, AuthError> {
    let response = revoke_from_payload(state, user, body).await?;

    Ok(Json(response))
}

async fn revoke_from_payload(
    state: AppState,
    user: AuthenticatedUser,
    body: RevokeApiKeyPayload,
) -> Result<RevokeApiKeyResponse, AuthError> {
    if body.key_id.trim().is_empty() {
        return Err(AuthError::BadRequest("API key id is required".to_string()));
    }

    let revoked_at = Utc::now().to_rfc3339();
    state
        .db
        .revoke_api_key(&body.key_id, &user.user_id.to_string(), &revoked_at)
        .await?;

    Ok(RevokeApiKeyResponse {
        key_id: body.key_id,
        revoked_at,
    })
}

async fn try_create_from_form(
    state: &AppState,
    user: &AuthenticatedUser,
    body: &CreateApiKeyForm,
) -> Result<ApiKeyResponse, AuthError> {
    create_from_name(state, user, &body.name).await
}

async fn create_from_name(
    state: &AppState,
    user: &AuthenticatedUser,
    name: &str,
) -> Result<ApiKeyResponse, AuthError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AuthError::BadRequest(
            "API key name is required".to_string(),
        ));
    }

    let plaintext_key = generate_api_key()?;
    let key_hash = hex::encode(Sha256::new().chain(plaintext_key.as_bytes()).finalize());
    let key_id = Uuid::new_v4().to_string();
    let created_at = Utc::now().to_rfc3339();

    let record = ApiKeyTable {
        key_id: key_id.clone(),
        user_id: user.user_id.to_string(),
        name: name.to_string(),
        key_hash,
        created_at: created_at.clone(),
        last_used_at: None,
        revoked_at: None,
    };

    state.db.insert_api_key(&record).await?;

    Ok(ApiKeyResponse {
        key_id,
        name: record.name,
        created_at,
        last_used_at: None,
        revoked_at: None,
        api_key: Some(plaintext_key),
    })
}

async fn list_api_keys(
    state: &AppState,
    user: &AuthenticatedUser,
) -> Result<Vec<ApiKeyResponse>, AuthError> {
    let mut api_keys = state
        .db
        .get_api_keys_by_user_id(&user.user_id.to_string())
        .await?;
    api_keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));

    Ok(api_keys
        .into_iter()
        .map(|api_key| ApiKeyResponse {
            key_id: api_key.key_id,
            name: api_key.name,
            created_at: api_key.created_at,
            last_used_at: api_key.last_used_at,
            revoked_at: api_key.revoked_at,
            api_key: None,
        })
        .collect())
}

async fn render_page(
    state: &AppState,
    user: &AuthenticatedUser,
    csrf_token: String,
    newly_created_key: Option<String>,
    notice: Option<String>,
    error: Option<String>,
) -> Result<impl IntoResponse, AuthError> {
    render(&ApiKeysTemplate {
        csrf_token,
        api_keys: list_api_keys(state, user).await?,
        newly_created_key,
        notice,
        error,
    })
}

fn map_notice(notice: Option<String>) -> Option<String> {
    match notice.as_deref() {
        Some("key_revoked") => Some("API key revoked.".to_string()),
        _ => None,
    }
}

fn map_error(error: Option<String>) -> Option<String> {
    error.filter(|value| !value.trim().is_empty())
}

fn user_safe_error(error: &AuthError) -> &str {
    match error {
        AuthError::BadRequest(_) => "Invalid API key request",
        AuthError::NotFound(_) => "API key not found",
        AuthError::Unauthorized(_) | AuthError::Forbidden(_) => "You are not authorized",
        AuthError::Conflict(_) => "Unable to update API key",
        AuthError::Internal(_) => "Unable to process API keys right now",
        AuthError::TooManyRequests(_) => "Too many requests; try again shortly",
    }
}

fn generate_api_key() -> Result<String, AuthError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| AuthError::Internal(format!("failed to generate API key: {e}")))?;

    Ok(format!("ek_{}", URL_SAFE_NO_PAD.encode(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::post,
        Extension, Router,
    };
    use lambda_http::tower::ServiceExt;
    use serde_json::Value;
    use sha2::{digest::Update, Digest, Sha256};

    use crate::{db::session::NewSession, middleware::csrf::CsrfToken, state::AppState};

    async fn test_state_with_auth() -> (AppState, String) {
        let state = AppState {
            db: crate::db::memory(),
            jwt_keys: None,
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
            issuer_url: "https://auth.test.example.com".to_string(),
        };

        let now = chrono::Utc::now().to_rfc3339();
        let user_id = state
            .db
            .insert_user(
                "api-keys@example.com".to_string(),
                Some("hashed_pw".to_string()),
                now.clone(),
                now,
                vec!["openid".to_string()],
                vec![],
            )
            .await
            .unwrap();

        let raw_session_token = "test-session-token".to_string();
        let session_id = hex::encode(Sha256::new().chain(raw_session_token.as_bytes()).finalize());

        state
            .db
            .insert_session(NewSession {
                id: session_id,
                user_id,
                expires_at: chrono::Utc::now().timestamp() + 3600,
                ip_address: "127.0.0.1".to_string(),
                created_at: chrono::Utc::now().timestamp(),
                last_seen_at: chrono::Utc::now().timestamp(),
                user_agent: Some("Test Agent".to_string()),
            })
            .await
            .unwrap();

        (state, raw_session_token)
    }

    async fn add_authenticated_user(state: &AppState, email: &str, token: &str) {
        let now = chrono::Utc::now().to_rfc3339();
        let user_id = state
            .db
            .insert_user(
                email.to_string(),
                Some("hashed_pw".to_string()),
                now.clone(),
                now,
                vec!["openid".to_string()],
                vec![],
            )
            .await
            .unwrap();

        let session_id = hex::encode(Sha256::new().chain(token.as_bytes()).finalize());
        state
            .db
            .insert_session(NewSession {
                id: session_id,
                user_id,
                expires_at: chrono::Utc::now().timestamp() + 3600,
                ip_address: "127.0.0.1".to_string(),
                created_at: chrono::Utc::now().timestamp(),
                last_seen_at: chrono::Utc::now().timestamp(),
                user_agent: Some("Test Agent".to_string()),
            })
            .await
            .unwrap();
    }

    fn test_router(state: AppState) -> Router {
        Router::new()
            .route("/account/api-keys", post(create_handler).get(list_handler))
            .route("/account/api-keys/revoke", post(revoke_handler))
            .route("/account/api-keys/manage", axum::routing::get(page_handler))
            .route("/account/api-keys/manage/create", post(create_form_handler))
            .route("/account/api-keys/manage/revoke", post(revoke_form_handler))
            .layer(Extension(CsrfToken("test-csrf-token".to_string())))
            .with_state(state)
    }

    async fn response_json(response: axum::response::Response) -> Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn test_create_api_key_returns_plaintext_and_metadata() {
        let (state, session_token) = test_state_with_auth().await;
        let app = test_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/account/api-keys")
            .header("content-type", "application/json")
            .header("cookie", format!("session={session_token}"))
            .body(Body::from(r#"{"name":"CI key"}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let json = response_json(response).await;
        assert_eq!(json["name"], "CI key");
        assert!(json["key_id"].as_str().is_some());
        assert!(json["api_key"].as_str().is_some());
        assert!(json["created_at"].as_str().is_some());
        assert!(json["last_used_at"].is_null());
        assert!(json["revoked_at"].is_null());
    }

    #[tokio::test]
    async fn test_list_api_keys_returns_created_and_usage_fields() {
        let (state, session_token) = test_state_with_auth().await;
        let app = test_router(state.clone());

        let create_request = Request::builder()
            .method("POST")
            .uri("/account/api-keys")
            .header("content-type", "application/json")
            .header("cookie", format!("session={session_token}"))
            .body(Body::from(r#"{"name":"Deployment key"}"#))
            .unwrap();
        let create_response = app.clone().oneshot(create_request).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::OK);

        let list_request = Request::builder()
            .method("GET")
            .uri("/account/api-keys")
            .header("cookie", format!("session={session_token}"))
            .body(Body::empty())
            .unwrap();

        let list_response = app.oneshot(list_request).await.unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);

        let json = response_json(list_response).await;
        let api_keys = json["api_keys"].as_array().unwrap();
        assert_eq!(api_keys.len(), 1);
        assert_eq!(api_keys[0]["name"], "Deployment key");
        assert!(api_keys[0]["created_at"].as_str().is_some());
        assert!(api_keys[0]["last_used_at"].is_null());
        assert!(api_keys[0]["revoked_at"].is_null());
        assert!(api_keys[0].get("api_key").is_none());
    }

    #[tokio::test]
    async fn test_revoke_api_key_marks_key_as_revoked() {
        let (state, session_token) = test_state_with_auth().await;
        let app = test_router(state.clone());

        let create_request = Request::builder()
            .method("POST")
            .uri("/account/api-keys")
            .header("content-type", "application/json")
            .header("cookie", format!("session={session_token}"))
            .body(Body::from(r#"{"name":"Revokable key"}"#))
            .unwrap();
        let create_response = app.clone().oneshot(create_request).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::OK);
        let create_json = response_json(create_response).await;
        let key_id = create_json["key_id"].as_str().unwrap().to_string();

        let revoke_request = Request::builder()
            .method("POST")
            .uri("/account/api-keys/revoke")
            .header("content-type", "application/json")
            .header("cookie", format!("session={session_token}"))
            .body(Body::from(format!(r#"{{"key_id":"{key_id}"}}"#)))
            .unwrap();
        let revoke_response = app.clone().oneshot(revoke_request).await.unwrap();
        assert_eq!(revoke_response.status(), StatusCode::OK);

        let list_request = Request::builder()
            .method("GET")
            .uri("/account/api-keys")
            .header("cookie", format!("session={session_token}"))
            .body(Body::empty())
            .unwrap();
        let list_response = app.oneshot(list_request).await.unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_json = response_json(list_response).await;

        let api_keys = list_json["api_keys"].as_array().unwrap();
        assert_eq!(api_keys.len(), 1);
        assert_eq!(api_keys[0]["key_id"], key_id);
        assert!(api_keys[0]["revoked_at"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_revoke_missing_api_key_returns_not_found() {
        let (state, session_token) = test_state_with_auth().await;
        let app = test_router(state);

        let revoke_request = Request::builder()
            .method("POST")
            .uri("/account/api-keys/revoke")
            .header("content-type", "application/json")
            .header("cookie", format!("session={session_token}"))
            .body(Body::from(r#"{"key_id":"missing-key"}"#))
            .unwrap();
        let revoke_response = app.oneshot(revoke_request).await.unwrap();

        assert_eq!(revoke_response.status(), StatusCode::NOT_FOUND);
        let json = response_json(revoke_response).await;
        assert_eq!(json["message"], "api key not found");
    }

    #[tokio::test]
    async fn test_revoke_other_users_api_key_returns_not_found() {
        let (state, owner_session_token) = test_state_with_auth().await;
        let other_session_token = "second-user-session-token".to_string();
        add_authenticated_user(&state, "other-user@example.com", &other_session_token).await;

        let app = test_router(state.clone());

        let create_request = Request::builder()
            .method("POST")
            .uri("/account/api-keys")
            .header("content-type", "application/json")
            .header("cookie", format!("session={owner_session_token}"))
            .body(Body::from(r#"{"name":"Owner key"}"#))
            .unwrap();
        let create_response = app.clone().oneshot(create_request).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::OK);
        let create_json = response_json(create_response).await;
        let key_id = create_json["key_id"].as_str().unwrap().to_string();

        let revoke_request = Request::builder()
            .method("POST")
            .uri("/account/api-keys/revoke")
            .header("content-type", "application/json")
            .header("cookie", format!("session={other_session_token}"))
            .body(Body::from(format!(r#"{{"key_id":"{key_id}"}}"#)))
            .unwrap();
        let revoke_response = app.oneshot(revoke_request).await.unwrap();

        assert_eq!(revoke_response.status(), StatusCode::NOT_FOUND);
        let json = response_json(revoke_response).await;
        assert_eq!(json["message"], "api key not found");
    }

    #[tokio::test]
    async fn test_revoke_twice_returns_not_found_without_overwriting_timestamp() {
        let (state, session_token) = test_state_with_auth().await;
        let app = test_router(state.clone());

        let create_request = Request::builder()
            .method("POST")
            .uri("/account/api-keys")
            .header("content-type", "application/json")
            .header("cookie", format!("session={session_token}"))
            .body(Body::from(r#"{"name":"Single revoke key"}"#))
            .unwrap();
        let create_response = app.clone().oneshot(create_request).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::OK);
        let create_json = response_json(create_response).await;
        let key_id = create_json["key_id"].as_str().unwrap().to_string();

        let first_revoke_request = Request::builder()
            .method("POST")
            .uri("/account/api-keys/revoke")
            .header("content-type", "application/json")
            .header("cookie", format!("session={session_token}"))
            .body(Body::from(format!(r#"{{"key_id":"{key_id}"}}"#)))
            .unwrap();
        let first_revoke_response = app.clone().oneshot(first_revoke_request).await.unwrap();
        assert_eq!(first_revoke_response.status(), StatusCode::OK);
        let first_revoke_json = response_json(first_revoke_response).await;
        let first_revoked_at = first_revoke_json["revoked_at"]
            .as_str()
            .unwrap()
            .to_string();

        let second_revoke_request = Request::builder()
            .method("POST")
            .uri("/account/api-keys/revoke")
            .header("content-type", "application/json")
            .header("cookie", format!("session={session_token}"))
            .body(Body::from(format!(r#"{{"key_id":"{key_id}"}}"#)))
            .unwrap();
        let second_revoke_response = app.clone().oneshot(second_revoke_request).await.unwrap();
        assert_eq!(second_revoke_response.status(), StatusCode::NOT_FOUND);
        let second_revoke_json = response_json(second_revoke_response).await;
        assert_eq!(second_revoke_json["message"], "api key not found");

        let list_request = Request::builder()
            .method("GET")
            .uri("/account/api-keys")
            .header("cookie", format!("session={session_token}"))
            .body(Body::empty())
            .unwrap();
        let list_response = app.oneshot(list_request).await.unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_json = response_json(list_response).await;
        let api_keys = list_json["api_keys"].as_array().unwrap();
        assert_eq!(api_keys.len(), 1);
        assert_eq!(api_keys[0]["key_id"], key_id);
        assert_eq!(api_keys[0]["revoked_at"], first_revoked_at);
    }

    #[tokio::test]
    async fn test_api_keys_manage_page_and_form_handlers() {
        let (state, session_token) = test_state_with_auth().await;
        let app = test_router(state.clone());

        let page_request = Request::builder()
            .method("GET")
            .uri("/account/api-keys/manage")
            .header("cookie", format!("session={session_token}"))
            .body(Body::empty())
            .unwrap();
        let page_response = app.clone().oneshot(page_request).await.unwrap();
        assert_eq!(page_response.status(), StatusCode::OK);

        let create_request = Request::builder()
            .method("POST")
            .uri("/account/api-keys/manage/create")
            .header("content-type", "application/x-www-form-urlencoded")
            .header(
                "cookie",
                format!("session={session_token}; __csrf=test-csrf-token"),
            )
            .body(Body::from("name=UI+key&csrf_token=test-csrf-token"))
            .unwrap();
        let create_response = app.clone().oneshot(create_request).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::OK);

        let list_request = Request::builder()
            .method("GET")
            .uri("/account/api-keys")
            .header("cookie", format!("session={session_token}"))
            .body(Body::empty())
            .unwrap();
        let list_response = app.clone().oneshot(list_request).await.unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_json = response_json(list_response).await;
        let key_id = list_json["api_keys"][0]["key_id"]
            .as_str()
            .unwrap()
            .to_string();
        let revoke_request = Request::builder()
            .method("POST")
            .uri("/account/api-keys/manage/revoke")
            .header("content-type", "application/x-www-form-urlencoded")
            .header(
                "cookie",
                format!("session={session_token}; __csrf=test-csrf-token"),
            )
            .body(Body::from(format!(
                "key_id={}&csrf_token=test-csrf-token",
                urlencoding::encode(&key_id)
            )))
            .unwrap();
        let revoke_response = app.oneshot(revoke_request).await.unwrap();
        assert_eq!(revoke_response.status(), StatusCode::SEE_OTHER);
    }
}
