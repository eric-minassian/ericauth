use askama::Template;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use serde::Deserialize;

use crate::{
    db::tenant::TenantTable,
    error::AuthError,
    middleware::{auth::AuthenticatedUser, csrf::CsrfToken},
    state::AppState,
    templates::render,
};

const TENANT_ADMIN_SCOPES: &[&str] = &["admin", "admin:tenants"];

#[derive(Deserialize)]
pub struct AdminQuery {
    notice: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateTenantForm {
    tenant_id: String,
    name: String,
    #[serde(rename = "csrf_token")]
    _csrf_token: Option<String>,
}

#[derive(Template)]
#[template(path = "admin_tenants.html")]
struct AdminTenantsTemplate {
    csrf_token: String,
    tenants: Vec<TenantTable>,
    notice: Option<String>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin_clients.html")]
struct AdminClientsTemplate {}

#[derive(Template)]
#[template(path = "admin_users.html")]
struct AdminUsersTemplate {}

#[derive(Template)]
#[template(path = "admin_policies.html")]
struct AdminPoliciesTemplate {}

pub async fn tenants_page_handler(
    Extension(csrf): Extension<CsrfToken>,
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<AdminQuery>,
) -> Result<impl IntoResponse, AuthError> {
    require_admin_access(&state, &user).await?;
    let tenants = state.db.list_tenants().await?;

    render(&AdminTenantsTemplate {
        csrf_token: csrf.0,
        tenants,
        notice: map_notice(query.notice),
        error: map_error(query.error),
    })
}

pub async fn create_tenant_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Form(body): Form<CreateTenantForm>,
) -> Response {
    match try_create_tenant(state, user, body).await {
        Ok(()) => Redirect::to("/admin/console/tenants?notice=tenant_created").into_response(),
        Err(err) => Redirect::to(&format!(
            "/admin/console/tenants?error={}",
            urlencoding::encode(user_safe_tenant_create_error(&err))
        ))
        .into_response(),
    }
}

pub async fn clients_page_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AuthError> {
    require_admin_access(&state, &user).await?;
    render(&AdminClientsTemplate {})
}

pub async fn users_page_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AuthError> {
    require_admin_access(&state, &user).await?;
    render(&AdminUsersTemplate {})
}

pub async fn policies_page_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AuthError> {
    require_admin_access(&state, &user).await?;
    render(&AdminPoliciesTemplate {})
}

async fn try_create_tenant(
    state: AppState,
    user: AuthenticatedUser,
    body: CreateTenantForm,
) -> Result<(), AuthError> {
    require_admin_access(&state, &user).await?;

    if body.tenant_id.trim().is_empty() || body.name.trim().is_empty() {
        return Err(AuthError::BadRequest(
            "tenant id and name are required".to_string(),
        ));
    }

    let tenant = TenantTable {
        tenant_id: body.tenant_id.trim().to_string(),
        name: body.name.trim().to_string(),
        projects: Vec::new(),
    };

    state.db.insert_tenant(tenant).await?;

    Ok(())
}

async fn require_admin_access(state: &AppState, user: &AuthenticatedUser) -> Result<(), AuthError> {
    let user_record = state
        .db
        .get_user_by_id(&user.user_id.to_string())
        .await?
        .ok_or_else(|| AuthError::Unauthorized("user not found".to_string()))?;

    let has_admin_scope = user_record
        .scopes
        .iter()
        .any(|scope| TENANT_ADMIN_SCOPES.contains(&scope.as_str()));

    if has_admin_scope {
        Ok(())
    } else {
        Err(AuthError::Unauthorized("admin scope required".to_string()))
    }
}

fn user_safe_tenant_create_error(err: &AuthError) -> &str {
    match err {
        AuthError::Unauthorized(_) => "Admin scope required",
        AuthError::Forbidden(_) => "Admin scope required",
        AuthError::BadRequest(_) => "Tenant ID and name are required",
        AuthError::Conflict(_) => "Tenant already exists",
        AuthError::Internal(_) => "Unable to create tenant right now",
        AuthError::NotFound(_) => "Unable to create tenant right now",
        AuthError::TooManyRequests(_) => "Too many requests; try again shortly",
    }
}

fn map_notice(notice: Option<String>) -> Option<String> {
    match notice.as_deref() {
        Some("tenant_created") => Some("Tenant created.".to_string()),
        _ => None,
    }
}

fn map_error(error: Option<String>) -> Option<String> {
    error.filter(|e| !e.trim().is_empty())
}
