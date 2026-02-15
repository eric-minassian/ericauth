use askama::Template;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    Extension, Form,
};
use serde::Deserialize;

use crate::{
    authz::{evaluate_policy, PolicyDecisionRequest},
    db::{tenant::TenantTable, user::UserTable},
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
pub struct ClientsQuery {
    tenant_id: Option<String>,
    client_id: Option<String>,
}

#[derive(Deserialize)]
pub struct UsersQuery {
    user_id: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
pub struct PoliciesQuery {
    principal: Option<String>,
    action: Option<String>,
    resource: Option<String>,
    scopes: Option<String>,
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
struct AdminClientsTemplate {
    tenants: Vec<TenantTable>,
    tenant_id: Option<String>,
    client_id: Option<String>,
    lookup_result: Option<ClientLookupView>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin_users.html")]
struct AdminUsersTemplate {
    user_id: Option<String>,
    email: Option<String>,
    lookup_result: Option<UserLookupView>,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin_policies.html")]
struct AdminPoliciesTemplate {
    principal: Option<String>,
    action: Option<String>,
    resource: Option<String>,
    scopes: Option<String>,
    decision: Option<PolicyDecisionView>,
    error: Option<String>,
}

struct ClientLookupView {
    client_id: String,
    client_name: String,
    redirect_uris: String,
    allowed_scopes: String,
    token_endpoint_auth_method: String,
}

struct UserLookupView {
    id: String,
    email: String,
    created_at: String,
    updated_at: String,
    scopes: String,
    has_password_login: bool,
    has_mfa: bool,
}

struct PolicyDecisionView {
    allowed: bool,
    required_scope: Option<String>,
    reason: String,
}

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
    Query(query): Query<ClientsQuery>,
) -> Result<impl IntoResponse, AuthError> {
    require_admin_access(&state, &user).await?;

    let tenants = state.db.list_tenants().await?;
    let tenant_id = trim_optional(query.tenant_id);
    let client_id = trim_optional(query.client_id);

    let (lookup_result, error) = if let Some(ref requested_client_id) = client_id {
        let client = state
            .db
            .get_client_for_tenant(tenant_id.as_deref(), requested_client_id)
            .await?;

        match client {
            Some(client) => (
                Some(ClientLookupView {
                    client_id: client.client_id,
                    client_name: client.client_name,
                    redirect_uris: client.redirect_uris.join(", "),
                    allowed_scopes: client.allowed_scopes.join(" "),
                    token_endpoint_auth_method: client.token_endpoint_auth_method,
                }),
                None,
            ),
            None => (
                None,
                Some("Client not found for this tenant scope.".to_string()),
            ),
        }
    } else {
        (None, None)
    };

    render(&AdminClientsTemplate {
        tenants,
        tenant_id,
        client_id,
        lookup_result,
        error,
    })
}

pub async fn users_page_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<UsersQuery>,
) -> Result<impl IntoResponse, AuthError> {
    require_admin_access(&state, &user).await?;

    let user_id = trim_optional(query.user_id);
    let email = trim_optional(query.email);
    let (lookup_result, error) = lookup_user(&state, user_id.as_deref(), email.as_deref()).await?;

    render(&AdminUsersTemplate {
        user_id,
        email,
        lookup_result,
        error,
    })
}

pub async fn policies_page_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<PoliciesQuery>,
) -> Result<impl IntoResponse, AuthError> {
    require_admin_access(&state, &user).await?;

    let principal = trim_optional(query.principal);
    let action = trim_optional(query.action);
    let resource = trim_optional(query.resource);
    let scopes = trim_optional(query.scopes);

    let (decision, error) = match (&action, &resource) {
        (Some(action), Some(resource)) => {
            let principal_value = principal
                .clone()
                .unwrap_or_else(|| "admin-console-principal".to_string());
            let scope_values = scopes
                .clone()
                .unwrap_or_default()
                .split_whitespace()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            let scope_refs = scope_values.iter().map(String::as_str).collect::<Vec<_>>();

            let decision = evaluate_policy(&PolicyDecisionRequest {
                principal: &principal_value,
                action,
                resource,
                scopes: &scope_refs,
            });

            (
                Some(PolicyDecisionView {
                    allowed: decision.allowed,
                    required_scope: decision.required_scope.map(ToString::to_string),
                    reason: decision.reason.to_string(),
                }),
                None,
            )
        }
        (Some(_), None) | (None, Some(_)) => (
            None,
            Some("Provide both action and resource to run simulation.".to_string()),
        ),
        (None, None) => (None, None),
    };

    render(&AdminPoliciesTemplate {
        principal,
        action,
        resource,
        scopes,
        decision,
        error,
    })
}

async fn lookup_user(
    state: &AppState,
    user_id: Option<&str>,
    email: Option<&str>,
) -> Result<(Option<UserLookupView>, Option<String>), AuthError> {
    let user = if let Some(id) = user_id {
        state.db.get_user_by_id(id).await?
    } else if let Some(value) = email {
        state.db.get_user_by_email(value.to_string()).await?
    } else {
        return Ok((None, None));
    };

    let Some(user) = user else {
        return Ok((None, Some("User not found.".to_string())));
    };

    Ok((Some(to_user_lookup_view(user)), None))
}

fn to_user_lookup_view(user: UserTable) -> UserLookupView {
    UserLookupView {
        id: user.id.to_string(),
        email: user.email,
        created_at: user.created_at,
        updated_at: user.updated_at,
        scopes: user.scopes.join(" "),
        has_password_login: user.password_hash.is_some(),
        has_mfa: user.mfa_totp_secret.is_some(),
    }
}

fn trim_optional(value: Option<String>) -> Option<String> {
    value
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
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
