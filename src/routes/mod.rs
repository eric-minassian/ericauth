mod account;
mod admin_pages;
mod admin_tenants;
mod api_keys;
mod audit_events;
pub(crate) mod authorize;
mod compliance;
mod consent;
pub(crate) mod events_webhook;
mod favicon;
mod forgot_password;
mod health;
mod jwks;
mod login;
mod login_page;
mod logout;
mod mfa;
mod openid_config;
mod passkey;
mod passkeys_page;
mod policy_simulate;
mod recover;
mod recover_page;
mod reset_password;
mod saml_metadata;
mod scim_auth;
mod scim_groups;
mod scim_users;
mod signup;
mod signup_page;
mod token;
mod token_revoke;
mod userinfo;
mod verify_email;

use std::env;

use axum::{
    http::{HeaderValue, Method},
    middleware,
    routing::{get, post, put},
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::{
    middleware::{
        admin_auth::admin_auth_middleware, csrf::csrf_middleware,
        rate_limit::rate_limit_middleware, security_headers::security_headers_middleware,
    },
    state::AppState,
};

pub fn router(state: AppState) -> Router {
    let cors_allowed_origins = env::var("CORS_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "https://auth.ericminassian.com".to_string())
        .split(',')
        .filter_map(|origin| {
            let trimmed = origin.trim();
            if trimmed.is_empty() {
                return None;
            }

            match trimmed.parse::<HeaderValue>() {
                Ok(value) => Some(value),
                Err(e) => {
                    tracing::warn!(origin = trimmed, error = %e, "Ignoring invalid CORS origin");
                    None
                }
            }
        })
        .collect::<Vec<_>>();

    let cors_allowed_origins = if cors_allowed_origins.is_empty() {
        vec![HeaderValue::from_static("https://auth.ericminassian.com")]
    } else {
        cors_allowed_origins
    };

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(cors_allowed_origins))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .allow_credentials(true);

    // API routes that need CORS (token endpoints, well-known endpoints, userinfo)
    let cors_routes = Router::new()
        .route("/token", post(token::handler))
        .route("/token/revoke", post(token_revoke::handler))
        .route("/.well-known/jwks.json", get(jwks::handler))
        .route(
            "/.well-known/openid-configuration",
            get(openid_config::handler),
        )
        .route(
            "/.well-known/saml/sp-metadata",
            get(saml_metadata::sp_handler),
        )
        .route(
            "/.well-known/saml/idp-metadata",
            get(saml_metadata::idp_handler),
        )
        .route(
            "/scim/v2/Groups",
            get(scim_groups::list_handler).post(scim_groups::create_handler),
        )
        .route("/scim/v2/Users", post(scim_users::create_handler))
        .route(
            "/scim/v2/Users/{id}",
            put(scim_users::update_handler).patch(scim_users::patch_handler),
        )
        .route("/userinfo", get(userinfo::handler).post(userinfo::handler))
        .layer(cors);

    // Rate-limited routes (auth entry points that accept untrusted input)
    let rate_limited_routes = Router::new()
        .route("/signup", get(signup_page::handler).post(signup::handler))
        .route("/login", get(login_page::handler).post(login::handler))
        .route(
            "/forgot-password",
            get(forgot_password::get_handler).post(forgot_password::post_handler),
        )
        .route(
            "/reset-password",
            get(reset_password::get_handler).post(reset_password::post_handler),
        )
        .route(
            "/recover",
            get(recover_page::handler).post(recover::handler),
        )
        .route(
            "/mfa/challenge",
            get(mfa::challenge_get_handler).post(mfa::challenge_post_handler),
        )
        .route("/verify-email", get(verify_email::handler))
        .route("/passkeys/auth/begin", post(passkey::auth_begin))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ));

    let admin_routes = Router::new()
        .route(
            "/audit/events",
            get(audit_events::get_handler).post(audit_events::post_handler),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_auth_middleware,
        ));

    // All other routes (no rate limit, no CORS)
    let other_routes = Router::new()
        .route(
            "/admin/tenants",
            get(admin_tenants::list_tenants_handler).post(admin_tenants::create_tenant_handler),
        )
        .route(
            "/admin/tenants/{tenant_id}",
            get(admin_tenants::get_tenant_handler).delete(admin_tenants::delete_tenant_handler),
        )
        .route(
            "/admin/tenants/{tenant_id}/projects",
            post(admin_tenants::create_project_handler),
        )
        .route(
            "/admin/tenants/{tenant_id}/clients/{client_id}",
            get(admin_tenants::get_tenant_client_handler),
        )
        .route(
            "/admin/console/tenants",
            get(admin_pages::tenants_page_handler).post(admin_pages::create_tenant_handler),
        )
        .route(
            "/admin/console/clients",
            get(admin_pages::clients_page_handler),
        )
        .route("/admin/console/users", get(admin_pages::users_page_handler))
        .route(
            "/admin/console/policies",
            get(admin_pages::policies_page_handler),
        )
        .route("/favicon.ico", get(favicon::handler))
        .route("/health", get(health::handler))
        .route("/logout", post(logout::handler))
        .route(
            "/compliance/account/export",
            get(compliance::account_export_handler),
        )
        .route(
            "/compliance/account/delete",
            post(compliance::account_delete_handler),
        )
        .route(
            "/compliance/audit/evidence",
            get(compliance::audit_evidence_handler),
        )
        .route("/account/compliance", get(compliance::page_handler))
        .route(
            "/account/compliance/export",
            post(compliance::export_form_handler),
        )
        .route(
            "/account/compliance/delete",
            post(compliance::delete_form_handler),
        )
        .route(
            "/account/compliance/audit-evidence",
            post(compliance::audit_evidence_form_handler),
        )
        .route(
            "/consent",
            get(consent::get_handler).post(consent::post_handler),
        )
        .route("/passkeys/manage", get(passkeys_page::handler))
        .route("/account", get(account::handler))
        .route("/account/sessions", get(account::sessions_page_handler))
        .route(
            "/account/sessions/revoke",
            post(account::revoke_session_handler),
        )
        .route(
            "/account/sessions/revoke-others",
            post(account::revoke_other_sessions_handler),
        )
        .route(
            "/account/password",
            get(account::password_page_handler).post(account::change_password_handler),
        )
        .route(
            "/account/recovery-codes/regenerate",
            post(account::regenerate_recovery_codes_handler),
        )
        .route(
            "/mfa/setup",
            get(mfa::setup_get_handler).post(mfa::setup_post_handler),
        )
        .route(
            "/account/api-keys",
            get(api_keys::list_handler).post(api_keys::create_handler),
        )
        .route("/account/api-keys/revoke", post(api_keys::revoke_handler))
        .route("/account/api-keys/manage", get(api_keys::page_handler))
        .route(
            "/account/api-keys/manage/create",
            post(api_keys::create_form_handler),
        )
        .route(
            "/account/api-keys/manage/revoke",
            post(api_keys::revoke_form_handler),
        )
        .route("/passkeys/register/begin", post(passkey::register_begin))
        .route(
            "/passkeys/register/complete",
            post(passkey::register_complete),
        )
        .route("/passkeys/auth/complete", post(passkey::auth_complete))
        .route("/passkeys/delete", post(passkey::delete))
        .route("/authorize", get(authorize::handler))
        .route("/policy/simulate", post(policy_simulate::handler));

    Router::new()
        .merge(cors_routes)
        .merge(rate_limited_routes)
        .merge(admin_routes)
        .merge(other_routes)
        .layer(middleware::from_fn(csrf_middleware))
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(state)
}
