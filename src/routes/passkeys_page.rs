use askama::Template;
use axum::{response::IntoResponse, Extension};

use crate::{
    error::AuthError, middleware::auth::AuthenticatedUser, middleware::csrf::CsrfToken,
    templates::render,
};

pub struct PasskeyEntry {
    pub credential_id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "passkeys.html")]
struct PasskeysTemplate {
    csrf_token: String,
    passkeys: Vec<PasskeyEntry>,
}

pub async fn handler(
    Extension(csrf): Extension<CsrfToken>,
    _user: AuthenticatedUser,
) -> Result<impl IntoResponse, AuthError> {
    // Credential loading will be wired once Phase 3 DB operations are available
    let passkeys: Vec<PasskeyEntry> = vec![];

    render(&PasskeysTemplate {
        csrf_token: csrf.0,
        passkeys,
    })
}
