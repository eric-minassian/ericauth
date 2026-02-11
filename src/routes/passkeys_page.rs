use askama::Template;
use axum::response::IntoResponse;

use crate::{error::AuthError, middleware::auth::AuthenticatedUser, templates::render};

pub struct PasskeyEntry {
    pub credential_id: String,
    pub name: String,
    pub created_at: String,
}

#[derive(Template)]
#[template(path = "passkeys.html")]
struct PasskeysTemplate {
    passkeys: Vec<PasskeyEntry>,
}

pub async fn handler(_user: AuthenticatedUser) -> Result<impl IntoResponse, AuthError> {
    // Credential loading will be wired once Phase 3 DB operations are available
    let passkeys: Vec<PasskeyEntry> = vec![];

    render(&PasskeysTemplate { passkeys })
}
