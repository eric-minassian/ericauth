use askama::Template;
use axum::{extract::State, response::IntoResponse, Extension};

use crate::{
    error::AuthError, middleware::auth::AuthenticatedUser, middleware::csrf::CsrfToken,
    state::AppState, templates::render,
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
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AuthError> {
    let credentials = state
        .db
        .get_credentials_by_user_id(&user.user_id.to_string())
        .await?;

    let passkeys: Vec<PasskeyEntry> = credentials
        .into_iter()
        .map(|cred| {
            let name = if cred.credential_id.len() > 8 {
                format!("Passkey {}...", &cred.credential_id[..8])
            } else {
                format!("Passkey {}", &cred.credential_id)
            };
            PasskeyEntry {
                credential_id: cred.credential_id,
                name,
                created_at: "Unknown".to_string(),
            }
        })
        .collect();

    render(&PasskeysTemplate {
        csrf_token: csrf.0,
        passkeys,
    })
}
