use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::{error::AuthError, middleware::auth::AuthenticatedUser, state::AppState};

// --- Registration ---

#[derive(Serialize)]
pub struct RegisterBeginResponse {
    challenge_id: String,
    options: CreationChallengeResponse,
}

pub async fn register_begin(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AuthError> {
    let user_id = user.user_id;

    // Load user to get email for display name
    let user_record = state
        .db
        .get_user_by_id(&user_id.to_string())
        .await?
        .ok_or_else(|| AuthError::NotFound("user not found".into()))?;

    // Load existing credentials to exclude from registration
    let cred_records = state
        .db
        .get_credentials_by_user_id(&user_id.to_string())
        .await?;

    let existing_passkeys: Vec<Passkey> = cred_records
        .iter()
        .filter_map(|c| serde_json::from_str(&c.passkey_json).ok())
        .collect();

    let exclude_creds: Option<Vec<CredentialID>> = if existing_passkeys.is_empty() {
        None
    } else {
        Some(
            existing_passkeys
                .iter()
                .map(|p| p.cred_id().clone())
                .collect(),
        )
    };

    let (ccr, passkey_registration) = state
        .webauthn
        .start_passkey_registration(
            user_id,
            &user_record.email,
            &user_record.email,
            exclude_creds,
        )
        .map_err(|e| AuthError::Internal(format!("WebAuthn registration start failed: {e}")))?;

    // Store the registration state as a challenge (5 min TTL)
    let challenge_id = Uuid::new_v4().to_string();
    let challenge_data = serde_json::to_string(&passkey_registration)
        .map_err(|e| AuthError::Internal(format!("Failed to serialize registration state: {e}")))?;

    state
        .db
        .insert_challenge(&challenge_id, &challenge_data, 300)
        .await?;

    Ok(Json(RegisterBeginResponse {
        challenge_id,
        options: ccr,
    }))
}

#[derive(Deserialize)]
pub struct RegisterCompletePayload {
    challenge_id: String,
    credential: RegisterPublicKeyCredential,
}

pub async fn register_complete(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<RegisterCompletePayload>,
) -> Result<impl IntoResponse, AuthError> {
    // Retrieve and delete the challenge (single-use)
    let challenge_data = state
        .db
        .get_and_delete_challenge(&body.challenge_id)
        .await?;

    let passkey_registration: PasskeyRegistration =
        serde_json::from_str(&challenge_data).map_err(|e| {
            AuthError::Internal(format!("Failed to deserialize registration state: {e}"))
        })?;

    // Complete registration
    let passkey = state
        .webauthn
        .finish_passkey_registration(&body.credential, &passkey_registration)
        .map_err(|e| AuthError::BadRequest(format!("WebAuthn registration failed: {e}")))?;

    // Store the credential
    let credential_id = URL_SAFE_NO_PAD.encode(passkey.cred_id());
    let passkey_json = serde_json::to_string(&passkey)
        .map_err(|e| AuthError::Internal(format!("Failed to serialize passkey: {e}")))?;

    state
        .db
        .insert_credential(&credential_id, &user.user_id.to_string(), &passkey_json)
        .await?;

    Ok(StatusCode::CREATED)
}
