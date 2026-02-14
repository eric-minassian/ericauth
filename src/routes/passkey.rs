use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    Form, Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::{
    error::AuthError,
    middleware::auth::AuthenticatedUser,
    session::{create_session, generate_session_token, session_cookie},
    state::AppState,
    validation::normalize_email,
};

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

    let now = chrono::Utc::now().to_rfc3339();
    state
        .db
        .insert_credential(
            &credential_id,
            &user.user_id.to_string(),
            &passkey_json,
            &now,
        )
        .await?;

    Ok(StatusCode::CREATED)
}

// --- Authentication ---

#[derive(Deserialize)]
pub struct AuthBeginPayload {
    email: Option<String>,
}

#[derive(Serialize)]
pub struct AuthBeginResponse {
    challenge_id: String,
    options: RequestChallengeResponse,
}

/// Stored alongside the challenge so we know which user is authenticating.
#[derive(Serialize, Deserialize)]
enum AuthChallengeState {
    Identified {
        user_id: String,
        passkey_authentication: PasskeyAuthentication,
    },
    Discoverable {
        discoverable_authentication: DiscoverableAuthentication,
    },
}

pub async fn auth_begin(
    State(state): State<AppState>,
    Json(body): Json<AuthBeginPayload>,
) -> Result<impl IntoResponse, AuthError> {
    let challenge_state = if let Some(email) = body.email.filter(|e| !e.is_empty()) {
        // Email provided: authenticate against this user's passkeys.
        let user = state
            .db
            .get_user_by_email(normalize_email(&email))
            .await?
            .ok_or_else(|| AuthError::Unauthorized("invalid email or passkey".into()))?;

        let cred_records = state
            .db
            .get_credentials_by_user_id(&user.id.to_string())
            .await?;

        if cred_records.is_empty() {
            return Err(AuthError::Unauthorized("no passkeys registered".into()));
        }

        let passkeys: Vec<Passkey> = cred_records
            .iter()
            .filter_map(|c| serde_json::from_str(&c.passkey_json).ok())
            .collect();

        if passkeys.is_empty() {
            return Err(AuthError::Internal("failed to deserialize passkeys".into()));
        }

        let (rcr, passkey_authentication) = state
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| {
                AuthError::Internal(format!("WebAuthn authentication start failed: {e}"))
            })?;

        (
            rcr,
            AuthChallengeState::Identified {
                user_id: user.id.to_string(),
                passkey_authentication,
            },
        )
    } else {
        // No email: start discoverable authentication flow.
        let (rcr, discoverable_authentication) = state
            .webauthn
            .start_discoverable_authentication()
            .map_err(|e| {
                AuthError::Internal(format!("WebAuthn discoverable authentication failed: {e}"))
            })?;

        (
            rcr,
            AuthChallengeState::Discoverable {
                discoverable_authentication,
            },
        )
    };

    // Store the authentication state as a challenge (5 min TTL)
    let challenge_id = Uuid::new_v4().to_string();
    let (rcr, challenge_state) = challenge_state;
    let challenge_data = serde_json::to_string(&challenge_state)
        .map_err(|e| AuthError::Internal(format!("Failed to serialize auth state: {e}")))?;

    state
        .db
        .insert_challenge(&challenge_id, &challenge_data, 300)
        .await?;

    Ok(Json(AuthBeginResponse {
        challenge_id,
        options: rcr,
    }))
}

#[derive(Deserialize)]
pub struct AuthCompletePayload {
    challenge_id: String,
    credential: PublicKeyCredential,
}

pub async fn auth_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AuthCompletePayload>,
) -> Result<impl IntoResponse, AuthError> {
    // Retrieve and delete the challenge (single-use)
    let challenge_data = state
        .db
        .get_and_delete_challenge(&body.challenge_id)
        .await?;

    let challenge_state: AuthChallengeState = serde_json::from_str(&challenge_data)
        .map_err(|e| AuthError::Internal(format!("Failed to deserialize auth state: {e}")))?;

    let (user_id, auth_result) = match challenge_state {
        AuthChallengeState::Identified {
            user_id,
            passkey_authentication,
        } => {
            let auth_result = state
                .webauthn
                .finish_passkey_authentication(&body.credential, &passkey_authentication)
                .map_err(|e| {
                    AuthError::Unauthorized(format!("WebAuthn authentication failed: {e}"))
                })?;
            (user_id, auth_result)
        }
        AuthChallengeState::Discoverable {
            discoverable_authentication,
        } => {
            let (user_uuid, cred_id) = state
                .webauthn
                .identify_discoverable_authentication(&body.credential)
                .map_err(|e| {
                    AuthError::Unauthorized(format!("WebAuthn authentication failed: {e}"))
                })?;
            let credential_id = URL_SAFE_NO_PAD.encode(cred_id);
            let credential = state
                .db
                .get_credential_by_id(&credential_id)
                .await?
                .ok_or_else(|| AuthError::Unauthorized("unknown credential".into()))?;
            let passkey: Passkey = serde_json::from_str(&credential.passkey_json)
                .map_err(|e| AuthError::Internal(format!("Failed to deserialize passkey: {e}")))?;

            let auth_result = state
                .webauthn
                .finish_discoverable_authentication(
                    &body.credential,
                    discoverable_authentication,
                    &[DiscoverableKey::from(passkey)],
                )
                .map_err(|e| {
                    AuthError::Unauthorized(format!("WebAuthn authentication failed: {e}"))
                })?;
            (user_uuid.to_string(), auth_result)
        }
    };

    // Update authenticator counter/signature metadata.
    update_passkey_authentication_state(&state, &user_id, &auth_result).await?;

    // Extract client IP
    let client_ip = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);

    // Create session
    let user_uuid = Uuid::parse_str(&user_id)
        .map_err(|e| AuthError::Internal(format!("Invalid user ID: {e}")))?;

    let session_token = generate_session_token()?;
    let session = create_session(
        state.db.as_ref(),
        session_token.clone(),
        user_uuid,
        client_ip,
        user_agent,
    )
    .await?;

    // Build response with session cookie
    let (cookie_name, cookie_value) = session_cookie(&session_token, session.expires_at);
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        cookie_name,
        cookie_value
            .parse()
            .map_err(|e| AuthError::Internal(format!("Failed to build cookie header: {e}")))?,
    );

    Ok((StatusCode::NO_CONTENT, response_headers))
}

// --- Deletion ---

#[derive(Deserialize)]
pub struct DeletePasskeyPayload {
    credential_id: String,
    #[serde(rename = "csrf_token")]
    _csrf_token: Option<String>,
}

pub async fn delete(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Form(body): Form<DeletePasskeyPayload>,
) -> Result<impl IntoResponse, AuthError> {
    // Verify the credential belongs to this user
    let credentials = state
        .db
        .get_credentials_by_user_id(&user.user_id.to_string())
        .await?;

    let owns_credential = credentials
        .iter()
        .any(|c| c.credential_id == body.credential_id);

    if !owns_credential {
        return Err(AuthError::NotFound("credential not found".into()));
    }

    state.db.delete_credential(&body.credential_id).await?;

    Ok(Redirect::to("/passkeys/manage"))
}

async fn update_passkey_authentication_state(
    state: &AppState,
    user_id: &str,
    auth_result: &AuthenticationResult,
) -> Result<(), AuthError> {
    if !auth_result.needs_update() {
        return Ok(());
    }

    let cred_records = state.db.get_credentials_by_user_id(user_id).await?;

    for cred in &cred_records {
        if let Ok(mut passkey) = serde_json::from_str::<Passkey>(&cred.passkey_json) {
            if passkey.cred_id() == auth_result.cred_id() {
                passkey.update_credential(auth_result);
                let updated_json = serde_json::to_string(&passkey).map_err(|e| {
                    AuthError::Internal(format!("Failed to serialize passkey update: {e}"))
                })?;
                state
                    .db
                    .update_credential(&cred.credential_id, &updated_json)
                    .await?;
                return Ok(());
            }
        }
    }

    Err(AuthError::Internal(
        "authenticated passkey not found for user".into(),
    ))
}
