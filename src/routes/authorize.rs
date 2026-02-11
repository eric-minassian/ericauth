use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use sha2::{digest::Update, Digest, Sha256};

use crate::{
    db::auth_code::AuthCodeTable,
    error::AuthError,
    middleware::auth::AuthenticatedUser,
    state::AppState,
    templates::{render, ErrorTemplate},
};

const AUTH_CODE_TTL_SECS: i64 = 600; // 10 minutes

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    response_type: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    prompt: Option<String>,
}

fn build_redirect_error(redirect_uri: &str, error: &str, state: Option<&str>) -> String {
    let mut url = redirect_uri.to_string();
    url.push(if url.contains('?') { '&' } else { '?' });
    url.push_str("error=");
    url.push_str(error);
    if let Some(s) = state {
        url.push_str("&state=");
        url.push_str(&urlencoding::encode(s));
    }
    url
}

fn build_redirect_success(redirect_uri: &str, code: &str, state: Option<&str>) -> String {
    let mut url = redirect_uri.to_string();
    url.push(if url.contains('?') { '&' } else { '?' });
    url.push_str("code=");
    url.push_str(code);
    if let Some(s) = state {
        url.push_str("&state=");
        url.push_str(&urlencoding::encode(s));
    }
    url
}

fn generate_auth_code() -> Result<String, AuthError> {
    let mut code_bytes = [0u8; 32];
    getrandom::fill(&mut code_bytes)
        .map_err(|e| AuthError::Internal(format!("Failed to generate auth code: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(code_bytes))
}

pub async fn handler(
    State(state): State<AppState>,
    user: Result<AuthenticatedUser, AuthError>,
    Query(params): Query<AuthorizeQuery>,
) -> Result<impl IntoResponse, AuthError> {
    // Step 1: Validate client_id - render error page if invalid (do NOT redirect)
    let client_id = params
        .client_id
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("missing client_id".into()))?;

    let client = state
        .db
        .get_client(client_id)
        .await?
        .ok_or_else(|| AuthError::BadRequest("unknown client_id".into()))?;

    // Step 2: Validate redirect_uri - render error page if invalid (do NOT redirect)
    let redirect_uri = params
        .redirect_uri
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("missing redirect_uri".into()))?;

    if !client.redirect_uris.contains(&redirect_uri.to_string()) {
        return render(&ErrorTemplate {
            title: "Invalid Request".to_string(),
            message: "Invalid redirect_uri".to_string(),
        })
        .map(|html| html.into_response());
    }

    let state_param = params.state.as_deref();

    // Step 3: All other errors redirect to redirect_uri with error params
    // Validate response_type
    let response_type = params.response_type.as_deref().unwrap_or("");
    if response_type != "code" {
        let url = build_redirect_error(redirect_uri, "unsupported_response_type", state_param);
        return Ok(Redirect::temporary(&url).into_response());
    }

    // Validate code_challenge
    let code_challenge = match params.code_challenge.as_deref() {
        Some(cc) if (43..=128).contains(&cc.len()) => cc,
        _ => {
            let url = build_redirect_error(redirect_uri, "invalid_request", state_param);
            return Ok(Redirect::temporary(&url).into_response());
        }
    };

    // Validate code_challenge_method
    let code_challenge_method = params.code_challenge_method.as_deref().unwrap_or("");
    if code_challenge_method != "S256" {
        let url = build_redirect_error(redirect_uri, "invalid_request", state_param);
        return Ok(Redirect::temporary(&url).into_response());
    }

    // Validate scopes
    let scope = params.scope.as_deref().unwrap_or("");
    let scopes: Vec<&str> = scope.split_whitespace().collect();

    if !scopes.contains(&"openid") {
        let url = build_redirect_error(redirect_uri, "invalid_scope", state_param);
        return Ok(Redirect::temporary(&url).into_response());
    }

    for s in &scopes {
        if !client.allowed_scopes.iter().any(|a| a == s) {
            let url = build_redirect_error(redirect_uri, "invalid_scope", state_param);
            return Ok(Redirect::temporary(&url).into_response());
        }
    }

    // Step 4: Session check
    let _user = match user {
        Ok(u) if params.prompt.as_deref() != Some("login") => u,
        _ => {
            // No session or prompt=login: redirect to login page with OAuth2 params
            let mut login_url = "/login?".to_string();
            login_url.push_str(&build_oauth_query_string(
                client_id,
                redirect_uri,
                scope,
                state_param,
                code_challenge,
                code_challenge_method,
                params.nonce.as_deref(),
            ));
            return Ok(Redirect::temporary(&login_url).into_response());
        }
    };

    // Session exists - redirect to consent page
    let mut consent_url = "/consent?".to_string();
    consent_url.push_str(&build_oauth_query_string(
        client_id,
        redirect_uri,
        scope,
        state_param,
        code_challenge,
        code_challenge_method,
        params.nonce.as_deref(),
    ));

    // For now, always show consent. In the future we could check if consent was previously granted.
    // Generate auth code - we do this after consent approval in the consent POST handler.
    // But if we want to skip consent in some cases, we'd generate it here.
    // For this implementation, always redirect to consent.
    Ok(Redirect::temporary(&consent_url).into_response())
}

pub fn build_oauth_query_string(
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    state: Option<&str>,
    code_challenge: &str,
    code_challenge_method: &str,
    nonce: Option<&str>,
) -> String {
    let mut qs = format!(
        "client_id={}&redirect_uri={}&scope={}&response_type=code&code_challenge={}&code_challenge_method={}",
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(scope),
        urlencoding::encode(code_challenge),
        urlencoding::encode(code_challenge_method),
    );
    if let Some(s) = state {
        qs.push_str("&state=");
        qs.push_str(&urlencoding::encode(s));
    }
    if let Some(n) = nonce {
        qs.push_str("&nonce=");
        qs.push_str(&urlencoding::encode(n));
    }
    qs
}

/// Generate and store an authorization code. Called from the consent POST handler.
pub async fn create_authorization_code(
    state: &AppState,
    user_id: &str,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    code_challenge: &str,
    nonce: Option<&str>,
) -> Result<String, AuthError> {
    let raw_code = generate_auth_code()?;
    let code_hash = hex::encode(Sha256::new().chain(raw_code.as_bytes()).finalize());

    let now = chrono::Utc::now().timestamp();

    let auth_code = AuthCodeTable {
        code: code_hash,
        client_id: client_id.to_string(),
        user_id: user_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        scope: scope.to_string(),
        code_challenge: code_challenge.to_string(),
        nonce: nonce.map(|n| n.to_string()),
        auth_time: now,
        expires_at: now + AUTH_CODE_TTL_SECS,
        used_at: None,
    };

    state.db.insert_auth_code(&auth_code).await?;

    Ok(raw_code)
}

/// Build a redirect URL with the authorization code. Called from the consent POST handler.
pub fn build_code_redirect(redirect_uri: &str, code: &str, state: Option<&str>) -> String {
    build_redirect_success(redirect_uri, code, state)
}
