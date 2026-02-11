use askama::Template;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    Extension,
};
use serde::Deserialize;

use crate::{
    error::AuthError, middleware::auth::AuthenticatedUser, middleware::csrf::CsrfToken,
    routes::authorize, state::AppState, templates::render,
};

#[derive(Deserialize)]
pub struct ConsentQuery {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    scope: Option<String>,
    response_type: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

#[derive(Template)]
#[template(path = "consent.html")]
struct ConsentTemplate {
    csrf_token: String,
    client_id: String,
    email: String,
    scopes: Vec<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    scope_raw: Option<String>,
    response_type: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

pub async fn get_handler(
    Extension(csrf): Extension<CsrfToken>,
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(params): Query<ConsentQuery>,
) -> Result<impl IntoResponse, AuthError> {
    let client_id = params
        .client_id
        .ok_or_else(|| AuthError::BadRequest("missing client_id".into()))?;

    let user_record = state
        .db
        .get_user_by_id(&user.user_id.to_string())
        .await?
        .ok_or_else(|| AuthError::Internal("user not found".into()))?;

    let scopes: Vec<String> = params
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .collect();

    render(&ConsentTemplate {
        csrf_token: csrf.0,
        client_id,
        email: user_record.email,
        scopes,
        redirect_uri: params.redirect_uri,
        state: params.state,
        scope_raw: params.scope,
        response_type: params.response_type,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
        nonce: params.nonce,
    })
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct ConsentForm {
    action: String,
    client_id: String,
    redirect_uri: Option<String>,
    state: Option<String>,
    scope: Option<String>,
    response_type: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

pub async fn post_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    axum::Form(form): axum::Form<ConsentForm>,
) -> Result<impl IntoResponse, AuthError> {
    let redirect_uri = form
        .redirect_uri
        .ok_or_else(|| AuthError::BadRequest("missing redirect_uri".into()))?;

    // Re-validate redirect_uri against registered client to prevent open redirect
    let client = state
        .db
        .get_client(&form.client_id)
        .await?
        .ok_or_else(|| AuthError::BadRequest("unknown client_id".into()))?;

    if !client.redirect_uris.contains(&redirect_uri) {
        return Err(AuthError::BadRequest("invalid redirect_uri".into()));
    }

    if form.action == "deny" {
        let mut url = redirect_uri;
        url.push_str(if url.contains('?') { "&" } else { "?" });
        url.push_str("error=access_denied");
        if let Some(s) = &form.state {
            url.push_str("&state=");
            url.push_str(s);
        }
        return Ok(Redirect::temporary(&url));
    }

    // Generate an authorization code
    let code_challenge = form
        .code_challenge
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("missing code_challenge".into()))?;

    let raw_code = authorize::create_authorization_code(
        &state,
        &user.user_id.to_string(),
        &form.client_id,
        &redirect_uri,
        form.scope.as_deref().unwrap_or(""),
        code_challenge,
        form.nonce.as_deref(),
    )
    .await?;

    let url = authorize::build_code_redirect(&redirect_uri, &raw_code, form.state.as_deref());
    Ok(Redirect::temporary(&url))
}
