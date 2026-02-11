use askama::Template;
use axum::{extract::Query, response::IntoResponse};
use serde::Deserialize;

use crate::{error::AuthError, templates::render};

#[derive(Deserialize)]
pub struct LoginPageQuery {
    error: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
    scope: Option<String>,
    response_type: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
    scope: Option<String>,
    response_type: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

pub async fn handler(Query(params): Query<LoginPageQuery>) -> Result<impl IntoResponse, AuthError> {
    render(&LoginTemplate {
        error: params.error,
        redirect_uri: params.redirect_uri,
        state: params.state,
        client_id: params.client_id,
        scope: params.scope,
        response_type: params.response_type,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
        nonce: params.nonce,
    })
}
