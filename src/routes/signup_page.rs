use askama::Template;
use axum::{extract::Query, response::IntoResponse, Extension};
use serde::Deserialize;

use crate::{error::AuthError, middleware::csrf::CsrfToken, templates::render};

#[derive(Deserialize)]
pub struct SignupPageQuery {
    error: Option<String>,
    email: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    response_type: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

#[derive(Template)]
#[template(path = "signup.html")]
struct SignupTemplate {
    csrf_token: String,
    error: Option<String>,
    email: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    response_type: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    oauth_query: String,
}

pub async fn handler(
    Extension(csrf): Extension<CsrfToken>,
    Query(params): Query<SignupPageQuery>,
) -> Result<impl IntoResponse, AuthError> {
    let oauth_query = build_oauth_link_query(&[
        ("client_id", &params.client_id),
        ("redirect_uri", &params.redirect_uri),
        ("response_type", &params.response_type),
        ("scope", &params.scope),
        ("state", &params.state),
        ("code_challenge", &params.code_challenge),
        ("code_challenge_method", &params.code_challenge_method),
        ("nonce", &params.nonce),
    ]);

    render(&SignupTemplate {
        csrf_token: csrf.0,
        error: params.error,
        email: params.email,
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        response_type: params.response_type,
        scope: params.scope,
        state: params.state,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
        nonce: params.nonce,
        oauth_query,
    })
}

fn build_oauth_link_query(params: &[(&str, &Option<String>)]) -> String {
    let mut qs = form_urlencoded::Serializer::new(String::new());
    let mut has_params = false;
    for &(key, value) in params {
        if let Some(v) = value {
            qs.append_pair(key, v);
            has_params = true;
        }
    }
    if has_params {
        qs.finish()
    } else {
        String::new()
    }
}
