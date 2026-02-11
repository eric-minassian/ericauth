use askama::Template;
use axum::{extract::Query, response::IntoResponse, Extension};
use serde::Deserialize;

use crate::{error::AuthError, middleware::csrf::CsrfToken, templates::render};

#[derive(Deserialize)]
pub struct SignupPageQuery {
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "signup.html")]
struct SignupTemplate {
    csrf_token: String,
    error: Option<String>,
}

pub async fn handler(
    Extension(csrf): Extension<CsrfToken>,
    Query(params): Query<SignupPageQuery>,
) -> Result<impl IntoResponse, AuthError> {
    render(&SignupTemplate {
        csrf_token: csrf.0,
        error: params.error,
    })
}
