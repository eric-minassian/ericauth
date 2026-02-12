use askama::Template;
use axum::{extract::Query, response::IntoResponse, Extension};
use serde::Deserialize;

use crate::{error::AuthError, middleware::csrf::CsrfToken, templates::render};

#[derive(Deserialize)]
pub struct RecoverPageQuery {
    error: Option<String>,
    email: Option<String>,
}

#[derive(Template)]
#[template(path = "recover.html")]
struct RecoverTemplate {
    csrf_token: String,
    error: Option<String>,
    email: Option<String>,
}

pub async fn handler(
    Extension(csrf): Extension<CsrfToken>,
    Query(params): Query<RecoverPageQuery>,
) -> Result<impl IntoResponse, AuthError> {
    render(&RecoverTemplate {
        csrf_token: csrf.0,
        error: params.error,
        email: params.email,
    })
}
