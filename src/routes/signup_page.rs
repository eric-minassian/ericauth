use askama::Template;
use axum::{extract::Query, response::IntoResponse};
use serde::Deserialize;

use crate::{error::AuthError, templates::render};

#[derive(Deserialize)]
pub struct SignupPageQuery {
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "signup.html")]
struct SignupTemplate {
    error: Option<String>,
}

pub async fn handler(
    Query(params): Query<SignupPageQuery>,
) -> Result<impl IntoResponse, AuthError> {
    render(&SignupTemplate {
        error: params.error,
    })
}
