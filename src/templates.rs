use askama::Template;
use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};

use crate::error::AuthError;

pub struct HtmlResponse(pub String);

impl IntoResponse for HtmlResponse {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            self.0,
        )
            .into_response()
    }
}

pub fn render<T: Template>(tmpl: &T) -> Result<HtmlResponse, AuthError> {
    let html = tmpl
        .render()
        .map_err(|e| AuthError::Internal(format!("template render error: {e}")))?;
    Ok(HtmlResponse(html))
}

#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
    pub title: String,
    pub message: String,
}
