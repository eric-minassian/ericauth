use askama::Template;
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    Extension, Form,
};
use serde::Deserialize;

use crate::{
    error::AuthError, middleware::csrf::CsrfToken, state::AppState, templates::render,
    validation::normalize_email,
};

use super::reset_password::issue_reset_token;

#[derive(Deserialize)]
pub struct ForgotPasswordQuery {
    notice: Option<String>,
    error: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
pub struct ForgotPasswordPayload {
    email: String,
    #[serde(rename = "csrf_token")]
    _csrf_token: Option<String>,
}

#[derive(Template)]
#[template(path = "forgot_password.html")]
struct ForgotPasswordTemplate {
    csrf_token: String,
    notice: Option<String>,
    error: Option<String>,
    email: Option<String>,
}

pub async fn get_handler(
    Extension(csrf): Extension<CsrfToken>,
    Query(query): Query<ForgotPasswordQuery>,
) -> Result<impl IntoResponse, AuthError> {
    render(&ForgotPasswordTemplate {
        csrf_token: csrf.0,
        notice: query.notice,
        error: query.error,
        email: query.email,
    })
}

pub async fn post_handler(
    State(state): State<AppState>,
    Form(payload): Form<ForgotPasswordPayload>,
) -> impl IntoResponse {
    let normalized = normalize_email(&payload.email);
    let _ = issue_reset_token(&state, &normalized).await;

    Redirect::to("/forgot-password?notice=If%20that%20account%20exists%2C%20we%20sent%20reset%20instructions")
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
    };
    use lambda_http::tower::ServiceExt;

    use crate::{routes, state::AppState, user::create_user};

    fn test_app_state() -> AppState {
        AppState {
            db: crate::db::memory(),
            jwt_keys: None,
            webauthn: std::sync::Arc::new(crate::webauthn_config::build_webauthn().unwrap()),
            issuer_url: "https://auth.test.example.com".to_string(),
        }
    }

    fn extract_csrf_cookie_value(response: &axum::response::Response) -> String {
        let raw = response
            .headers()
            .get(header::SET_COOKIE)
            .expect("missing set-cookie")
            .to_str()
            .expect("invalid set-cookie");

        raw.split(';')
            .find_map(|part| part.trim().strip_prefix("__csrf="))
            .expect("missing __csrf cookie")
            .to_string()
    }

    #[tokio::test]
    async fn test_forgot_password_non_enumerating_response() {
        let state = test_app_state();
        create_user(
            state.db.as_ref(),
            "known.user@example.com".to_string(),
            "Password123!".to_string(),
        )
        .await
        .unwrap();

        let app = routes::router(state);

        let get_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/forgot-password")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);
        let csrf = extract_csrf_cookie_value(&get_response);

        let existing = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forgot-password")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::COOKIE, format!("__csrf={csrf}"))
                    .body(Body::from(format!(
                        "email=known.user%40example.com&csrf_token={}",
                        urlencoding::encode(&csrf)
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        let unknown = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forgot-password")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::COOKIE, format!("__csrf={csrf}"))
                    .body(Body::from(format!(
                        "email=missing.user%40example.com&csrf_token={}",
                        urlencoding::encode(&csrf)
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(existing.status(), StatusCode::SEE_OTHER);
        assert_eq!(unknown.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            existing.headers().get(header::LOCATION),
            unknown.headers().get(header::LOCATION)
        );
    }

    #[tokio::test]
    async fn test_csrf_enforced_for_forgot_password_post() {
        let app = routes::router(test_app_state());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forgot-password")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("email=user%40example.com"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_csrf_enforced_for_reset_password_post() {
        let app = routes::router(test_app_state());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/reset-password")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "token=fake-token&new_password=Password123%21&confirm_password=Password123%21",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
