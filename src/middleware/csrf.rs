use axum::{
    body::Body,
    extract::Request,
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http_body_util::BodyExt;

/// Paths where CSRF protection is applied.
const CSRF_PROTECTED_PATHS: &[&str] = &[
    "/login",
    "/signup",
    "/consent",
    "/passkeys/manage",
    "/passkeys/delete",
    "/recover",
    "/forgot-password",
    "/reset-password",
    "/mfa/setup",
    "/mfa/challenge",
    "/account",
    "/account/sessions",
    "/account/sessions/revoke",
    "/account/sessions/revoke-others",
    "/account/password",
    "/account/recovery-codes/regenerate",
    "/admin/console/tenants",
];

/// CSRF token stored in request extensions so handlers can pass it to templates.
#[derive(Clone)]
pub struct CsrfToken(pub String);

/// Double-submit cookie CSRF middleware.
///
/// - GET requests to protected paths: generates a token, sets `__csrf` cookie,
///   injects `CsrfToken` into extensions.
/// - POST requests to protected paths: compares `__csrf` cookie value against
///   `csrf_token` form field.
/// - All other requests pass through unchanged.
pub async fn csrf_middleware(request: Request, next: Next) -> Result<Response, Response> {
    let path = request.uri().path().to_string();
    let is_protected = CSRF_PROTECTED_PATHS.iter().any(|p| *p == path);

    if !is_protected {
        return Ok(next.run(request).await);
    }

    match *request.method() {
        Method::GET => handle_get(request, next).await,
        Method::POST => {
            // Only enforce CSRF for form submissions, not JSON API calls
            let is_form = request
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"));
            if is_form {
                handle_post(request, next).await
            } else {
                Ok(next.run(request).await)
            }
        }
        _ => Ok(next.run(request).await),
    }
}

async fn handle_get(mut request: Request, next: Next) -> Result<Response, Response> {
    let token = generate_csrf_token().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to generate CSRF token",
        )
            .into_response()
    })?;

    request.extensions_mut().insert(CsrfToken(token.clone()));

    let mut response = next.run(request).await;

    let cookie = format!("__csrf={token}; Path=/; SameSite=Strict; Secure; HttpOnly");
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        cookie.parse().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build CSRF cookie",
            )
                .into_response()
        })?,
    );

    Ok(response)
}

async fn handle_post(request: Request, next: Next) -> Result<Response, Response> {
    let cookie_token = extract_csrf_cookie(&request);

    let cookie_token = cookie_token
        .ok_or_else(|| (StatusCode::FORBIDDEN, "missing CSRF cookie").into_response())?;

    // Read the body to extract csrf_token field
    let (parts, body) = request.into_parts();
    let bytes = body
        .collect()
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "failed to read request body").into_response())?
        .to_bytes();

    let form_token = extract_csrf_from_form(&bytes);

    let form_token = form_token
        .ok_or_else(|| (StatusCode::FORBIDDEN, "missing CSRF token in form").into_response())?;

    if cookie_token != form_token {
        return Err((StatusCode::FORBIDDEN, "CSRF token mismatch").into_response());
    }

    // Reconstruct the request with the body
    let request = Request::from_parts(parts, Body::from(bytes));
    Ok(next.run(request).await)
}

fn extract_csrf_cookie(request: &Request) -> Option<String> {
    let cookie_header = request
        .headers()
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?;

    cookie_header
        .split(';')
        .map(|s| s.trim())
        .find_map(|s| s.strip_prefix("__csrf="))
        .map(|s| s.to_string())
}

fn extract_csrf_from_form(body: &[u8]) -> Option<String> {
    let body_str = std::str::from_utf8(body).ok()?;
    form_urlencoded::parse(body_str.as_bytes())
        .find(|(key, _)| key == "csrf_token")
        .map(|(_, value)| value.into_owned())
}

fn generate_csrf_token() -> Result<String, &'static str> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| "failed to generate random bytes")?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_csrf_token() {
        let token = generate_csrf_token().unwrap();
        assert!(!token.is_empty());
        // 32 bytes base64url-encoded should be 43 chars
        assert_eq!(token.len(), 43);
    }

    #[test]
    fn test_generate_csrf_token_uniqueness() {
        let t1 = generate_csrf_token().unwrap();
        let t2 = generate_csrf_token().unwrap();
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_extract_csrf_from_form_body() {
        let body = b"email=test%40example.com&password=secret&csrf_token=abc123";
        let token = extract_csrf_from_form(body);
        assert_eq!(token, Some("abc123".to_string()));
    }

    #[test]
    fn test_extract_csrf_from_form_body_missing() {
        let body = b"email=test%40example.com&password=secret";
        let token = extract_csrf_from_form(body);
        assert_eq!(token, None);
    }
}
