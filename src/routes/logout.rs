use axum::{extract::State, http::StatusCode, response::IntoResponse};

use crate::{error::AuthError, middleware::auth::AuthenticatedUser, state::AppState};

pub async fn handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AuthError> {
    state.db.delete_session(&user.session_id).await?;

    // Clear the session cookie by setting it to empty with an expired date
    let clear_cookie =
        "session=; HttpOnly; Path=/; Secure; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::SET_COOKIE,
        clear_cookie
            .parse()
            .map_err(|e| AuthError::Internal(format!("Failed to build cookie header: {e}")))?,
    );

    Ok((StatusCode::NO_CONTENT, headers))
}
