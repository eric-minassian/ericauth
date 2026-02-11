use axum::{extract::State, http::StatusCode, response::IntoResponse};

use crate::{
    error::AuthError, middleware::auth::AuthenticatedUser, session::session_cookie, state::AppState,
};

pub async fn handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, AuthError> {
    state.db.delete_session(&user.session_id).await?;

    // Clear the session cookie by setting it to empty with an expired date
    let clear_cookie = session_cookie("", chrono::DateTime::UNIX_EPOCH);

    Ok((StatusCode::NO_CONTENT, [clear_cookie]))
}
