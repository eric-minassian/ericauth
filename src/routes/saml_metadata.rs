use axum::{
    extract::State,
    http::{header, HeaderValue},
    response::IntoResponse,
};

use crate::{db, error::AuthError, state::AppState};

pub async fn sp_handler(State(state): State<AppState>) -> Result<impl IntoResponse, AuthError> {
    let config = db::get_saml_config(state.db.as_ref(), &state.issuer_url)?;
    let metadata = config
        .sp_metadata_xml()
        .map_err(|e| AuthError::Internal(e.to_string()))?;

    Ok((
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/samlmetadata+xml"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=3600"),
            ),
        ],
        metadata,
    ))
}

pub async fn idp_handler(State(state): State<AppState>) -> Result<impl IntoResponse, AuthError> {
    let config = db::get_saml_config(state.db.as_ref(), &state.issuer_url)?;
    let metadata = config
        .idp_metadata_xml()
        .map_err(|e| AuthError::Internal(e.to_string()))?;

    Ok((
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/samlmetadata+xml"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=3600"),
            ),
        ],
        metadata,
    ))
}
