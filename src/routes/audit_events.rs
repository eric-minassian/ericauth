use std::collections::BTreeMap;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{
    audit::{append_event, list_events, AuditEventInput},
    error::AuthError,
    state::AppState,
};

#[derive(Deserialize)]
pub struct AuditEventPayload {
    event_type: String,
    outcome: String,
    actor: Option<String>,
    client_ip: Option<String>,
    user_agent: Option<String>,
    metadata: Option<BTreeMap<String, String>>,
}

pub async fn post_handler(
    State(state): State<AppState>,
    Json(body): Json<AuditEventPayload>,
) -> Result<impl IntoResponse, AuthError> {
    let event = append_event(
        state.db.as_ref(),
        AuditEventInput {
            event_type: body.event_type,
            outcome: body.outcome,
            actor: body.actor,
            client_ip: body.client_ip,
            user_agent: body.user_agent,
            metadata: body.metadata.unwrap_or_default(),
        },
    )
    .await?;

    Ok((StatusCode::CREATED, Json(event)))
}

pub async fn get_handler(State(state): State<AppState>) -> Result<impl IntoResponse, AuthError> {
    Ok(Json(list_events(state.db.as_ref()).await?))
}
