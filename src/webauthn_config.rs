use std::env;

use url::Url;
use webauthn_rs::prelude::*;

use crate::error::AuthError;

const DEFAULT_RP_ID: &str = "auth.ericminassian.com";
const DEFAULT_RP_ORIGIN: &str = "https://auth.ericminassian.com";
const DEFAULT_RP_NAME: &str = "EricAuth";

pub fn build_webauthn() -> Result<Webauthn, AuthError> {
    let rp_id = env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| DEFAULT_RP_ID.to_string());
    let rp_origin_raw =
        env::var("WEBAUTHN_RP_ORIGIN").unwrap_or_else(|_| DEFAULT_RP_ORIGIN.to_string());
    let rp_name = env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| DEFAULT_RP_NAME.to_string());

    let rp_origin = Url::parse(&rp_origin_raw)
        .map_err(|e| AuthError::Internal(format!("Invalid RP origin URL: {e}")))?;

    tracing::info!(%rp_id, rp_origin = %rp_origin, "Configuring WebAuthn relying party");

    let builder = WebauthnBuilder::new(&rp_id, &rp_origin)
        .map_err(|e| AuthError::Internal(format!("Invalid WebAuthn configuration: {e}")))?
        .rp_name(&rp_name);

    builder
        .build()
        .map_err(|e| AuthError::Internal(format!("Failed to build WebAuthn: {e}")))
}
