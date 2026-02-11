use url::Url;
use webauthn_rs::prelude::*;

use crate::error::AuthError;

pub fn build_webauthn() -> Result<Webauthn, AuthError> {
    let rp_id = "auth.ericminassian.com";
    let rp_origin = Url::parse("https://auth.ericminassian.com")
        .map_err(|e| AuthError::Internal(format!("Invalid RP origin URL: {e}")))?;

    let builder = WebauthnBuilder::new(rp_id, &rp_origin)
        .map_err(|e| AuthError::Internal(format!("Invalid WebAuthn configuration: {e}")))?
        .rp_name("EricAuth");

    builder
        .build()
        .map_err(|e| AuthError::Internal(format!("Failed to build WebAuthn: {e}")))
}
