use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{jwt::AccessTokenClaims, state::AppState};

pub struct BearerToken {
    pub claims: AccessTokenClaims,
}

pub struct BearerError(String);

impl IntoResponse for BearerError {
    fn into_response(self) -> Response {
        let www_auth = format!(
            "Bearer error=\"invalid_token\", error_description=\"{}\"",
            self.0
        );
        (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_str(&www_auth)
                    .unwrap_or_else(|_| HeaderValue::from_static("Bearer error=\"invalid_token\"")),
            )],
            self.0,
        )
            .into_response()
    }
}

impl<S> FromRequestParts<S> for BearerToken
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = BearerError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);

        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| BearerError("missing Authorization header".into()))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| BearerError("invalid Authorization header format".into()))?;

        if token.is_empty() {
            return Err(BearerError("empty bearer token".into()));
        }

        let jwt_keys = state
            .jwt_keys
            .as_ref()
            .ok_or_else(|| BearerError("JWT verification not configured".into()))?;

        // For /userinfo, the audience is not checked strictly per OIDC spec.
        // We use an empty audience validation to allow any audience.
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&[&state.issuer_url]);
        validation.validate_aud = false;

        let token_data =
            jsonwebtoken::decode::<AccessTokenClaims>(token, &jwt_keys.decoding_key, &validation)
                .map_err(|e| BearerError(format!("invalid token: {e}")))?;

        Ok(BearerToken {
            claims: token_data.claims,
        })
    }
}
