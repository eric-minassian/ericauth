use std::env;
use std::sync::Arc;

use webauthn_rs::Webauthn;

use crate::{db::Database, jwt::JwtKeys, webauthn_config::build_webauthn};

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub jwt_keys: Option<JwtKeys>,
    pub webauthn: Arc<Webauthn>,
}

impl AppState {
    pub async fn new() -> Self {
        let db = match env::var("DATABASE_BACKEND").as_deref() {
            Ok("memory") => {
                tracing::info!("Using in-memory database backend");
                Database::memory()
            }
            _ => {
                tracing::info!("Using DynamoDB database backend");
                Database::dynamo().await
            }
        };

        let jwt_keys = load_jwt_keys().await;

        let webauthn = Arc::new(build_webauthn().expect("Failed to initialize WebAuthn"));

        Self {
            db,
            jwt_keys,
            webauthn,
        }
    }
}

/// Load JWT keys, trying Secrets Manager first, then falling back to env var.
async fn load_jwt_keys() -> Option<JwtKeys> {
    let kid = env::var("JWT_KEY_ID").unwrap_or_else(|_| "ericauth-key-1".to_string());

    // Try Secrets Manager first
    if let Ok(secret_arn) = env::var("JWT_SECRET_ARN") {
        match load_pem_from_secrets_manager(&secret_arn).await {
            Ok(pem) => {
                return match JwtKeys::from_pem(pem.as_bytes(), &kid) {
                    Ok(keys) => {
                        tracing::info!("JWT keys loaded from Secrets Manager");
                        Some(keys)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse JWT key from Secrets Manager: {e}");
                        None
                    }
                };
            }
            Err(e) => {
                tracing::warn!("Failed to load JWT key from Secrets Manager: {e}");
            }
        }
    }

    // Fall back to env var
    match env::var("JWT_PRIVATE_KEY") {
        Ok(pem) => match JwtKeys::from_pem(pem.as_bytes(), &kid) {
            Ok(keys) => {
                tracing::info!("JWT keys loaded from environment variable");
                Some(keys)
            }
            Err(e) => {
                tracing::warn!("Failed to load JWT keys from env: {e}");
                None
            }
        },
        Err(_) => {
            tracing::info!("No JWT key configured, JWT signing disabled");
            None
        }
    }
}

async fn load_pem_from_secrets_manager(secret_arn: &str) -> Result<String, String> {
    let config = aws_config::load_from_env().await;
    let client = aws_sdk_secretsmanager::Client::new(&config);

    let response = client
        .get_secret_value()
        .secret_id(secret_arn)
        .send()
        .await
        .map_err(|e| format!("Secrets Manager GetSecretValue failed: {e}"))?;

    response
        .secret_string()
        .map(|s| s.to_string())
        .ok_or_else(|| "Secret has no string value".to_string())
}
