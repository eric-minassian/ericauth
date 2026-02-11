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

        let jwt_keys = match env::var("JWT_PRIVATE_KEY") {
            Ok(pem) => {
                let kid = env::var("JWT_KEY_ID").unwrap_or_else(|_| "ericauth-key-1".to_string());
                match JwtKeys::from_pem(pem.as_bytes(), &kid) {
                    Ok(keys) => {
                        tracing::info!("JWT keys loaded successfully");
                        Some(keys)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load JWT keys: {e}");
                        None
                    }
                }
            }
            Err(_) => {
                tracing::info!("JWT_PRIVATE_KEY not set, JWT signing disabled");
                None
            }
        };

        let webauthn = Arc::new(build_webauthn().expect("Failed to initialize WebAuthn"));

        Self {
            db,
            jwt_keys,
            webauthn,
        }
    }
}
