use std::env;

use crate::db::Database;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
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
        Self { db }
    }
}
