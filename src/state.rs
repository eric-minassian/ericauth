use std::sync::Arc;

use tokio::sync::Mutex;

use crate::db::Database;

pub type AppState = Arc<Mutex<AppStateInner>>;

pub fn initialize_state(ddb_client: aws_sdk_dynamodb::Client) -> AppState {
    Arc::new(Mutex::new(AppStateInner::new(ddb_client)))
}

pub struct AppStateInner {
    pub db: Database,
}

impl AppStateInner {
    pub fn new(ddb_client: aws_sdk_dynamodb::Client) -> Self {
        Self {
            db: Database::new(ddb_client),
        }
    }
}
