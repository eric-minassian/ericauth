use std::sync::Arc;

use tokio::sync::Mutex;

use crate::db::Database;

pub type AppState = Arc<Mutex<_AppState>>;

pub fn initialize_state() -> AppState {
    Arc::new(Mutex::new(_AppState::new()))
}

#[derive(Default)]
pub struct _AppState {
    pub db: Database,
}

impl _AppState {
    pub fn new() -> Self {
        Self::default()
    }
}
