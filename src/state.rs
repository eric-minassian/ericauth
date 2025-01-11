use std::sync::Arc;

use tokio::sync::Mutex;

use crate::db::Database;

pub type State = Arc<Mutex<_State>>;

pub fn initialize_state() -> State {
    Arc::new(Mutex::new(_State::new()))
}

pub struct _State {
    pub db: Database,
}

impl _State {
    pub fn new() -> Self {
        Self {
            db: Database::new(),
        }
    }
}
