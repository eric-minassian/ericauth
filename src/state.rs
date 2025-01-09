use std::{collections::HashMap, sync::Arc};

use tokio::sync::Mutex;

pub type State = Arc<Mutex<_State>>;

pub fn initialize_state() -> State {
    Arc::new(Mutex::new(_State::new()))
}

pub struct _State {
    pub kv: HashMap<String, String>,
}

impl _State {
    pub fn new() -> Self {
        Self { kv: HashMap::new() }
    }
}
