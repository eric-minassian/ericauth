use std::collections::HashMap;

#[derive(Debug)]
pub struct User {
    pub email: String,
    pub password_hash: String,
}

#[derive(Debug)]
pub struct Database {
    users: HashMap<String, User>,
}

impl Database {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    pub fn insert_user(&mut self, email: String, password_hash: String) {
        self.users.insert(
            email.clone(),
            User {
                email,
                password_hash,
            },
        );
    }

    pub fn get_user(&self, email: &str) -> Option<&User> {
        self.users.get(email)
    }

    pub fn get_password_hash(&self, email: &str) -> Option<&str> {
        self.users
            .get(email)
            .map(|user| user.password_hash.as_str())
    }
}
