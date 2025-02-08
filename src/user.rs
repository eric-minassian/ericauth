use uuid::Uuid;

use crate::{db::Database, password::hash_password};

pub struct User {
    pub id: Uuid,
    pub email: String,
}

pub fn verify_username_input(username: &str) -> bool {
    username.len() > 3 && username.len() < 32 && username.chars().all(|c| c.is_ascii_alphanumeric())
}

pub async fn create_user(
    db: &Database,
    email: String,
    password: String,
) -> Result<User, &'static str> {
    let password_hash = hash_password(&password)?;

    let user_id = db.insert_user(email.clone(), password_hash).await.unwrap();

    Ok(User { id: user_id, email })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_username_input() {
        assert!(verify_username_input("validUsername123"));
        assert!(!verify_username_input("ab"));
        assert!(!verify_username_input("a".repeat(33).as_str()));
        assert!(!verify_username_input("invalid@username"));
        assert!(!verify_username_input(" username "));
        assert!(!verify_username_input("username\n"));
        assert!(!verify_username_input("username\t"));
    }
}
