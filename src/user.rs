use chrono::Utc;
use uuid::Uuid;

use crate::{db::Database, error::AuthError, password::hash_password};

pub struct User {
    pub id: Uuid,
    pub email: String,
    pub created_at: String,
    pub updated_at: String,
}

pub fn verify_username_input(username: &str) -> bool {
    username.len() > 3 && username.len() < 32 && username.chars().all(|c| c.is_ascii_alphanumeric())
}

pub async fn create_user(
    db: &Database,
    email: String,
    password: String,
) -> Result<User, AuthError> {
    let password_hash = hash_password(&password).map_err(|e| AuthError::Internal(e.to_string()))?;

    let now = Utc::now().to_rfc3339();
    let user_id = db
        .insert_user(email.clone(), password_hash, now.clone(), now.clone())
        .await?;

    Ok(User {
        id: user_id,
        email,
        created_at: now.clone(),
        updated_at: now,
    })
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
