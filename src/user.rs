use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    db, error::AuthError, generate_random_recovery_code, password::hash_password,
    validation::normalize_email,
};

pub struct User {
    pub id: Uuid,
    pub email: String,
    pub created_at: String,
    pub updated_at: String,
    pub scopes: Vec<String>,
    pub recovery_codes: Vec<String>,
}

pub struct RecoveryCodes {
    pub plaintext_codes: Vec<String>,
    pub hashed_codes: Vec<String>,
}

pub fn verify_username_input(username: &str) -> bool {
    username.len() > 3 && username.len() < 32 && username.chars().all(|c| c.is_ascii_alphanumeric())
}

pub async fn create_user(
    db: &dyn db::Database,
    email: String,
    password: String,
) -> Result<User, AuthError> {
    let email = normalize_email(&email);

    let password_hash =
        Some(hash_password(&password).map_err(|e| AuthError::Internal(e.to_string()))?);

    let recovery_codes = generate_recovery_codes(8)?;

    let now = Utc::now().to_rfc3339();
    let scopes = vec![];
    let user_id = db
        .insert_user(
            email.clone(),
            password_hash,
            now.clone(),
            now.clone(),
            scopes.clone(),
            recovery_codes.hashed_codes,
        )
        .await?;

    Ok(User {
        id: user_id,
        email,
        created_at: now.clone(),
        updated_at: now,
        scopes,
        recovery_codes: recovery_codes.plaintext_codes,
    })
}

pub fn generate_recovery_codes(count: usize) -> Result<RecoveryCodes, AuthError> {
    let mut plaintext_codes = Vec::with_capacity(count);
    let mut hashed_codes = Vec::with_capacity(count);

    for _ in 0..count {
        let code =
            generate_random_recovery_code().map_err(|e| AuthError::Internal(e.to_string()))?;
        let hash = hex::encode(Sha256::digest(code.as_bytes()));
        plaintext_codes.push(code);
        hashed_codes.push(hash);
    }

    Ok(RecoveryCodes {
        plaintext_codes,
        hashed_codes,
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
