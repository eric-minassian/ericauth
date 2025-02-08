use uuid::Uuid;

use crate::{
    encryption::encrypt_str, generate_random_recovery_code, password::hash_password,
    USERS_TABLE_NAME,
};

pub struct User {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub email_verified: bool,
    pub registered_totp: bool,
    pub registered_security_key: bool,
    pub registered_passkey: bool,
    pub registered_2fa: bool,
}

pub fn verify_username_input(username: &str) -> bool {
    username.len() > 3 && username.len() < 32 && username.chars().all(|c| c.is_ascii_alphanumeric())
}

pub async fn create_user(
    client: &aws_sdk_dynamodb::Client,
    email: String,
    username: String,
    password: String,
) -> Result<User, &'static str> {
    let password_hash = hash_password(&password)?;
    let recovery_code = generate_random_recovery_code()?;
    let encrypted_recovery_code = encrypt_str(&recovery_code)?;

    unimplemented!()
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
