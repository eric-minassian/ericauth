use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};

pub fn hash_password(password: &str) -> Result<String, &'static str> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| "Failed to hash password")?
        .to_string();

    Ok(password_hash)
}

pub fn verify_password_hash(password: &str, password_hash: &str) -> Result<bool, &'static str> {
    let parsed_hash =
        PasswordHash::new(password_hash).map_err(|_| "invalid password hash in db")?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

pub fn verify_password_strength(password: &str) -> bool {
    // @TODO: Add haveibeenpwned check
    // https://haveibeenpwned.com/API/v3

    password.len() >= 8
        && password.len() < 128
        && password.chars().any(|c| c.is_ascii_uppercase())
        && password.chars().any(|c| c.is_ascii_lowercase())
        && password.chars().any(|c| c.is_ascii_digit())
        && password.chars().any(|c| !c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_password() {
        let password = "password123";
        let hashed = hash_password(password).unwrap();
        assert_ne!(hashed, password);
    }

    #[test]
    fn test_verify_password_hash() {
        let password = "password123";
        let hashed = hash_password(password).unwrap();
        assert!(verify_password_hash(password, &hashed).unwrap());
        assert!(!verify_password_hash("wrongpassword", &hashed).unwrap());
    }

    #[test]
    fn test_verify_password_strength() {
        assert!(verify_password_strength("StrongPass1!"));
        assert!(!verify_password_strength("short"));
        assert!(!verify_password_strength("weakpassword"));
        assert!(!verify_password_strength("12345678"));
        assert!(!verify_password_strength("Password"));
        assert!(!verify_password_strength("Password123"));
        assert!(!verify_password_strength("Password!"));
    }
}
