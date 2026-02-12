/// Validates that an email address has a basic valid format.
pub fn verify_email(email: &str) -> bool {
    email.contains('@') && email.len() < 256
}

/// Normalize email input for lookups/storage.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_email() {
        assert!(verify_email("user@example.com"));
        assert!(!verify_email("nope"));
        assert!(!verify_email(""));
        assert!(!verify_email(&"a".repeat(256)));
    }

    #[test]
    fn test_normalize_email() {
        assert_eq!(normalize_email(" User@Example.COM "), "user@example.com");
    }
}
