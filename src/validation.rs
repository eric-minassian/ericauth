/// Validates that an email address has a valid format.
/// Checks: exactly one @, non-empty local/domain parts, domain has at least one dot,
/// and total length under 256 characters.
pub fn verify_email(email: &str) -> bool {
    if email.len() >= 256 {
        return false;
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    if local.is_empty() || domain.is_empty() {
        return false;
    }

    // Domain must contain at least one dot
    if !domain.contains('.') {
        return false;
    }

    // Domain parts must not be empty (no leading/trailing/consecutive dots)
    domain.split('.').all(|part| !part.is_empty())
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
    fn test_verify_email_rejects_no_domain_dot() {
        assert!(!verify_email("user@localhost"));
    }

    #[test]
    fn test_verify_email_rejects_empty_local() {
        assert!(!verify_email("@example.com"));
    }

    #[test]
    fn test_verify_email_rejects_empty_domain() {
        assert!(!verify_email("user@"));
    }

    #[test]
    fn test_verify_email_rejects_multiple_at() {
        assert!(!verify_email("user@foo@bar.com"));
    }

    #[test]
    fn test_verify_email_accepts_valid() {
        assert!(verify_email("user@example.com"));
        assert!(verify_email("a.b+tag@sub.domain.co.uk"));
    }

    #[test]
    fn test_normalize_email() {
        assert_eq!(normalize_email(" User@Example.COM "), "user@example.com");
    }
}
