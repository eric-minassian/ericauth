use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::AuthError;

pub fn generate_refresh_token() -> Result<String, AuthError> {
    let mut token_bytes = [0u8; 32];
    getrandom::fill(&mut token_bytes)
        .map_err(|e| AuthError::Internal(format!("Failed to generate refresh token: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(token_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_refresh_token() {
        let token = generate_refresh_token().unwrap();
        // 32 bytes base64url-encoded without padding = 43 characters
        assert_eq!(token.len(), 43);
    }

    #[test]
    fn test_generate_refresh_token_uniqueness() {
        let token1 = generate_refresh_token().unwrap();
        let token2 = generate_refresh_token().unwrap();
        assert_ne!(token1, token2);
    }
}
