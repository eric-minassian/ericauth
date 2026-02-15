use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use sha2::{Digest, Sha256};

pub const TOTP_STEP_SECONDS: i64 = 30;
pub const TOTP_DIGITS: u32 = 6;
pub const TOTP_WINDOW: i64 = 1;

pub fn generate_totp_secret() -> Result<String, &'static str> {
    let mut secret_bytes = [0u8; 20];
    getrandom::fill(&mut secret_bytes).map_err(|_| "failed to generate TOTP secret")?;
    Ok(base32::encode(
        base32::Alphabet::Rfc4648 { padding: false },
        &secret_bytes,
    ))
}

pub fn totp_code_at(
    secret_base32: &str,
    timestamp: i64,
    step_seconds: i64,
) -> Result<String, &'static str> {
    if step_seconds <= 0 {
        return Err("invalid TOTP step");
    }
    if timestamp < 0 {
        return Err("invalid timestamp");
    }

    let secret = decode_totp_secret(secret_base32)?;
    let counter = (timestamp / step_seconds) as u64;
    hotp_code(&secret, counter)
}

pub fn verify_totp_code(
    secret_base32: &str,
    code: &str,
    timestamp: i64,
    step_seconds: i64,
    window: i64,
) -> Result<bool, &'static str> {
    if step_seconds <= 0 {
        return Err("invalid TOTP step");
    }
    if timestamp < 0 {
        return Err("invalid timestamp");
    }

    let trimmed_code = code.trim();
    if trimmed_code.len() != TOTP_DIGITS as usize
        || !trimmed_code.chars().all(|c| c.is_ascii_digit())
    {
        return Ok(false);
    }

    for drift in -window..=window {
        let check_timestamp = timestamp + (drift * step_seconds);
        if check_timestamp < 0 {
            continue;
        }

        let expected = totp_code_at(secret_base32, check_timestamp, step_seconds)?;
        if expected == trimmed_code {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn hash_backup_code(code: &str) -> String {
    hex::encode(Sha256::digest(code.trim().as_bytes()))
}

fn decode_totp_secret(secret_base32: &str) -> Result<Vec<u8>, &'static str> {
    let cleaned = secret_base32.trim().replace(' ', "").to_uppercase();
    if cleaned.is_empty() {
        return Err("invalid TOTP secret");
    }

    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
        .ok_or("invalid TOTP secret")
}

fn hotp_code(secret: &[u8], counter: u64) -> Result<String, &'static str> {
    let key = PKey::hmac(secret).map_err(|_| "invalid TOTP secret")?;
    let mut signer = Signer::new(MessageDigest::sha1(), &key).map_err(|_| "invalid TOTP secret")?;
    signer
        .update(&counter.to_be_bytes())
        .map_err(|_| "failed to generate TOTP")?;
    let hmac = signer
        .sign_to_vec()
        .map_err(|_| "failed to generate TOTP")?;

    let offset = (hmac[19] & 0x0f) as usize;
    let code = (((hmac[offset] & 0x7f) as u32) << 24)
        | ((hmac[offset + 1] as u32) << 16)
        | ((hmac[offset + 2] as u32) << 8)
        | (hmac[offset + 3] as u32);
    let modulus = 10u32.pow(TOTP_DIGITS);

    Ok(format!(
        "{:0width$}",
        code % modulus,
        width = TOTP_DIGITS as usize
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn test_totp_matches_known_vector() {
        let code = totp_code_at(TEST_SECRET, 59, TOTP_STEP_SECONDS).expect("totp code");
        assert_eq!(code, "287082");
    }

    #[test]
    fn test_verify_totp_current_window() {
        let now = 1_700_000_000;
        let code = totp_code_at(TEST_SECRET, now, TOTP_STEP_SECONDS).expect("totp code");
        assert!(
            verify_totp_code(TEST_SECRET, &code, now, TOTP_STEP_SECONDS, TOTP_WINDOW)
                .expect("verify result")
        );
    }

    #[test]
    fn test_verify_totp_accepts_window_drift() {
        let now = 1_700_000_000;
        let prior_window_code =
            totp_code_at(TEST_SECRET, now - TOTP_STEP_SECONDS, TOTP_STEP_SECONDS).expect("code");

        assert!(verify_totp_code(
            TEST_SECRET,
            &prior_window_code,
            now,
            TOTP_STEP_SECONDS,
            TOTP_WINDOW,
        )
        .expect("verify result"));
    }

    #[test]
    fn test_verify_totp_rejects_outside_window() {
        let now = 1_700_000_000;
        let old_code = totp_code_at(
            TEST_SECRET,
            now - (TOTP_STEP_SECONDS * 2),
            TOTP_STEP_SECONDS,
        )
        .expect("code");

        assert!(
            !verify_totp_code(TEST_SECRET, &old_code, now, TOTP_STEP_SECONDS, TOTP_WINDOW)
                .expect("verify result")
        );
    }

    #[test]
    fn test_generate_totp_secret_is_base32() {
        let secret = generate_totp_secret().expect("secret generation");
        let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret);
        assert!(decoded.is_some());
    }
}
