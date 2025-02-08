use std::{env, sync::OnceLock};

use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
};

const NONCE_LENGTH: usize = 12;
const AUTH_TAG_LENGTH: usize = 16;
const EXPECTED_KEY_LENGTH: usize = 32;

static ENCRYPTION_KEY: OnceLock<Key<Aes256Gcm>> = OnceLock::new();

fn get_encryption_key() -> &'static Key<Aes256Gcm> {
    ENCRYPTION_KEY.get_or_init(|| {
        let key_str =
            env::var("ENCRYPTION_KEY").expect("ENCRYPTION_KEY environment variable must be set");

        let key_bytes = key_str.as_bytes();
        if key_bytes.len() != EXPECTED_KEY_LENGTH {
            panic!(
                "ENCRYPTION_KEY must be exactly {} bytes when UTF-8 encoded, got {} bytes",
                EXPECTED_KEY_LENGTH,
                key_bytes.len()
            );
        }

        Key::<Aes256Gcm>::from_slice(key_bytes).to_owned()
    })
}

pub fn encrypt(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let key = get_encryption_key();
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let encrypted_data = cipher
        .encrypt(&nonce, data)
        .map_err(|_| "encryption failed")?;

    let mut result = Vec::with_capacity(NONCE_LENGTH + encrypted_data.len());
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&encrypted_data);

    Ok(result)
}

pub fn encrypt_str(data: &str) -> Result<Vec<u8>, &'static str> {
    Ok(encrypt(data.as_bytes())?)
}

pub fn decrypt(encrypted: &[u8]) -> Result<Vec<u8>, &'static str> {
    if encrypted.len() <= NONCE_LENGTH + AUTH_TAG_LENGTH {
        return Err("encrypted data too short");
    }

    let key = get_encryption_key();
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&encrypted[..NONCE_LENGTH]);
    let encrypted_data = &encrypted[NONCE_LENGTH..];

    cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|_| "decryption failed")
}

pub fn decrypt_str(encrypted: &[u8]) -> Result<String, &'static str> {
    let decrypted = decrypt(encrypted)?;
    String::from_utf8(decrypted).map_err(|_| "decryption failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn set_test_key() {
        env::set_var("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef"); // 32-byte key for AES-256
        get_encryption_key();
    }

    #[test]
    fn test_encrypt_decrypt() {
        set_test_key();

        let plaintext = b"Hello, AES-GCM!";
        let encrypted = encrypt(plaintext).expect("Encryption failed");
        let decrypted = decrypt(&encrypted).expect("Decryption failed");

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_str() {
        set_test_key();

        let plaintext = "Hello, AES-GCM!";
        let encrypted = encrypt_str(plaintext).expect("Encryption failed");
        let decrypted = decrypt_str(&encrypted).expect("Decryption failed");

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_invalid_decryption() {
        set_test_key();

        let invalid_data = vec![0u8; 10]; // Too short to be valid encrypted data
        let result = decrypt(&invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_non_utf8_decryption() {
        set_test_key();

        let non_utf8_data = vec![0, 159, 146, 150]; // Invalid UTF-8 bytes
        let encrypted = encrypt(&non_utf8_data).expect("Encryption failed");
        let decrypted = decrypt(&encrypted).expect("Decryption failed");

        assert_eq!(non_utf8_data, decrypted); // Should still match original bytes

        let result = decrypt_str(&encrypted);
        assert!(result.is_err()); // Should fail because it's not valid UTF-8
    }
}
