use jsonwebtoken::{DecodingKey, EncodingKey};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand_core::OsRng;

use crate::error::AuthError;

/// Holds the ES256 signing/verification keys and metadata for JWT operations.
#[derive(Clone)]
pub struct JwtKeys {
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    pub kid: String,
    pub public_key_pem: String,
}

impl JwtKeys {
    /// Load JWT keys from a PEM-encoded ES256 private key.
    pub fn from_pem(private_pem: &[u8], kid: &str) -> Result<Self, AuthError> {
        let encoding_key = EncodingKey::from_ec_pem(private_pem)
            .map_err(|e| AuthError::Internal(format!("Failed to load JWT encoding key: {e}")))?;

        // Extract the public key from the private key PEM
        let private_key = p256::SecretKey::from_sec1_pem(
            std::str::from_utf8(private_pem)
                .map_err(|e| AuthError::Internal(format!("Invalid PEM encoding: {e}")))?,
        )
        .or_else(|_| {
            p256::SecretKey::from_pkcs8_pem(
                std::str::from_utf8(private_pem)
                    .map_err(|e| AuthError::Internal(format!("Invalid PEM encoding: {e}")))?,
            )
            .map_err(|e| AuthError::Internal(format!("Failed to parse private key: {e}")))
        })?;

        let public_key = private_key.public_key();
        let public_key_pem = public_key.to_string();

        let decoding_key = DecodingKey::from_ec_pem(public_key_pem.as_bytes())
            .map_err(|e| AuthError::Internal(format!("Failed to load JWT decoding key: {e}")))?;

        Ok(Self {
            encoding_key,
            decoding_key,
            kid: kid.to_string(),
            public_key_pem,
        })
    }
}

/// Generate a new ES256 keypair. Returns `(private_pem, public_pem)`.
pub fn generate_es256_keypair() -> Result<(String, String), AuthError> {
    let signing_key = SigningKey::random(&mut OsRng);
    let secret_key = p256::SecretKey::from(signing_key);

    let private_pem = secret_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| AuthError::Internal(format!("Failed to encode private key: {e}")))?;

    let public_key = secret_key.public_key();
    let public_pem = public_key.to_string();

    Ok((private_pem.to_string(), public_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_load_keypair() {
        let (private_pem, _public_pem) = generate_es256_keypair().unwrap();
        let keys = JwtKeys::from_pem(private_pem.as_bytes(), "test-kid-1").unwrap();

        assert_eq!(keys.kid, "test-kid-1");
        assert!(!keys.public_key_pem.is_empty());
    }
}
