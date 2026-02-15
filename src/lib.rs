pub mod admin_rbac;
pub mod audit;
pub mod db;
pub mod encryption;
pub mod error;
pub mod jwt;
pub mod mfa;
pub mod middleware;
pub mod oauth;
pub mod password;
pub mod refresh_token;
pub mod routes;
pub mod saml;
pub mod session;
pub mod state;
pub mod templates;
pub mod user;
pub mod validation;
pub mod webauthn_config;

pub fn generate_random_recovery_code() -> Result<String, &'static str> {
    let mut recovery_code_bytes = [0u8; 10];
    getrandom::fill(&mut recovery_code_bytes).map_err(|_| "Invalid Recovery Code")?;

    Ok(base32::encode(
        base32::Alphabet::Rfc4648 { padding: false },
        &recovery_code_bytes,
    )
    .to_uppercase())
}
