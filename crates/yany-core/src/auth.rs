use crate::error::YanyError;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use rand::RngCore;
use zeroize::Zeroize;

const MIN_PASSWORD: usize = 8;
const MAX_PASSWORD: usize = 128;

pub fn validate_password(password: &str) -> Result<(), YanyError> {
    let len = password.chars().count();
    if len < MIN_PASSWORD || len > MAX_PASSWORD {
        return Err(YanyError::Invalid(
            "password must be 8..=128 characters".into(),
        ));
    }
    if password.chars().any(|c| c.is_control()) {
        return Err(YanyError::Invalid("password contains control chars".into()));
    }
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String, YanyError> {
    validate_password(password)?;
    let mut salt_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| YanyError::Crypto(e.to_string()))?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| YanyError::Crypto(e.to_string()))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, encoded: &str) -> Result<(), YanyError> {
    validate_password(password)?;
    let parsed =
        PasswordHash::new(encoded).map_err(|_| YanyError::Auth)?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| YanyError::Auth)?;
    Ok(())
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

pub fn wipe(mut secret: String) {
    secret.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let h = hash_password("correct-horse").unwrap();
        verify_password("correct-horse", &h).unwrap();
        assert!(verify_password("wrong-password", &h).is_err());
    }

    #[test]
    fn rejects_short_password() {
        assert!(validate_password("short").is_err());
        assert!(validate_password("has\nnewlineok?").is_err());
    }
}
