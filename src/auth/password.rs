//! Password hashing and verification using Argon2id.
//!
//! Used in `local_password` auth mode for self-hosted registries.

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

use crate::error::RegistryError;

/// Hashes a password using Argon2id with a random salt.
pub fn hash_password(password: &str) -> Result<String, RegistryError> {
    // Use rand_core 0.6's OsRng (compatible with argon2/password_hash)
    let salt = SaltString::generate(&mut rand_core_06::OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| RegistryError::Internal(format!("Password hash failed: {e}")))
}

/// Verifies a password against a stored Argon2id hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, RegistryError> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| RegistryError::Internal(format!("Invalid password hash format: {e}")))?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let hash = hash_password("correct-horse-battery-staple").expect("hash");
        assert!(hash.starts_with("$argon2"));

        assert!(verify_password("correct-horse-battery-staple", &hash).expect("verify"));
        assert!(!verify_password("wrong-password", &hash).expect("verify wrong"));
    }

    #[test]
    fn different_passwords_different_hashes() {
        let h1 = hash_password("password1").expect("hash1");
        let h2 = hash_password("password2").expect("hash2");
        assert_ne!(h1, h2);
    }
}
