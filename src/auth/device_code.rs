//! Device code generation for CLI authentication.
//!
//! Generates user-facing codes (e.g., "ABCD-1234") and device codes
//! (64-char hex) for the device code flow.

use rand::Rng;

/// Generates a user-facing code in the format `XXXX-XXXX`.
///
/// Uses uppercase alphanumeric characters (excluding confusable ones
/// like 0/O, 1/I/L) for readability.
#[must_use]
pub fn generate_user_code() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rng();

    let part1: String = (0..4)
        .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
        .collect();
    let part2: String = (0..4)
        .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
        .collect();

    format!("{part1}-{part2}")
}

/// Generates a 64-character hex device code (32 random bytes).
#[must_use]
pub fn generate_device_code() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// Generates an API token in the format `duu_` + 32 hex characters.
#[must_use]
pub fn generate_api_token() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    format!("duu_{}", hex::encode(bytes))
}

/// Generates a random state string for CSRF protection (32 hex chars).
#[must_use]
pub fn generate_csrf_state() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_code_format() {
        let code = generate_user_code();
        assert_eq!(code.len(), 9); // XXXX-XXXX
        assert_eq!(&code[4..5], "-");
        assert!(code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    }

    #[test]
    fn device_code_length() {
        let code = generate_device_code();
        assert_eq!(code.len(), 64);
        assert!(code.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn api_token_format() {
        let token = generate_api_token();
        assert!(token.starts_with("duu_"));
        assert_eq!(token.len(), 36); // "duu_" + 32 hex
    }

    #[test]
    fn csrf_state_length() {
        let state = generate_csrf_state();
        assert_eq!(state.len(), 32);
    }

    #[test]
    fn codes_are_unique() {
        let c1 = generate_user_code();
        let c2 = generate_user_code();
        // Statistically extremely unlikely to collide
        assert_ne!(c1, c2);
    }
}
