//! JWT session token creation and verification.
//!
//! Uses HS256 with the `JWT_SECRET` environment variable.

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// JWT claims stored in the session cookie.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// User ID (database primary key).
    pub sub: i64,
    /// Username for display.
    pub username: String,
    /// Avatar URL (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    /// Expiration time (Unix timestamp).
    pub exp: usize,
    /// Issued at (Unix timestamp).
    pub iat: usize,
}

/// Creates a signed JWT token.
///
/// The token expires after `max_age_secs` seconds (default: 7 days).
pub fn create_token(
    secret: &str,
    user_id: i64,
    username: &str,
    avatar_url: Option<&str>,
    max_age_secs: u64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = Claims {
        sub: user_id,
        username: username.to_string(),
        avatar_url: avatar_url.map(String::from),
        exp: now + max_age_secs as usize,
        iat: now,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

/// Verifies and decodes a JWT token.
///
/// Returns the claims if the token is valid and not expired.
pub fn verify_token(secret: &str, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;

    Ok(data.claims)
}

/// Default session duration: 7 days.
pub const SESSION_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_jwt() {
        let secret = "test-secret-key-for-jwt";
        let token =
            create_token(secret, 42, "alice", Some("https://avatar.com/a"), 3600).expect("create");

        let claims = verify_token(secret, &token).expect("verify");
        assert_eq!(claims.sub, 42);
        assert_eq!(claims.username, "alice");
        assert_eq!(claims.avatar_url.as_deref(), Some("https://avatar.com/a"));
    }

    #[test]
    fn expired_token_rejected() {
        let secret = "test-secret";
        // Create a token that expired 1 second ago
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: 1,
            username: "bob".to_string(),
            avatar_url: None,
            exp: now.saturating_sub(120), // well past the 60s leeway
            iat: now.saturating_sub(3600),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("encode");

        let err = verify_token(secret, &token);
        assert!(err.is_err());
    }

    #[test]
    fn wrong_secret_rejected() {
        let token = create_token("secret-a", 1, "user", None, 3600).expect("create");
        let err = verify_token("secret-b", &token);
        assert!(err.is_err());
    }
}
