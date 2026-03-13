//! Session middleware and cookie helpers.
//!
//! Extracts the `duumbi_session` JWT cookie and provides the `MaybeUser`
//! extractor for web handlers.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use std::sync::Arc;

use super::jwt;
use crate::AppState;

/// An authenticated user session, extracted from the JWT cookie.
#[derive(Debug, Clone)]
pub struct SessionUser {
    /// Database user ID.
    pub id: i64,
    /// Username.
    pub username: String,
    /// Avatar URL (GitHub avatar or initials fallback).
    pub avatar_url: Option<String>,
}

/// Optional session extractor — does NOT reject unauthenticated requests.
///
/// Use this in web handlers where login is optional (e.g., nav bar rendering).
#[derive(Debug, Clone)]
pub struct MaybeUser(pub Option<SessionUser>);

/// Cookie name for the JWT session.
pub const SESSION_COOKIE: &str = "duumbi_session";

impl FromRequestParts<Arc<AppState>> for MaybeUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Parse cookies from the Cookie header
        let Some(cookie_header) = parts.headers.get(axum::http::header::COOKIE) else {
            return Ok(MaybeUser(None));
        };

        let Ok(cookie_str) = cookie_header.to_str() else {
            return Ok(MaybeUser(None));
        };

        // Find our session cookie
        let token = cookie_str
            .split(';')
            .filter_map(|s| {
                let s = s.trim();
                s.strip_prefix(&format!("{SESSION_COOKIE}="))
            })
            .next();

        let Some(token) = token else {
            return Ok(MaybeUser(None));
        };

        // Verify JWT
        match jwt::verify_token(&state.jwt_secret, token) {
            Ok(claims) => Ok(MaybeUser(Some(SessionUser {
                id: claims.sub,
                username: claims.username,
                avatar_url: claims.avatar_url,
            }))),
            Err(_) => Ok(MaybeUser(None)),
        }
    }
}

/// Builds a `Set-Cookie` header value for the session JWT.
#[must_use]
pub fn build_session_cookie(jwt_token: &str, base_url: &str) -> String {
    let secure = base_url.starts_with("https://");
    let secure_flag = if secure { "; Secure" } else { "" };

    format!(
        "{SESSION_COOKIE}={jwt_token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}{secure_flag}",
        jwt::SESSION_MAX_AGE_SECS,
    )
}

/// Builds a `Set-Cookie` header value that clears the session cookie.
#[must_use]
pub fn build_logout_cookie() -> String {
    format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cookie_https() {
        let cookie = build_session_cookie("tok123", "https://registry.duumbi.dev");
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("duumbi_session=tok123"));
    }

    #[test]
    fn session_cookie_localhost() {
        let cookie = build_session_cookie("tok123", "http://localhost:8080");
        assert!(cookie.contains("HttpOnly"));
        assert!(!cookie.contains("Secure"));
    }

    #[test]
    fn logout_cookie_clears() {
        let cookie = build_logout_cookie();
        assert!(cookie.contains("Max-Age=0"));
        assert!(cookie.contains("duumbi_session="));
    }
}
