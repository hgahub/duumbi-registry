//! Authentication middleware and helpers.
//!
//! Extracts Bearer tokens from the `Authorization` header and validates
//! them against the database.

use axum::extract::Request;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;

use crate::error::RegistryError;
use crate::AppState;

/// Extracts the Bearer token from the Authorization header.
pub fn extract_bearer_token(req: &Request) -> Result<String, RegistryError> {
    let header = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or_else(|| RegistryError::AuthFailed("Missing Authorization header".to_string()))?;

    let value = header
        .to_str()
        .map_err(|_| RegistryError::AuthFailed("Invalid Authorization header".to_string()))?;

    if let Some(token) = value.strip_prefix("Bearer ") {
        Ok(token.to_string())
    } else {
        Err(RegistryError::AuthFailed(
            "Expected Bearer token".to_string(),
        ))
    }
}

/// Middleware that requires a valid Bearer token for write operations.
#[allow(dead_code)] // Available for future route-level middleware usage
pub async fn require_auth(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, RegistryError> {
    let token = extract_bearer_token(&req)?;
    let username = state.db.validate_token(&token)?;

    // Store username in request extensions for handlers to use
    req.extensions_mut().insert(AuthUser(username));

    Ok(next.run(req).await)
}

/// Authenticated user identity, set by the auth middleware.
#[derive(Clone, Debug)]
#[allow(dead_code)] // Read by handlers via request extensions
pub struct AuthUser(pub String);
