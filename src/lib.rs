//! duumbi-registry — Registry server for duumbi modules.
//!
//! Library crate exposing the server components for embedding in tests.

pub mod api;
pub mod auth;
pub mod db;
pub mod error;
pub mod storage;
pub mod types;
pub mod web;

use std::sync::Arc;

/// Authentication mode for the registry.
#[derive(Debug, Clone)]
pub enum AuthMode {
    /// GitHub OAuth2 (for the global registry at registry.duumbi.dev).
    GithubOauth,
    /// Local username + password (for private, self-hosted registries).
    LocalPassword,
}

impl AuthMode {
    /// Parses the `AUTH_MODE` environment variable value.
    ///
    /// Accepted values: `"github_oauth"`, `"local_password"` (default).
    #[must_use]
    pub fn from_env_value(value: &str) -> Self {
        match value {
            "github_oauth" => Self::GithubOauth,
            _ => Self::LocalPassword,
        }
    }

    /// Returns the string representation used in API responses.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GithubOauth => "github_oauth",
            Self::LocalPassword => "local_password",
        }
    }

    /// Whether this mode supports the device code flow for CLI login.
    #[must_use]
    pub fn device_code_supported(&self) -> bool {
        matches!(self, Self::GithubOauth)
    }
}

/// Shared application state passed to all handlers.
pub struct AppState {
    /// Database connection pool.
    pub db: db::Database,
    /// Module archive storage.
    pub storage: storage::Storage,
    /// Authentication mode (GitHub OAuth or local password).
    pub auth_mode: AuthMode,
    /// Secret key for signing JWT session tokens.
    pub jwt_secret: String,
    /// Public base URL (e.g., `https://registry.duumbi.dev`).
    pub base_url: String,
    /// GitHub OAuth client ID (required when auth_mode is GithubOauth).
    pub github_client_id: Option<String>,
    /// GitHub OAuth client secret (required when auth_mode is GithubOauth).
    pub github_client_secret: Option<String>,
    /// In-memory rate limiter for auth endpoints.
    pub rate_limiter: auth::rate_limit::RateLimiter,
}

/// Builds the full axum application (API + web frontend).
pub fn build_app(state: Arc<AppState>) -> axum::Router {
    api::router(state.clone()).merge(web::router(state))
}
