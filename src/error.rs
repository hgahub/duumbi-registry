//! Error types for the registry server.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

/// Registry server errors.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Module not found.
    #[error("Module not found: {0}")]
    NotFound(String),

    /// Version not found.
    #[error("Version not found: {module}@{version}")]
    VersionNotFound { module: String, version: String },

    /// Module version already exists.
    #[error("Version {version} already exists for {module}")]
    VersionConflict { module: String, version: String },

    /// Authentication required or failed.
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// Invalid module archive or metadata.
    #[error("Invalid module: {0}")]
    InvalidModule(String),

    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// Storage I/O error.
    #[error("Storage error: {0}")]
    Storage(#[from] std::io::Error),

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::NotFound(_) | Self::VersionNotFound { .. } => {
                (StatusCode::NOT_FOUND, self.to_string())
            }
            Self::VersionConflict { .. } => (StatusCode::CONFLICT, self.to_string()),
            Self::AuthFailed(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::InvalidModule(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::Database(_) | Self::Storage(_) | Self::Internal(_) => {
                tracing::error!("{self}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };

        let body = serde_json::json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}
