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

/// Shared application state passed to all handlers.
pub struct AppState {
    /// Database connection pool.
    pub db: db::Database,
    /// Module archive storage.
    pub storage: storage::Storage,
}

/// Builds the full axum application (API + web frontend).
pub fn build_app(state: Arc<AppState>) -> axum::Router {
    api::router(state.clone()).merge(web::router(state))
}
