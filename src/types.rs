//! Shared types for API requests and responses.
//!
//! These types mirror the DTOs in the duumbi client (`src/registry/types.rs`)
//! to ensure wire compatibility.

use serde::{Deserialize, Serialize};

/// Version information for a published module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// SemVer version string.
    pub version: String,
    /// Integrity hash (`sha256:<hex>`).
    pub integrity: String,
    /// Whether this version is yanked.
    pub yanked: bool,
    /// ISO-8601 publication timestamp.
    pub published_at: Option<String>,
}

/// Full module metadata with all published versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    /// Scoped module name (e.g., `@duumbi/stdlib-math`).
    pub name: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// All published versions (newest first).
    pub versions: Vec<VersionInfo>,
}

/// A single search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    /// Scoped module name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Latest non-yanked version.
    pub latest_version: String,
}

/// Search response with pagination info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    /// Matching modules.
    pub results: Vec<SearchHit>,
    /// Total count of matches.
    pub total: u64,
}

/// Publish response confirming a successful upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishResponse {
    /// Published module name.
    pub name: String,
    /// Published version.
    pub version: String,
}
