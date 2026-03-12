//! HTTP API handlers and router.
//!
//! Implements the registry REST API consumed by the duumbi CLI client.
//!
//! ## Endpoints
//!
//! | Method | Path | Auth | Description |
//! |--------|------|------|-------------|
//! | GET | `/api/v1/modules/{module}` | No | Module info |
//! | GET | `/api/v1/modules/{module}/{version}/download` | No | Download archive |
//! | PUT | `/api/v1/modules/{module}` | Yes | Publish version |
//! | DELETE | `/api/v1/modules/{module}/{version}` | Yes | Yank version |
//! | GET | `/api/v1/search?q={query}` | No | Search modules |
//! | GET | `/health` | No | Health check |

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{delete, get, put};
use axum::{Json, Router};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::AppState;
use crate::auth;
use crate::error::RegistryError;
use crate::types::{PublishResponse, SearchResponse};

/// Builds the API router with all routes and middleware.
pub fn router(state: Arc<AppState>) -> Router {
    let public = Router::new()
        .route(
            "/api/v1/modules/{*module_path}",
            get(get_module_or_download),
        )
        .route("/api/v1/search", get(search))
        .route("/health", get(health));

    let authed = Router::new()
        .route("/api/v1/modules/{*module_path}", put(publish))
        .route("/api/v1/modules/{*module_version_path}", delete(yank))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    Router::new()
        .merge(public)
        .merge(authed)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Health check endpoint.
async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// GET /api/v1/modules/{scope}/{name} — module info
/// GET /api/v1/modules/{scope}/{name}/{version}/download — download archive
///
/// Both share the same wildcard route; we disambiguate by path segment count.
async fn get_module_or_download(
    State(state): State<Arc<AppState>>,
    Path(module_path): Path<String>,
) -> Result<axum::response::Response, RegistryError> {
    // Parse path: "scope/name" or "scope/name/version/download"
    let parts: Vec<&str> = module_path.split('/').collect();

    match parts.as_slice() {
        // @scope/name → module info
        [scope, name] => {
            let module = format!("{scope}/{name}");
            let info = state.db.get_module(&module)?;
            Ok(Json(info).into_response())
        }
        // @scope/name/version/download → download archive
        [scope, name, version, "download"] => {
            let module = format!("{scope}/{name}");
            let data = state.storage.load(&module, version)?;
            Ok((StatusCode::OK, [("content-type", "application/gzip")], data).into_response())
        }
        _ => Err(RegistryError::NotFound(format!(
            "Invalid path: {module_path}"
        ))),
    }
}

/// Search query parameters.
#[derive(serde::Deserialize)]
struct SearchParams {
    q: Option<String>,
}

/// GET /api/v1/search?q={query} — search modules.
async fn search(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchParams>,
) -> Result<Json<SearchResponse>, RegistryError> {
    let query = params.q.unwrap_or_default();
    let results = state.db.search(&query, 50)?;
    Ok(Json(results))
}

/// PUT /api/v1/modules/{scope}/{name} — publish a new version.
///
/// Expects the raw `.tar.gz` archive as the request body.
/// Reads `manifest.toml` from the archive to extract version and metadata.
async fn publish(
    State(state): State<Arc<AppState>>,
    Path(module_path): Path<String>,
    body: Bytes,
) -> Result<Json<PublishResponse>, RegistryError> {
    let parts: Vec<&str> = module_path.split('/').collect();
    let module = match parts.as_slice() {
        [scope, name] => format!("{scope}/{name}"),
        _ => {
            return Err(RegistryError::InvalidModule(
                "Invalid module path".to_string(),
            ));
        }
    };

    if body.is_empty() {
        return Err(RegistryError::InvalidModule(
            "Empty archive body".to_string(),
        ));
    }

    // Compute integrity hash
    use sha2::{Digest, Sha256};
    let integrity = format!("sha256:{:x}", Sha256::digest(&body));

    // Extract version from the archive's manifest.toml
    let (version, description) = extract_manifest_info(&body)?;

    // Validate version is valid semver
    semver::Version::parse(&version)
        .map_err(|e| RegistryError::InvalidModule(format!("Invalid version '{version}': {e}")))?;

    // Store in database
    state
        .db
        .publish_version(&module, description.as_deref(), &version, &integrity)?;

    // Store archive on filesystem
    state.storage.store(&module, &version, &body)?;

    tracing::info!("Published {module}@{version}");

    Ok(Json(PublishResponse {
        name: module,
        version,
    }))
}

/// DELETE /api/v1/modules/{scope}/{name}/{version} — yank a version.
async fn yank(
    State(state): State<Arc<AppState>>,
    Path(module_version_path): Path<String>,
) -> Result<StatusCode, RegistryError> {
    let parts: Vec<&str> = module_version_path.split('/').collect();
    let (module, version) = match parts.as_slice() {
        [scope, name, version] => (format!("{scope}/{name}"), version.to_string()),
        _ => {
            return Err(RegistryError::InvalidModule(
                "Expected @scope/name/version".to_string(),
            ));
        }
    };

    state.db.yank_version(&module, &version)?;

    tracing::info!("Yanked {module}@{version}");

    Ok(StatusCode::NO_CONTENT)
}

/// Extracts version and description from a .tar.gz archive's manifest.toml.
fn extract_manifest_info(tarball: &[u8]) -> Result<(String, Option<String>), RegistryError> {
    use std::io::Read;

    let decoder = flate2::read::GzDecoder::new(tarball);
    let mut archive = tar::Archive::new(decoder);

    for entry in archive
        .entries()
        .map_err(|e| RegistryError::InvalidModule(format!("Cannot read archive: {e}")))?
    {
        let mut entry =
            entry.map_err(|e| RegistryError::InvalidModule(format!("Bad archive entry: {e}")))?;

        let path = entry
            .path()
            .map_err(|e| RegistryError::InvalidModule(format!("Bad path: {e}")))?
            .to_path_buf();

        if path.file_name().is_some_and(|n| n == "manifest.toml") {
            let mut content = String::new();
            entry
                .read_to_string(&mut content)
                .map_err(|e| RegistryError::InvalidModule(format!("Cannot read manifest: {e}")))?;

            let manifest: toml::Value = toml::from_str(&content)
                .map_err(|e| RegistryError::InvalidModule(format!("Invalid manifest TOML: {e}")))?;

            let version = manifest
                .get("version")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    RegistryError::InvalidModule("manifest.toml missing 'version'".to_string())
                })?
                .to_string();

            let description = manifest
                .get("description")
                .and_then(|v| v.as_str())
                .map(String::from);

            return Ok((version, description));
        }
    }

    Err(RegistryError::InvalidModule(
        "Archive does not contain manifest.toml".to_string(),
    ))
}
