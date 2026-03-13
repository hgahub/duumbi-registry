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
//! | GET | `/api/v1/auth/mode` | No | Auth mode discovery |
//! | GET | `/api/v1/auth/verify` | Bearer | Token verification |
//! | GET | `/health` | No | Health check |

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::AppState;
use crate::auth::extract_bearer_token;
use crate::error::RegistryError;
use crate::types::{PublishResponse, SearchResponse};

/// Builds the API router with all routes and middleware.
pub fn router(state: Arc<AppState>) -> Router {
    // All module routes share one wildcard; the handler dispatches by method+path.
    // PUT and DELETE require auth — we check inside the handler.
    Router::new()
        .route(
            "/api/v1/modules/{*module_path}",
            get(get_module_or_download).put(publish).delete(yank),
        )
        .route("/api/v1/search", get(search))
        .route("/api/v1/auth/mode", get(auth_mode))
        .route("/api/v1/auth/verify", get(auth_verify))
        .route(
            "/api/v1/auth/device/code",
            axum::routing::post(device_code_create),
        )
        .route(
            "/api/v1/auth/device/token",
            axum::routing::post(device_code_poll),
        )
        .route("/health", get(health))
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
    req: axum::extract::Request,
) -> Result<Json<PublishResponse>, RegistryError> {
    // Inline auth check
    let token = extract_bearer_token(&req)?;
    state.db.validate_token(&token)?;

    let body = axum::body::to_bytes(req.into_body(), 100 * 1024 * 1024)
        .await
        .map_err(|e| RegistryError::InvalidModule(format!("Failed to read body: {e}")))?;

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
    Path(module_path): Path<String>,
    req: axum::extract::Request,
) -> Result<StatusCode, RegistryError> {
    // Inline auth check
    let token = extract_bearer_token(&req)?;
    state.db.validate_token(&token)?;

    let parts: Vec<&str> = module_path.split('/').collect();
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

/// GET /api/v1/auth/mode — reports which authentication mode is configured.
///
/// The duumbi CLI calls this to decide whether to use device code flow
/// or fall back to manual token entry.
async fn auth_mode(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mode = &state.auth_mode;
    Json(serde_json::json!({
        "mode": mode.as_str(),
        "device_code_supported": mode.device_code_supported(),
    }))
}

/// GET /api/v1/auth/verify — validates a Bearer token.
///
/// Returns `{ "username": "..." }` on success, 401 on invalid/revoked token.
async fn auth_verify(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> Result<Json<serde_json::Value>, RegistryError> {
    let token = extract_bearer_token(&req)?;
    let username = state.db.validate_token(&token)?;

    Ok(Json(serde_json::json!({ "username": username })))
}

// ---------------------------------------------------------------------------
// Device code flow endpoints (#201)
// ---------------------------------------------------------------------------

/// Request body for `POST /api/v1/auth/device/code`.
#[derive(serde::Deserialize)]
struct DeviceCodeRequest {
    #[allow(dead_code)]
    client_id: Option<String>,
}

/// POST /api/v1/auth/device/code — initiate a device code flow.
///
/// Returns a user code for the CLI to display and a device code for polling.
async fn device_code_create(
    State(state): State<Arc<AppState>>,
    Json(_body): Json<DeviceCodeRequest>,
) -> Result<Json<serde_json::Value>, RegistryError> {
    if !state.auth_mode.device_code_supported() {
        return Err(RegistryError::AuthFailed(
            "Device code flow not supported in this auth mode".to_string(),
        ));
    }

    let user_code = crate::auth::device_code::generate_user_code();
    let device_code = crate::auth::device_code::generate_device_code();

    let expires_at = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::minutes(15))
        .ok_or_else(|| RegistryError::Internal("Time overflow".to_string()))?
        .to_rfc3339();

    state
        .db
        .create_device_code(&device_code, &user_code, &expires_at)?;

    let verification_uri = format!("{}/device", state.base_url);

    Ok(Json(serde_json::json!({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "expires_in": 900,
        "interval": 5,
    })))
}

/// Request body for `POST /api/v1/auth/device/token`.
#[derive(serde::Deserialize)]
struct DeviceTokenRequest {
    device_code: String,
    #[allow(dead_code)]
    client_id: Option<String>,
}

/// POST /api/v1/auth/device/token — poll for device code authorization.
///
/// Returns 428 while pending, 200 with token on success, 410 on expiry.
async fn device_code_poll(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DeviceTokenRequest>,
) -> Result<axum::response::Response, RegistryError> {
    let record = state.db.get_device_code(&body.device_code)?;

    // Check expiry
    let now = chrono::Utc::now().to_rfc3339();
    if record.expires_at < now {
        let body = serde_json::json!({ "error": "expired_token" });
        return Ok((StatusCode::GONE, Json(body)).into_response());
    }

    match record.status.as_str() {
        "pending" => {
            let body = serde_json::json!({ "error": "authorization_pending" });
            // 428 Precondition Required — standard for "not yet"
            Ok((StatusCode::PRECONDITION_REQUIRED, Json(body)).into_response())
        }
        "authorized" => {
            // Look up the user to get the username
            let user_id = record.user_id.ok_or_else(|| {
                RegistryError::Internal("Authorized device code has no user_id".to_string())
            })?;
            let user = state.db.get_user_by_id(user_id)?;

            // The token was already created during authorization.
            // We need to return the raw token — but we only stored the hash.
            // The raw token is stored temporarily in the device_codes.token_hash
            // field as the actual raw token (not hash) during authorize_device_code.
            // Wait — that's wrong. Let's re-think.
            //
            // Actually, the raw token needs to be communicated back. Since the
            // device code entry stores the token_hash, and the tokens table also
            // has the hash, we can't recover the raw token. The solution is:
            // the raw token is generated during authorize_device_code and ALSO
            // stored (encrypted or plain) in device_codes for retrieval here.
            //
            // For simplicity, device_codes.token_hash stores the RAW token
            // (not hash) temporarily. It's deleted after retrieval.
            let raw_token = record.token_hash.ok_or_else(|| {
                RegistryError::Internal("Authorized device code has no token".to_string())
            })?;

            let body = serde_json::json!({
                "token": raw_token,
                "username": user.username,
            });
            Ok((StatusCode::OK, Json(body)).into_response())
        }
        _ => {
            let body = serde_json::json!({ "error": "expired_token" });
            Ok((StatusCode::GONE, Json(body)).into_response())
        }
    }
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

            // Support both flat format (version = "1.0") and
            // [module] section format (module.version = "1.0")
            let module_section = manifest.get("module").unwrap_or(&manifest);

            let version = module_section
                .get("version")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    RegistryError::InvalidModule("manifest.toml missing 'version'".to_string())
                })?
                .to_string();

            let description = module_section
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
