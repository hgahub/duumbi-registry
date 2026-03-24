//! Server-side rendered web frontend using Askama templates.
//!
//! Provides HTML pages for browsing, searching, and viewing modules.
//! Mounted alongside the JSON API on the same axum server.

mod auth_routes;
mod settings;

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;

use crate::auth::session::{MaybeUser, SessionUser};
use crate::error::RegistryError;
use crate::types::{ModuleInfo, SearchHit, VersionInfo};
use crate::AppState;

/// Renders an Askama template into an HTML response.
fn render_template(tmpl: &impl Template) -> Result<Response, RegistryError> {
    let html = tmpl
        .render()
        .map_err(|e| RegistryError::Internal(format!("Template render error: {e}")))?;
    Ok(Html(html).into_response())
}

/// Builds the web frontend router.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/search", get(search_page))
        .route("/publish", get(publish_guide))
        // Auth routes
        .route(
            "/login",
            get(auth_routes::login_page).post(auth_routes::login_submit),
        )
        .route("/logout", post(auth_routes::logout))
        .route(
            "/register",
            get(auth_routes::register_page).post(auth_routes::register_submit),
        )
        .route("/auth/github", get(auth_routes::github_redirect))
        .route("/auth/github/callback", get(auth_routes::github_callback))
        .route(
            "/device",
            get(auth_routes::device_page).post(auth_routes::device_authorize),
        )
        // Settings routes
        .route(
            "/settings/tokens",
            get(settings::tokens_page).post(settings::create_token),
        )
        .route("/settings/tokens/revoke", post(settings::revoke_token))
        // Module routes: /@scope/name and /@scope/name/version
        .route("/{*path}", get(module_or_version))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    search_query: String,
    user: Option<SessionUser>,
    recent_modules: Vec<SearchHit>,
    module_count: u64,
}

#[derive(Template)]
#[template(path = "search.html")]
struct SearchTemplate {
    search_query: String,
    user: Option<SessionUser>,
    results: Vec<SearchHit>,
    total: u64,
}

#[derive(Template)]
#[template(path = "module.html")]
struct ModuleTemplate {
    search_query: String,
    user: Option<SessionUser>,
    module: ModuleInfo,
}

#[derive(Template)]
#[template(path = "version.html")]
struct VersionTemplate {
    search_query: String,
    user: Option<SessionUser>,
    module_name: String,
    version: VersionInfo,
    base_url: String,
}

#[derive(Template)]
#[template(path = "publish.html")]
struct PublishTemplate {
    search_query: String,
    user: Option<SessionUser>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET / — Landing page with recently published modules.
async fn index(
    State(state): State<Arc<AppState>>,
    MaybeUser(user): MaybeUser,
) -> Result<Response, RegistryError> {
    let recent = state.db.list_recent_modules(20)?;
    let module_count = state.db.count_modules()?;
    render_template(&IndexTemplate {
        search_query: String::new(),
        user,
        recent_modules: recent,
        module_count,
    })
}

/// Search query parameters.
#[derive(serde::Deserialize)]
struct SearchParams {
    q: Option<String>,
}

/// GET /search?q=... — Search results page.
async fn search_page(
    State(state): State<Arc<AppState>>,
    MaybeUser(user): MaybeUser,
    Query(params): Query<SearchParams>,
) -> Result<Response, RegistryError> {
    let query = params.q.unwrap_or_default();
    if query.is_empty() {
        return Ok(Redirect::to("/").into_response());
    }

    let resp = state.db.search(&query, 50)?;
    render_template(&SearchTemplate {
        search_query: query,
        user,
        results: resp.results,
        total: resp.total,
    })
}

/// GET /publish — Publishing guide page.
async fn publish_guide(MaybeUser(user): MaybeUser) -> Result<Response, StatusCode> {
    render_template(&PublishTemplate {
        search_query: String::new(),
        user,
    })
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// GET /{*path} — Serves module page or version page based on path segments.
async fn module_or_version(
    State(state): State<Arc<AppState>>,
    MaybeUser(user): MaybeUser,
    Path(path): Path<String>,
) -> Result<Response, RegistryError> {
    let parts: Vec<&str> = path.split('/').collect();

    match parts.as_slice() {
        [scope, name] => {
            let module_name = format!("{scope}/{name}");
            let module = state.db.get_module(&module_name)?;
            render_template(&ModuleTemplate {
                search_query: String::new(),
                user,
                module,
            })
        }
        [scope, name, version] => {
            let module_name = format!("{scope}/{name}");
            let module = state.db.get_module(&module_name)?;
            let ver = module
                .versions
                .into_iter()
                .find(|v| v.version == *version)
                .ok_or_else(|| RegistryError::VersionNotFound {
                    module: module_name.clone(),
                    version: version.to_string(),
                })?;

            render_template(&VersionTemplate {
                search_query: String::new(),
                user,
                module_name,
                version: ver,
                base_url: String::new(),
            })
        }
        _ => Err(RegistryError::NotFound(format!("Page not found: /{path}"))),
    }
}
