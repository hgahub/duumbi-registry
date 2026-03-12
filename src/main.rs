//! duumbi-registry — Registry server for duumbi modules.
//!
//! Serves the `registry.duumbi.dev` API. Stores module archives (.tar.gz)
//! and metadata in SQLite with filesystem blob storage.

mod api;
mod auth;
mod db;
mod error;
mod storage;
mod types;
mod web;

use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

/// duumbi-registry — Module registry server.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Port to listen on.
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Path to the SQLite database file.
    #[arg(long, default_value = "registry.db")]
    db: String,

    /// Path to the module storage directory.
    #[arg(long, default_value = "storage")]
    storage_dir: String,
}

/// Shared application state passed to all handlers.
pub struct AppState {
    /// Database connection pool.
    pub db: db::Database,
    /// Module archive storage.
    pub storage: storage::Storage,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("duumbi_registry=info,tower_http=info")),
        )
        .init();

    let args = Args::parse();

    let database = db::Database::open(&args.db)?;
    database.migrate()?;

    let storage = storage::Storage::new(&args.storage_dir)?;

    let state = Arc::new(AppState {
        db: database,
        storage,
    });

    let app = api::router(state.clone()).merge(web::router(state));

    let addr = format!("0.0.0.0:{}", args.port);
    tracing::info!("Registry server listening on {addr}");

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
