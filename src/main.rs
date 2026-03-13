//! duumbi-registry — Registry server binary entry point.

use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use duumbi_registry::{AppState, AuthMode, build_app, db, storage};

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("duumbi_registry=info,tower_http=info")),
        )
        .init();

    let args = Args::parse();

    // Auth configuration from environment
    let auth_mode = AuthMode::from_env_value(&std::env::var("AUTH_MODE").unwrap_or_default());
    let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
        tracing::warn!(
            "JWT_SECRET not set — using insecure default. Set JWT_SECRET in production!"
        );
        "duumbi-dev-secret-change-me".to_string()
    });
    let base_url =
        std::env::var("BASE_URL").unwrap_or_else(|_| format!("http://localhost:{}", args.port));
    let github_client_id = std::env::var("GITHUB_CLIENT_ID").ok();
    let github_client_secret = std::env::var("GITHUB_CLIENT_SECRET").ok();

    if matches!(auth_mode, AuthMode::GithubOauth) {
        if github_client_id.is_none() || github_client_secret.is_none() {
            anyhow::bail!(
                "AUTH_MODE=github_oauth requires GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET"
            );
        }
        tracing::info!("Auth mode: GitHub OAuth2");
    } else {
        tracing::info!("Auth mode: local password");
    }

    let database = db::Database::open(&args.db)?;
    database.migrate()?;

    let storage = storage::Storage::new(&args.storage_dir)?;

    let state = Arc::new(AppState {
        db: database,
        storage,
        auth_mode,
        jwt_secret,
        base_url,
        github_client_id,
        github_client_secret,
        rate_limiter: duumbi_registry::auth::rate_limit::RateLimiter::new(),
    });

    let app = build_app(Arc::clone(&state));

    // Background cleanup task for expired device codes
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                match state.db.cleanup_expired_device_codes() {
                    Ok(count) if count > 0 => {
                        tracing::debug!("Cleaned up {count} expired device codes");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("Device code cleanup failed: {e}");
                    }
                }
            }
        });
    }

    let addr = format!("0.0.0.0:{}", args.port);
    tracing::info!("Registry server listening on {addr}");

    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
