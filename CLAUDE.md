# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Registry server for [duumbi](https://github.com/hgahub/duumbi) modules. A Rust/Axum web application that stores, serves, and indexes `.tar.gz` module packages via a REST API and a server-rendered HTML frontend.

## Build & Development Commands

```bash
cargo build                                    # Build
cargo run -- --port 8080 --db dev.db --storage-dir dev-storage  # Run locally
cargo test                                     # Run all tests (includes e2e)
cargo test <test_name>                         # Run a single test
cargo clippy --all-targets -- -D warnings      # Lint (treat warnings as errors)
docker compose up -d                           # Run via Docker
```

## Architecture

**Rust crate structured as a library (`lib.rs`) + binary (`main.rs`).** The library exposes `build_app()` so integration tests can spin up embedded servers without going through main.

### Key modules (`src/`)

- **`api/`** — REST API handlers (`/api/v1/modules/...`, `/api/v1/search`, `/api/v1/auth/...`, `/health`). Consumed by the duumbi CLI.
- **`web/`** — Server-rendered HTML frontend using Askama templates. Includes `auth_routes.rs` (login/register/OAuth flows) and `settings.rs` (token management). Templates live in `templates/`.
- **`db/`** — SQLite database layer via `rusqlite`. Single `Database` struct wrapping `Mutex<Connection>`. Migrations are versioned and applied in code (not SQL files). Stores modules, versions, users, OAuth accounts, device codes, and auth tokens. Archives live on the filesystem, not in the DB.
- **`storage/`** — Filesystem storage for `.tar.gz` module archives, organized as `@scope/name/version.tar.gz`.
- **`auth/`** — Authentication subsystem:
  - `jwt.rs` — JWT session tokens for web UI
  - `password.rs` — Argon2 password hashing (local_password mode)
  - `oauth.rs` — GitHub OAuth2 flow (github_oauth mode)
  - `device_code.rs` — Device code flow for CLI login
  - `session.rs` — Cookie-based session extraction (`SessionUser`, `MaybeUser`)
  - `rate_limit.rs` — In-memory rate limiter for auth endpoints
- **`error.rs`** — `RegistryError` enum with `IntoResponse` impl mapping variants to HTTP status codes.
- **`types.rs`** — Shared API types (serialized as JSON).

### Auth modes

Controlled by `AUTH_MODE` env var:
- `local_password` (default) — username/password registration at `/register`
- `github_oauth` — GitHub OAuth2, requires `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `JWT_SECRET`, `BASE_URL`

### Testing

Integration tests in `tests/e2e.rs` spin up embedded axum servers with in-memory SQLite and temp directories. They exercise the API via `reqwest` HTTP calls. No mocking — tests hit real (in-memory) databases.

### Config (env vars)

`DUUMBI_PORT`, `DUUMBI_DB`, `DUUMBI_STORAGE`, `RUST_LOG`, `AUTH_MODE`, `JWT_SECRET`, `BASE_URL`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`.
