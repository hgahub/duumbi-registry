# duumbi-registry

Registry server for [duumbi](https://github.com/hgahub/duumbi) modules. Stores, serves, and indexes `.tar.gz` module packages via a REST API.

## Quick Start

```bash
docker compose up -d
```

The registry is now available at `http://localhost:8080`.

Verify:

```bash
curl http://localhost:8080/health
# ok
```

## API

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/modules/@scope/name` | No | Module info (all versions) |
| GET | `/api/v1/modules/@scope/name/ver/download` | No | Download `.tar.gz` |
| PUT | `/api/v1/modules/@scope/name` | Bearer | Publish new version |
| DELETE | `/api/v1/modules/@scope/name/ver` | Bearer | Yank version |
| GET | `/api/v1/search?q=text` | No | Search modules |
| GET | `/health` | No | Health check |

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DUUMBI_PORT` | `8080` | Server listen port |
| `DUUMBI_DB` | `registry.db` | SQLite database path |
| `DUUMBI_STORAGE` | `storage` | Module archive directory |
| `RUST_LOG` | `duumbi_registry=info` | Log level ([tracing](https://docs.rs/tracing-subscriber)) |

### docker-compose.yml override example

```yaml
services:
  registry:
    build: .
    ports:
      - "9090:8080"
    volumes:
      - ./my-data:/data
    environment:
      - RUST_LOG=duumbi_registry=debug,tower_http=debug
```

## Self-Hosted Deployment

### Prerequisites

- Docker and Docker Compose v2+
- (Optional) Reverse proxy for TLS (nginx, Caddy, Traefik)

### TLS with reverse proxy (Caddy example)

```
registry.mycompany.com {
    reverse_proxy localhost:8080
}
```

### Data persistence

All data is stored under `/data` in the container:

- `/data/registry.db` — SQLite database (modules, versions, tokens)
- `/data/modules/` — `.tar.gz` archives organized by `@scope/name/version.tar.gz`

The `docker-compose.yml` uses a named volume (`registry-data`) that persists across container restarts and rebuilds.

### Backup & Restore

```bash
# Backup
docker compose exec registry cp /data/registry.db /data/registry.db.bak
docker compose cp registry:/data ./backup

# Restore
docker compose down
docker compose cp ./backup/. registry:/data
docker compose up -d
```

### Authentication

The registry supports two authentication modes, controlled by the `AUTH_MODE` environment variable:

| Mode | Use case | How users register |
|------|----------|-------------------|
| `local_password` (default) | Self-hosted / private | Web registration form at `/register` |
| `github_oauth` | Global (`registry.duumbi.dev`) | "Sign in with GitHub" on the web UI |

**Self-hosted setup (local_password):**

```bash
# Generate a JWT secret (required)
export JWT_SECRET=$(openssl rand -hex 32)

# Start the registry
docker compose up -d
```

Users register at `http://localhost:8080/register`, then manage API tokens at `/settings/tokens`.

**GitHub OAuth setup (github_oauth):**

1. Create a GitHub OAuth App at https://github.com/settings/developers
2. Set callback URL to `https://your-registry.example.com/auth/github/callback`
3. Configure environment variables:

```bash
AUTH_MODE=github_oauth
GITHUB_CLIENT_ID=your_client_id
GITHUB_CLIENT_SECRET=your_client_secret
JWT_SECRET=$(openssl rand -hex 32)
BASE_URL=https://your-registry.example.com
```

### User management (API tokens)

Users manage their own tokens via the web UI at `/settings/tokens`. Tokens are SHA-256 hashed in the database — raw tokens are shown once at creation.

CLI authentication:

```bash
# Device code flow (GitHub OAuth registries)
duumbi registry login myregistry
# → Opens browser, enter code, CLI receives token automatically

# Manual token (any registry)
duumbi registry login myregistry --token duu_your_token_here
```

## Client Configuration

On the duumbi client side, add the private registry to your workspace:

```bash
# Add registry
duumbi registry add company https://registry.mycompany.com

# Login (stores token in ~/.duumbi/credentials.toml)
duumbi registry login company --token duu_your_token_here

# Add a dependency from the private registry
duumbi deps add @company/my-module

# Publish to the private registry
duumbi publish --registry company
```

Or edit `.duumbi/config.toml` directly:

```toml
[registries]
company = "https://registry.mycompany.com"

[dependencies]
"@company/my-module" = { version = "1.0.0", registry = "company" }
```

## Development

```bash
# Build
cargo build

# Run locally
cargo run -- --port 8080 --db dev.db --storage-dir dev-storage

# Run tests
cargo test

# Clippy
cargo clippy --all-targets -- -D warnings
```

## License

MPL-2.0
