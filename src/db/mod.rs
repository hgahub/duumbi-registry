//! Database layer backed by SQLite.
//!
//! Stores module metadata, versions, users, OAuth accounts, device codes,
//! and auth tokens. The actual `.tar.gz` archives live on the filesystem
//! (see `storage`).
//!
//! Uses a versioned migration system: each migration is applied once,
//! tracked in the `schema_version` table.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::error::RegistryError;
use crate::types::{ModuleInfo, SearchHit, SearchResponse, VersionInfo};

/// SQLite database wrapper with interior mutability.
pub struct Database {
    conn: Mutex<Connection>,
}

// ---------------------------------------------------------------------------
// User types
// ---------------------------------------------------------------------------

/// A registered user.
#[derive(Debug, Clone)]
pub struct User {
    /// Database-assigned user ID.
    pub id: i64,
    /// Unique username (GitHub login or self-chosen).
    pub username: String,
    /// Optional display name.
    pub display_name: Option<String>,
    /// Avatar URL (from GitHub or gravatar).
    pub avatar_url: Option<String>,
    /// Email address (may be private).
    pub email: Option<String>,
    /// Argon2 password hash (None for OAuth-only users).
    pub password_hash: Option<String>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// ISO-8601 last-update timestamp.
    pub updated_at: String,
}

/// Parameters for creating a new user.
pub struct CreateUser<'a> {
    /// Unique username.
    pub username: &'a str,
    /// Optional display name.
    pub display_name: Option<&'a str>,
    /// Optional avatar URL.
    pub avatar_url: Option<&'a str>,
    /// Optional email.
    pub email: Option<&'a str>,
    /// Optional password hash (for local_password mode).
    pub password_hash: Option<&'a str>,
}

/// A stored API token (metadata only — the raw token is never persisted).
#[derive(Debug, Clone)]
pub struct TokenRecord {
    /// Database-assigned token ID.
    pub id: i64,
    /// Owning user ID.
    pub user_id: i64,
    /// User-chosen name for the token.
    pub token_name: String,
    /// First 8 characters of the raw token for display.
    pub token_prefix: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// ISO-8601 timestamp of last API call with this token.
    pub last_used_at: Option<String>,
}

/// A stored device code for CLI authentication flow.
#[derive(Debug, Clone)]
pub struct DeviceCodeRecord {
    /// Current status: "pending", "authorized", or "expired".
    pub status: String,
    /// User-facing code (e.g., "ABCD-1234").
    pub user_code: String,
    /// User who authorized (set when status becomes "authorized").
    pub user_id: Option<i64>,
    /// SHA-256 hash of the generated token (set on authorization).
    pub token_hash: Option<String>,
    /// ISO-8601 expiration timestamp.
    pub expires_at: String,
}

impl Database {
    /// Opens (or creates) a SQLite database at the given path.
    pub fn open(path: &str) -> Result<Self, RegistryError> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            let db_path = Path::new(path);
            if let Some(parent) = db_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // SQLITE_NO_LOCK=1 selects the unix-none VFS which disables all
            // POSIX file locking. Required for Azure Files (SMB) mounts which
            // do not support POSIX locking. On normal filesystems (Docker
            // volumes, local disk) leave locking enabled so WAL recovery works.
            let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
            if std::env::var("SQLITE_NO_LOCK").as_deref() == Ok("1") {
                Connection::open_with_flags_and_vfs(db_path, flags, "unix-none")?
            } else {
                Connection::open_with_flags(db_path, flags)?
            }
        };

        // busy_timeout: retry for up to 5 s before returning SQLITE_BUSY.
        // Without this, the background cleanup task and HTTP request handlers
        // race on the connection and one immediately fails with "database is
        // locked" instead of waiting for the other to finish.
        conn.execute_batch(
            "PRAGMA journal_mode=DELETE; \
             PRAGMA foreign_keys=ON; \
             PRAGMA busy_timeout=5000;",
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    // -----------------------------------------------------------------------
    // Migrations
    // -----------------------------------------------------------------------

    /// Runs database migrations up to the latest version.
    ///
    /// Each migration is applied exactly once. The `schema_version` table
    /// tracks which migrations have been applied.
    pub fn migrate(&self) -> Result<(), RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");

        // Bootstrap: ensure schema_version table exists
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version  INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );",
        )?;

        let current: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        for (version, sql) in MIGRATIONS {
            if *version > current {
                tracing::info!("Applying migration v{version}");
                conn.execute_batch(sql)?;
                let now = chrono::Utc::now().to_rfc3339();
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
                    rusqlite::params![version, now],
                )?;
            }
        }

        // Schema repair: add `revoked` column to `tokens` if it was created
        // by an intermediate version of migration 002 that lacked it.
        // SQLite does not support ALTER TABLE ADD COLUMN IF NOT EXISTS, so we
        // check via PRAGMA first and only run ALTER TABLE when needed.
        // The PRAGMA query is propagated as a real error rather than silenced
        // with unwrap_or, so genuine schema corruption is surfaced immediately.
        let has_revoked: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('tokens') WHERE name = 'revoked'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(RegistryError::Database)?
            > 0;

        if !has_revoked {
            tracing::warn!(
                "tokens.revoked column missing — applying schema repair (ALTER TABLE ADD COLUMN)"
            );
            conn.execute_batch("ALTER TABLE tokens ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0")?;
        }

        Ok(())
    }

    /// Returns the current schema version.
    #[cfg(test)]
    fn schema_version(&self) -> i64 {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");
        conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // Modules
    // -----------------------------------------------------------------------

    /// Fetches module info with all versions.
    pub fn get_module(&self, name: &str) -> Result<ModuleInfo, RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");

        let mut stmt = conn.prepare("SELECT description FROM modules WHERE name = ?1")?;

        let description: Option<String> = stmt
            .query_row([name], |row| row.get(0))
            .map_err(|_| RegistryError::NotFound(name.to_string()))?;

        let mut vstmt = conn.prepare(
            "SELECT version, integrity, yanked, published_at \
             FROM versions WHERE module_name = ?1 ORDER BY published_at DESC",
        )?;

        let versions: Vec<VersionInfo> = vstmt
            .query_map([name], |row| {
                Ok(VersionInfo {
                    version: row.get(0)?,
                    integrity: row.get(1)?,
                    yanked: row.get(2)?,
                    published_at: row.get(3)?,
                })
            })?
            .filter_map(Result::ok)
            .collect();

        Ok(ModuleInfo {
            name: name.to_string(),
            description,
            versions,
        })
    }

    /// Inserts a new module (if not exists) and a new version.
    pub fn publish_version(
        &self,
        name: &str,
        description: Option<&str>,
        version: &str,
        integrity: &str,
    ) -> Result<(), RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");

        // Check for duplicate version
        let exists: bool = conn
            .prepare("SELECT 1 FROM versions WHERE module_name = ?1 AND version = ?2")?
            .exists([name, version])?;

        if exists {
            return Err(RegistryError::VersionConflict {
                module: name.to_string(),
                version: version.to_string(),
            });
        }

        // Upsert module
        conn.execute(
            "INSERT INTO modules (name, description) VALUES (?1, ?2) \
             ON CONFLICT(name) DO UPDATE SET description = COALESCE(?2, description)",
            rusqlite::params![name, description],
        )?;

        // Insert version
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO versions (module_name, version, integrity, yanked, published_at) \
             VALUES (?1, ?2, ?3, 0, ?4)",
            rusqlite::params![name, version, integrity, now],
        )?;

        Ok(())
    }

    /// Marks a version as yanked.
    pub fn yank_version(&self, name: &str, version: &str) -> Result<(), RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");

        let updated = conn.execute(
            "UPDATE versions SET yanked = 1 WHERE module_name = ?1 AND version = ?2",
            [name, version],
        )?;

        if updated == 0 {
            return Err(RegistryError::VersionNotFound {
                module: name.to_string(),
                version: version.to_string(),
            });
        }

        Ok(())
    }

    /// Lists the most recently published modules (by latest version timestamp).
    pub fn list_recent_modules(&self, limit: u32) -> Result<Vec<SearchHit>, RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");

        let mut stmt = conn.prepare(
            "SELECT m.name, m.description, \
                    (SELECT v.version FROM versions v \
                     WHERE v.module_name = m.name AND v.yanked = 0 \
                     ORDER BY v.published_at DESC LIMIT 1) as latest, \
                    (SELECT MAX(v.published_at) FROM versions v \
                     WHERE v.module_name = m.name) as last_pub \
             FROM modules m \
             ORDER BY last_pub DESC \
             LIMIT ?1",
        )?;

        let results: Vec<SearchHit> = stmt
            .query_map(rusqlite::params![limit], |row| {
                Ok(SearchHit {
                    name: row.get(0)?,
                    description: row.get(1)?,
                    latest_version: row
                        .get::<_, Option<String>>(2)?
                        .unwrap_or_else(|| "0.0.0".to_string()),
                })
            })?
            .filter_map(Result::ok)
            .collect();

        Ok(results)
    }

    /// Searches modules by name or description.
    pub fn search(&self, query: &str, limit: u32) -> Result<SearchResponse, RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");

        let pattern = format!("%{query}%");

        let mut stmt = conn.prepare(
            "SELECT m.name, m.description, \
                    (SELECT v.version FROM versions v \
                     WHERE v.module_name = m.name AND v.yanked = 0 \
                     ORDER BY v.published_at DESC LIMIT 1) as latest \
             FROM modules m \
             WHERE m.name LIKE ?1 OR m.description LIKE ?1 \
             LIMIT ?2",
        )?;

        let results: Vec<SearchHit> = stmt
            .query_map(rusqlite::params![pattern, limit], |row| {
                Ok(SearchHit {
                    name: row.get(0)?,
                    description: row.get(1)?,
                    latest_version: row
                        .get::<_, Option<String>>(2)?
                        .unwrap_or_else(|| "0.0.0".to_string()),
                })
            })?
            .filter_map(Result::ok)
            .collect();

        let total = results.len() as u64;

        Ok(SearchResponse { results, total })
    }

    // -----------------------------------------------------------------------
    // Users (#195)
    // -----------------------------------------------------------------------

    /// Creates a new user. Returns the user ID.
    pub fn create_user(&self, params: &CreateUser<'_>) -> Result<i64, RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");
        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO users (username, display_name, avatar_url, email, password_hash, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                params.username,
                params.display_name,
                params.avatar_url,
                params.email,
                params.password_hash,
                now,
                now,
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Looks up a user by ID.
    pub fn get_user_by_id(&self, id: i64) -> Result<User, RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");

        conn.query_row(
            "SELECT id, username, display_name, avatar_url, email, password_hash, created_at, updated_at \
             FROM users WHERE id = ?1",
            [id],
            |row| {
                Ok(User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    display_name: row.get(2)?,
                    avatar_url: row.get(3)?,
                    email: row.get(4)?,
                    password_hash: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            },
        )
        .map_err(|_| RegistryError::NotFound(format!("User ID {id}")))
    }

    /// Looks up a user by username.
    pub fn get_user_by_username(&self, username: &str) -> Result<User, RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");

        conn.query_row(
            "SELECT id, username, display_name, avatar_url, email, password_hash, created_at, updated_at \
             FROM users WHERE username = ?1",
            [username],
            |row| {
                Ok(User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    display_name: row.get(2)?,
                    avatar_url: row.get(3)?,
                    email: row.get(4)?,
                    password_hash: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            },
        )
        .map_err(|_| RegistryError::NotFound(format!("User '{username}'")))
    }

    /// Updates a user's profile fields (display_name, avatar_url, email).
    pub fn update_user(
        &self,
        id: i64,
        display_name: Option<&str>,
        avatar_url: Option<&str>,
        email: Option<&str>,
    ) -> Result<(), RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");
        let now = chrono::Utc::now().to_rfc3339();

        let updated = conn.execute(
            "UPDATE users SET display_name = ?2, avatar_url = ?3, email = ?4, updated_at = ?5 \
             WHERE id = ?1",
            rusqlite::params![id, display_name, avatar_url, email, now],
        )?;

        if updated == 0 {
            return Err(RegistryError::NotFound(format!("User ID {id}")));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // OAuth accounts (#200)
    // -----------------------------------------------------------------------

    /// Finds or creates a user via OAuth provider.
    ///
    /// If an `oauth_accounts` row exists for `(provider, provider_id)`, updates
    /// the access token and returns the linked user. Otherwise creates a new
    /// user and links the OAuth account.
    pub fn find_or_create_oauth_user(
        &self,
        provider: &str,
        provider_id: &str,
        username: &str,
        avatar_url: Option<&str>,
        email: Option<&str>,
        access_token: Option<&str>,
    ) -> Result<User, RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");
        let now = chrono::Utc::now().to_rfc3339();

        // Check if OAuth account already exists
        let existing_user_id: Option<i64> = conn
            .prepare("SELECT user_id FROM oauth_accounts WHERE provider = ?1 AND provider_id = ?2")?
            .query_row(rusqlite::params![provider, provider_id], |row| row.get(0))
            .ok();

        let user_id = if let Some(uid) = existing_user_id {
            // Update access token and user profile
            conn.execute(
                "UPDATE oauth_accounts SET access_token = ?3 \
                 WHERE provider = ?1 AND provider_id = ?2",
                rusqlite::params![provider, provider_id, access_token],
            )?;
            conn.execute(
                "UPDATE users SET avatar_url = ?2, email = ?3, updated_at = ?4 WHERE id = ?1",
                rusqlite::params![uid, avatar_url, email, now],
            )?;
            uid
        } else {
            // Create new user
            conn.execute(
                "INSERT INTO users (username, display_name, avatar_url, email, password_hash, created_at, updated_at) \
                 VALUES (?1, ?1, ?2, ?3, NULL, ?4, ?5)",
                rusqlite::params![username, avatar_url, email, now, now],
            )?;
            let uid = conn.last_insert_rowid();

            // Link OAuth account
            conn.execute(
                "INSERT INTO oauth_accounts (user_id, provider, provider_id, access_token, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![uid, provider, provider_id, access_token, now],
            )?;

            uid
        };

        // Fetch and return full user
        drop(conn);
        self.get_user_by_id(user_id)
    }

    // -----------------------------------------------------------------------
    // Tokens (#198, #204)
    // -----------------------------------------------------------------------

    /// Validates an API token. Returns the username if valid.
    ///
    /// The incoming raw token is SHA-256 hashed before lookup.
    /// Updates `last_used_at` on success.
    pub fn validate_token(&self, raw_token: &str) -> Result<String, RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");
        let hash = hash_token(raw_token);

        let (token_id, user_id): (i64, i64) = conn
            .prepare("SELECT id, user_id FROM tokens WHERE token_hash = ?1 AND revoked = 0")?
            .query_row([&hash], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|_| RegistryError::AuthFailed("Invalid or revoked token".to_string()))?;

        // Update last_used_at
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE tokens SET last_used_at = ?2 WHERE id = ?1",
            rusqlite::params![token_id, now],
        )?;

        // Look up username
        let username: String = conn
            .query_row(
                "SELECT username FROM users WHERE id = ?1",
                [user_id],
                |row| row.get(0),
            )
            .map_err(|_| RegistryError::AuthFailed("User not found for token".to_string()))?;

        Ok(username)
    }

    /// Creates a new API token for a user.
    ///
    /// Stores the SHA-256 hash and first 8 chars of the raw token.
    /// The raw token must be generated by the caller and shown to the user
    /// exactly once.
    pub fn create_token(
        &self,
        user_id: i64,
        token_name: &str,
        raw_token: &str,
    ) -> Result<i64, RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");
        let now = chrono::Utc::now().to_rfc3339();
        let hash = hash_token(raw_token);
        let prefix = &raw_token[..raw_token.len().min(12)];

        conn.execute(
            "INSERT INTO tokens (user_id, token_name, token_hash, token_prefix, created_at, revoked) \
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            rusqlite::params![user_id, token_name, hash, prefix, now],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Lists all tokens for a user (metadata only, never raw tokens).
    pub fn list_tokens(&self, user_id: i64) -> Result<Vec<TokenRecord>, RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");

        let mut stmt = conn.prepare(
            "SELECT id, user_id, token_name, token_prefix, created_at, last_used_at \
             FROM tokens WHERE user_id = ?1 AND revoked = 0 ORDER BY created_at DESC",
        )?;

        let tokens = stmt
            .query_map([user_id], |row| {
                Ok(TokenRecord {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    token_name: row.get(2)?,
                    token_prefix: row.get(3)?,
                    created_at: row.get(4)?,
                    last_used_at: row.get(5)?,
                })
            })?
            .filter_map(Result::ok)
            .collect();

        Ok(tokens)
    }

    /// Revokes a token by ID (must belong to the given user).
    pub fn revoke_token(&self, token_id: i64, user_id: i64) -> Result<bool, RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");

        let updated = conn.execute(
            "UPDATE tokens SET revoked = 1 WHERE id = ?1 AND user_id = ?2",
            rusqlite::params![token_id, user_id],
        )?;

        Ok(updated > 0)
    }

    // -----------------------------------------------------------------------
    // Device codes (#201)
    // -----------------------------------------------------------------------

    /// Stores a new device code for CLI authentication.
    ///
    /// Expired and pending device codes are purged before inserting the new
    /// record to avoid `UNIQUE` constraint violations on `user_code` when a
    /// user retries the device-code login flow.
    pub fn create_device_code(
        &self,
        device_code: &str,
        user_code: &str,
        expires_at: &str,
    ) -> Result<(), RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");
        let now = chrono::Utc::now().to_rfc3339();

        // Remove only expired codes so the UNIQUE(user_code) constraint cannot
        // trigger a spurious HTTP 500 when a user retries login after expiry.
        // Active pending codes from concurrent sessions are intentionally left
        // untouched — deleting all pending rows would invalidate other users'
        // in-progress device-code flows.
        conn.execute(
            "DELETE FROM device_codes WHERE expires_at < ?1",
            rusqlite::params![now],
        )?;

        conn.execute(
            "INSERT INTO device_codes (device_code, user_code, status, user_id, token_hash, expires_at, created_at) \
             VALUES (?1, ?2, 'pending', NULL, NULL, ?3, ?4)",
            rusqlite::params![device_code, user_code, expires_at, now],
        )?;

        Ok(())
    }

    /// Looks up a device code by its device_code value.
    pub fn get_device_code(&self, device_code: &str) -> Result<DeviceCodeRecord, RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");

        conn.query_row(
            "SELECT status, user_code, user_id, token_hash, expires_at FROM device_codes WHERE device_code = ?1",
            [device_code],
            |row| Ok(DeviceCodeRecord {
                status: row.get(0)?,
                user_code: row.get(1)?,
                user_id: row.get(2)?,
                token_hash: row.get(3)?,
                expires_at: row.get(4)?,
            }),
        )
        .map_err(|_| RegistryError::NotFound("Device code not found".to_string()))
    }

    /// Authorizes a device code: sets status to "authorized", links user,
    /// and stores the raw token temporarily for CLI retrieval.
    ///
    /// The raw token is stored in `device_codes.token_hash` (despite the name)
    /// so the polling endpoint can return it to the CLI. The actual hashed
    /// version is stored in the `tokens` table.
    pub fn authorize_device_code(
        &self,
        user_code: &str,
        user_id: i64,
        raw_token: &str,
        token_name: &str,
    ) -> Result<bool, RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");
        let now = chrono::Utc::now().to_rfc3339();
        let token_hash = hash_token(raw_token);
        let token_prefix = &raw_token[..raw_token.len().min(12)];

        // Store RAW token in device_codes for CLI retrieval (temporary)
        let updated = conn.execute(
            "UPDATE device_codes SET status = 'authorized', user_id = ?2, token_hash = ?3 \
             WHERE user_code = ?1 AND status = 'pending' AND expires_at > ?4",
            rusqlite::params![user_code, user_id, raw_token, now],
        )?;

        if updated == 0 {
            return Ok(false);
        }

        // Also create the token in the tokens table
        conn.execute(
            "INSERT INTO tokens (user_id, token_name, token_hash, token_prefix, created_at, revoked) \
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            rusqlite::params![user_id, token_name, token_hash, token_prefix, now],
        )?;

        Ok(true)
    }

    /// Deletes expired device codes (for cleanup task).
    pub fn cleanup_expired_device_codes(&self) -> Result<usize, RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");
        let now = chrono::Utc::now().to_rfc3339();

        let deleted = conn.execute(
            "DELETE FROM device_codes WHERE expires_at < ?1",
            rusqlite::params![now],
        )?;

        Ok(deleted)
    }
}

// ---------------------------------------------------------------------------
// Token hashing
// ---------------------------------------------------------------------------

/// Computes the SHA-256 hex digest of a raw token string.
fn hash_token(raw: &str) -> String {
    format!("{:x}", Sha256::digest(raw.as_bytes()))
}

// ---------------------------------------------------------------------------
// Migrations
// ---------------------------------------------------------------------------

/// Ordered list of migrations. Each entry is `(version, sql)`.
const MIGRATIONS: &[(i64, &str)] = &[(1, MIGRATION_001), (2, MIGRATION_002)];

/// Migration 001: Original schema (modules, versions, tokens).
const MIGRATION_001: &str = r#"
CREATE TABLE IF NOT EXISTS modules (
    name        TEXT PRIMARY KEY,
    description TEXT
);

CREATE TABLE IF NOT EXISTS versions (
    module_name  TEXT NOT NULL REFERENCES modules(name),
    version      TEXT NOT NULL,
    integrity    TEXT NOT NULL,
    yanked       INTEGER NOT NULL DEFAULT 0,
    published_at TEXT,
    PRIMARY KEY (module_name, version)
);

CREATE INDEX IF NOT EXISTS idx_versions_module ON versions(module_name);
"#;

/// Migration 002: Auth schema (users, oauth_accounts, device_codes, new tokens).
const MIGRATION_002: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    display_name  TEXT,
    avatar_url    TEXT,
    email         TEXT,
    password_hash TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_accounts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    provider      TEXT NOT NULL,
    provider_id   TEXT NOT NULL,
    access_token  TEXT,
    created_at    TEXT NOT NULL,
    UNIQUE(provider, provider_id)
);
CREATE INDEX IF NOT EXISTS idx_oauth_provider ON oauth_accounts(provider, provider_id);

CREATE TABLE IF NOT EXISTS device_codes (
    device_code   TEXT PRIMARY KEY,
    user_code     TEXT NOT NULL UNIQUE,
    status        TEXT NOT NULL DEFAULT 'pending',
    user_id       INTEGER REFERENCES users(id),
    token_hash    TEXT,
    expires_at    TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code);

-- Replace the old tokens table with a user-linked, hash-based version.
-- The old table stored raw tokens with a username column.
-- The new table stores SHA-256 hashes and links to users.id.
DROP TABLE IF EXISTS tokens;

CREATE TABLE tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    token_name   TEXT NOT NULL DEFAULT 'default',
    token_hash   TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id);
"#;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Database {
        let db = Database::open(":memory:").expect("in-memory db");
        db.migrate().expect("migration");
        db
    }

    // -- Migration tests (#194) --

    #[test]
    fn migrate_succeeds() {
        let db = Database::open(":memory:").expect("in-memory db");
        db.migrate().expect("migration");
    }

    #[test]
    fn migrate_is_idempotent() {
        let db = Database::open(":memory:").expect("in-memory db");
        db.migrate().expect("first migration");
        db.migrate().expect("second migration must also succeed");
        assert_eq!(db.schema_version(), 2);
    }

    #[test]
    fn schema_version_after_migrate() {
        let db = test_db();
        assert_eq!(db.schema_version(), 2);
    }

    // -- Module tests (existing) --

    #[test]
    fn publish_and_get_module() {
        let db = test_db();

        db.publish_version(
            "@test/example",
            Some("A test module"),
            "1.0.0",
            "sha256:abc",
        )
        .expect("publish");

        let info = db.get_module("@test/example").expect("get");
        assert_eq!(info.name, "@test/example");
        assert_eq!(info.description.as_deref(), Some("A test module"));
        assert_eq!(info.versions.len(), 1);
        assert_eq!(info.versions[0].version, "1.0.0");
        assert!(!info.versions[0].yanked);
    }

    #[test]
    fn duplicate_version_rejected() {
        let db = test_db();

        db.publish_version("@test/m", None, "1.0.0", "sha256:a")
            .expect("first publish");

        let err = db
            .publish_version("@test/m", None, "1.0.0", "sha256:b")
            .expect_err("duplicate");

        assert!(matches!(err, RegistryError::VersionConflict { .. }));
    }

    #[test]
    fn yank_version() {
        let db = test_db();

        db.publish_version("@test/m", None, "1.0.0", "sha256:a")
            .expect("publish");

        db.yank_version("@test/m", "1.0.0").expect("yank");

        let info = db.get_module("@test/m").expect("get");
        assert!(info.versions[0].yanked);
    }

    #[test]
    fn yank_nonexistent_version_fails() {
        let db = test_db();

        let err = db.yank_version("@test/m", "1.0.0").expect_err("not found");

        assert!(matches!(err, RegistryError::VersionNotFound { .. }));
    }

    #[test]
    fn search_by_name() {
        let db = test_db();

        db.publish_version(
            "@duumbi/stdlib-math",
            Some("Math functions"),
            "1.0.0",
            "sha256:a",
        )
        .expect("publish");
        db.publish_version("@duumbi/stdlib-io", Some("IO helpers"), "2.0.0", "sha256:b")
            .expect("publish");

        let resp = db.search("math", 10).expect("search");
        assert_eq!(resp.results.len(), 1);
        assert_eq!(resp.results[0].name, "@duumbi/stdlib-math");
    }

    // -- User tests (#195) --

    #[test]
    fn create_and_get_user() {
        let db = test_db();

        let user_id = db
            .create_user(&CreateUser {
                username: "alice",
                display_name: Some("Alice Smith"),
                avatar_url: Some("https://example.com/alice.png"),
                email: Some("alice@example.com"),
                password_hash: None,
            })
            .expect("create user");

        let user = db.get_user_by_id(user_id).expect("get by id");
        assert_eq!(user.username, "alice");
        assert_eq!(user.display_name.as_deref(), Some("Alice Smith"));
        assert!(user.password_hash.is_none());

        let user2 = db.get_user_by_username("alice").expect("get by username");
        assert_eq!(user2.id, user_id);
    }

    #[test]
    fn create_user_duplicate_username_fails() {
        let db = test_db();

        db.create_user(&CreateUser {
            username: "bob",
            display_name: None,
            avatar_url: None,
            email: None,
            password_hash: None,
        })
        .expect("first create");

        let err = db
            .create_user(&CreateUser {
                username: "bob",
                display_name: None,
                avatar_url: None,
                email: None,
                password_hash: None,
            })
            .expect_err("duplicate");

        // SQLite UNIQUE constraint violation
        assert!(matches!(err, RegistryError::Database(_)));
    }

    #[test]
    fn get_user_not_found() {
        let db = test_db();

        let err = db.get_user_by_id(999).expect_err("not found");
        assert!(matches!(err, RegistryError::NotFound(_)));

        let err = db.get_user_by_username("nobody").expect_err("not found");
        assert!(matches!(err, RegistryError::NotFound(_)));
    }

    #[test]
    fn update_user_profile() {
        let db = test_db();

        let uid = db
            .create_user(&CreateUser {
                username: "carol",
                display_name: None,
                avatar_url: None,
                email: None,
                password_hash: None,
            })
            .expect("create");

        db.update_user(
            uid,
            Some("Carol D."),
            Some("https://avatar.com/c"),
            Some("c@d.com"),
        )
        .expect("update");

        let user = db.get_user_by_id(uid).expect("get");
        assert_eq!(user.display_name.as_deref(), Some("Carol D."));
        assert_eq!(user.email.as_deref(), Some("c@d.com"));
    }

    // -- OAuth tests (#200) --

    #[test]
    fn oauth_user_creation_and_upsert() {
        let db = test_db();

        // First login — creates user
        let user = db
            .find_or_create_oauth_user(
                "github",
                "12345",
                "ghuser",
                Some("https://github.com/avatar"),
                Some("gh@example.com"),
                Some("gho_access_token_1"),
            )
            .expect("first login");
        assert_eq!(user.username, "ghuser");

        // Second login — updates access token
        let user2 = db
            .find_or_create_oauth_user(
                "github",
                "12345",
                "ghuser",
                Some("https://github.com/avatar2"),
                Some("gh@example.com"),
                Some("gho_access_token_2"),
            )
            .expect("second login");
        assert_eq!(user2.id, user.id);
        assert_eq!(
            user2.avatar_url.as_deref(),
            Some("https://github.com/avatar2")
        );
    }

    // -- Token tests (#198, #204) --

    #[test]
    fn hashed_token_create_and_validate() {
        let db = test_db();

        let uid = db
            .create_user(&CreateUser {
                username: "tokenuser",
                display_name: None,
                avatar_url: None,
                email: None,
                password_hash: None,
            })
            .expect("create user");

        let raw_token = "duu_abc123def456ghi789jkl012mno345";
        db.create_token(uid, "ci-deploy", raw_token)
            .expect("create token");

        let username = db.validate_token(raw_token).expect("validate");
        assert_eq!(username, "tokenuser");
    }

    #[test]
    fn invalid_token_rejected() {
        let db = test_db();

        let err = db.validate_token("duu_nonexistent").expect_err("invalid");
        assert!(matches!(err, RegistryError::AuthFailed(_)));
    }

    #[test]
    fn revoked_token_rejected() {
        let db = test_db();

        let uid = db
            .create_user(&CreateUser {
                username: "revoker",
                display_name: None,
                avatar_url: None,
                email: None,
                password_hash: None,
            })
            .expect("create user");

        let raw = "duu_revoke_test_token_abcdef12345";
        let token_id = db.create_token(uid, "temp", raw).expect("create");

        db.revoke_token(token_id, uid).expect("revoke");

        let err = db.validate_token(raw).expect_err("revoked");
        assert!(matches!(err, RegistryError::AuthFailed(_)));
    }

    #[test]
    fn list_tokens_for_user() {
        let db = test_db();

        let uid = db
            .create_user(&CreateUser {
                username: "lister",
                display_name: None,
                avatar_url: None,
                email: None,
                password_hash: None,
            })
            .expect("create");

        db.create_token(uid, "token-a", "duu_aaaa1111bbbb2222cccc3333")
            .expect("create a");
        db.create_token(uid, "token-b", "duu_dddd4444eeee5555ffff6666")
            .expect("create b");

        let tokens = db.list_tokens(uid).expect("list");
        assert_eq!(tokens.len(), 2);
        assert!(tokens.iter().any(|t| t.token_name == "token-a"));
        assert!(tokens.iter().any(|t| t.token_name == "token-b"));
        // Prefix is stored, not full hash
        assert!(tokens[0].token_prefix.starts_with("duu_"));
    }

    #[test]
    fn revoke_token_wrong_user_fails() {
        let db = test_db();

        let uid1 = db
            .create_user(&CreateUser {
                username: "user1",
                display_name: None,
                avatar_url: None,
                email: None,
                password_hash: None,
            })
            .expect("create user1");

        let uid2 = db
            .create_user(&CreateUser {
                username: "user2",
                display_name: None,
                avatar_url: None,
                email: None,
                password_hash: None,
            })
            .expect("create user2");

        let raw = "duu_cross_user_test_token_abc12345";
        let token_id = db.create_token(uid1, "mine", raw).expect("create");

        let revoked = db.revoke_token(token_id, uid2).expect("revoke attempt");
        assert!(!revoked, "other user must not revoke");

        // Token still valid
        let username = db.validate_token(raw).expect("still valid");
        assert_eq!(username, "user1");
    }

    // -- Device code tests (#201) --

    #[test]
    fn device_code_lifecycle() {
        let db = test_db();

        let uid = db
            .create_user(&CreateUser {
                username: "devuser",
                display_name: None,
                avatar_url: None,
                email: None,
                password_hash: None,
            })
            .expect("create user");

        let expires = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::minutes(15))
            .expect("invariant: time")
            .to_rfc3339();

        db.create_device_code("dc_secret_123", "ABCD-1234", &expires)
            .expect("create device code");

        // Check pending
        let record = db.get_device_code("dc_secret_123").expect("get");
        assert_eq!(record.status, "pending");
        assert_eq!(record.user_code, "ABCD-1234");

        // Authorize
        let raw_token = "duu_device_code_token_abcdef123456";
        let ok = db
            .authorize_device_code("ABCD-1234", uid, raw_token, "cli-login")
            .expect("authorize");
        assert!(ok);

        // Check authorized
        let record2 = db.get_device_code("dc_secret_123").expect("get again");
        assert_eq!(record2.status, "authorized");

        // Token works
        let username = db.validate_token(raw_token).expect("validate");
        assert_eq!(username, "devuser");
    }

    #[test]
    fn expired_device_code_cleanup() {
        let db = test_db();

        let past = chrono::Utc::now()
            .checked_sub_signed(chrono::Duration::minutes(1))
            .expect("invariant: time")
            .to_rfc3339();

        db.create_device_code("dc_expired", "XXXX-0000", &past)
            .expect("create expired");

        let cleaned = db.cleanup_expired_device_codes().expect("cleanup");
        assert_eq!(cleaned, 1);

        let err = db.get_device_code("dc_expired").expect_err("gone");
        assert!(matches!(err, RegistryError::NotFound(_)));
    }

    #[test]
    fn create_device_code_second_request_only_purges_expired() {
        // A second login attempt should succeed (no UNIQUE constraint violation),
        // but MUST NOT remove pending codes belonging to other sessions.
        let db = test_db();

        let future = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::minutes(15))
            .expect("invariant: time")
            .to_rfc3339();

        // First user's pending code.
        db.create_device_code("dc_user1", "AAAA-1111", &future)
            .expect("first code");

        // Second call (same user retrying) — should succeed without error.
        db.create_device_code("dc_user2", "BBBB-2222", &future)
            .expect("second code must not return UNIQUE error");

        // The first user's pending code MUST still exist so their flow is not broken.
        let rec = db
            .get_device_code("dc_user1")
            .expect("first pending code must survive second create");
        assert_eq!(rec.status, "pending", "first code must still be pending");
    }

    #[test]
    fn migrate_repairs_missing_revoked_column() {
        // Simulate a DB that was created with an intermediate version of
        // migration 002 that lacked the `revoked` column.
        let db = Database::open(":memory:").expect("in-memory db");
        {
            let conn = db.conn.lock().expect("lock");

            // Apply schema_version bootstrap manually.
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );",
            )
            .expect("bootstrap");

            // Create tokens table WITHOUT revoked column (old schema).
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS tokens (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id      INTEGER NOT NULL,
                    token_name   TEXT NOT NULL DEFAULT 'default',
                    token_hash   TEXT NOT NULL UNIQUE,
                    token_prefix TEXT NOT NULL DEFAULT '',
                    created_at   TEXT NOT NULL,
                    last_used_at TEXT
                );",
            )
            .expect("create old tokens");

            // Mark version 2 as already applied so migrate() won't DROP+recreate.
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (2, '2024-01-01T00:00:00Z')",
                [],
            )
            .expect("record v2");
        }

        // migrate() should detect the missing column and repair it.
        db.migrate()
            .expect("migrate must repair missing revoked column");

        // After repair, INSERT with revoked=0 should succeed.
        {
            let conn = db.conn.lock().expect("lock");
            conn.execute(
                "INSERT INTO tokens (user_id, token_name, token_hash, token_prefix, created_at, revoked) \
                 VALUES (1, 'test', 'abc', 'abc', '2024-01-01T00:00:00Z', 0)",
                [],
            )
            .expect("INSERT with revoked column must work after repair");

            // And UPDATE SET revoked = 1 (the revoke flow) must also succeed.
            conn.execute("UPDATE tokens SET revoked = 1 WHERE id = 1", [])
                .expect("UPDATE revoked must work after repair");
        }
    }
}
