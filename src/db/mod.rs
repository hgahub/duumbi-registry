//! Database layer backed by SQLite.
//!
//! Stores module metadata, versions, and auth tokens.
//! The actual `.tar.gz` archives live on the filesystem (see `storage`).

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

use crate::error::RegistryError;
use crate::types::{ModuleInfo, SearchHit, SearchResponse, VersionInfo};

/// SQLite database wrapper with interior mutability.
pub struct Database {
    conn: Mutex<Connection>,
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
            Connection::open(db_path)?
        };

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Runs database migrations.
    pub fn migrate(&self) -> Result<(), RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");
        conn.execute_batch(SCHEMA)?;
        Ok(())
    }

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

    /// Validates an API token. Returns the username if valid.
    pub fn validate_token(&self, token: &str) -> Result<String, RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");

        let username: String = conn
            .prepare("SELECT username FROM tokens WHERE token = ?1 AND revoked = 0")?
            .query_row([token], |row| row.get(0))
            .map_err(|_| RegistryError::AuthFailed("Invalid or revoked token".to_string()))?;

        Ok(username)
    }

    /// Creates a new API token for a user.
    pub fn create_token(&self, username: &str, token: &str) -> Result<(), RegistryError> {
        let conn = self.conn.lock().expect("invariant: db mutex not poisoned");
        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO tokens (username, token, created_at, revoked) VALUES (?1, ?2, ?3, 0)",
            rusqlite::params![username, token, now],
        )?;

        Ok(())
    }
}

/// Database schema (migrations).
const SCHEMA: &str = r#"
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

CREATE TABLE IF NOT EXISTS tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL,
    token      TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_versions_module ON versions(module_name);
CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Database {
        Database::open(":memory:").expect("in-memory db")
    }

    #[test]
    fn migrate_succeeds() {
        let db = test_db();
        db.migrate().expect("migration");
    }

    #[test]
    fn publish_and_get_module() {
        let db = test_db();
        db.migrate().expect("migration");

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
        db.migrate().expect("migration");

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
        db.migrate().expect("migration");

        db.publish_version("@test/m", None, "1.0.0", "sha256:a")
            .expect("publish");

        db.yank_version("@test/m", "1.0.0").expect("yank");

        let info = db.get_module("@test/m").expect("get");
        assert!(info.versions[0].yanked);
    }

    #[test]
    fn yank_nonexistent_version_fails() {
        let db = test_db();
        db.migrate().expect("migration");

        let err = db.yank_version("@test/m", "1.0.0").expect_err("not found");

        assert!(matches!(err, RegistryError::VersionNotFound { .. }));
    }

    #[test]
    fn search_by_name() {
        let db = test_db();
        db.migrate().expect("migration");

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

    #[test]
    fn token_validation() {
        let db = test_db();
        db.migrate().expect("migration");

        db.create_token("alice", "tok_abc123").expect("create");

        let user = db.validate_token("tok_abc123").expect("valid");
        assert_eq!(user, "alice");

        let err = db.validate_token("tok_invalid").expect_err("invalid");
        assert!(matches!(err, RegistryError::AuthFailed(_)));
    }
}
