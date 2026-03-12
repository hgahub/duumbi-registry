//! Filesystem storage for module archives.
//!
//! Archives are stored as `{storage_dir}/@scope/name/version.tar.gz`.

use std::path::PathBuf;

use crate::error::RegistryError;

/// Filesystem-backed module archive storage.
pub struct Storage {
    root: PathBuf,
}

impl Storage {
    /// Creates a new storage instance, ensuring the root directory exists.
    pub fn new(root: &str) -> Result<Self, RegistryError> {
        let path = PathBuf::from(root);
        std::fs::create_dir_all(&path)?;
        Ok(Self { root: path })
    }

    /// Stores a module archive.
    pub fn store(
        &self,
        module: &str,
        version: &str,
        data: &[u8],
    ) -> Result<PathBuf, RegistryError> {
        let dir = self.module_dir(module);
        std::fs::create_dir_all(&dir)?;

        let archive_path = dir.join(format!("{version}.tar.gz"));
        std::fs::write(&archive_path, data)?;

        Ok(archive_path)
    }

    /// Reads a module archive.
    pub fn load(&self, module: &str, version: &str) -> Result<Vec<u8>, RegistryError> {
        let archive_path = self.module_dir(module).join(format!("{version}.tar.gz"));

        if !archive_path.exists() {
            return Err(RegistryError::VersionNotFound {
                module: module.to_string(),
                version: version.to_string(),
            });
        }

        Ok(std::fs::read(&archive_path)?)
    }

    /// Returns the storage directory for a module.
    fn module_dir(&self, module: &str) -> PathBuf {
        // module is like "@scope/name" — preserve the path structure
        self.root.join(module)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_load_archive() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let storage = Storage::new(tmp.path().to_str().expect("path")).expect("storage");

        let data = b"fake tarball content";
        let path = storage
            .store("@test/example", "1.0.0", data)
            .expect("store");

        assert!(path.exists());

        let loaded = storage.load("@test/example", "1.0.0").expect("load");
        assert_eq!(loaded, data);
    }

    #[test]
    fn load_nonexistent_returns_error() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let storage = Storage::new(tmp.path().to_str().expect("path")).expect("storage");

        let err = storage.load("@test/missing", "1.0.0").expect_err("missing");
        assert!(matches!(err, RegistryError::VersionNotFound { .. }));
    }
}
