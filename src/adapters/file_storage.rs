use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions, create_dir_all},
    io::{BufReader, Read, Write},
    path::PathBuf,
};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::domain::{errors::StorageError, ports::StoragePort};

pub struct FileStorage {
    base_path: PathBuf,
    path: PathBuf,
}

impl FileStorage {
    pub fn new() -> Self {
        let home = dirs_2::home_dir().expect("Error: Could not found home dir!");
        let base_path = home.join(".vault");

        // Complete path
        let path = base_path.join("default.vault");

        Self { path, base_path }
    }

    fn hash_file(path: &PathBuf) -> Result<Vec<u8>, StorageError> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        std::io::copy(&mut reader, &mut hasher)?;
        Ok(hasher.finalize().to_vec())
    }
}

impl StoragePort for FileStorage {
    fn set_path(&mut self, mut path: String) {
        path.push_str(".vault");

        // Set complete path through base path
        self.path = self.base_path.join(path);
    }

    fn get_path(&self) -> Option<String> {
        self.path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
    }

    fn save(&self, data: &[u8]) -> Result<(), StorageError> {
        // Checks dir
        if let Some(parent) = self.path.parent() {
            create_dir_all(parent)?;
        }

        // Create backup file
        let backup_path = self.path.with_extension("bkp");
        if self.path.exists() {
            std::fs::copy(&self.path, &backup_path)?;

            // Validate bkp integrity
            let orig_hash = Self::hash_file(&self.path)?;
            let bkp_hash = Self::hash_file(&backup_path)?;

            if orig_hash != bkp_hash {
                return Err(StorageError::IntegrityError);
            }
        }

        // Create the vault file with restrictive permissions (owner read/write only).
        // File::create inherits the process umask (commonly 644); using OpenOptions
        // with an explicit mode guarantees 600 regardless of the user's umask.
        #[cfg(unix)]
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.path)?;

        #[cfg(not(unix))]
        let mut file = File::create(&self.path)?;
        if file.write_all(data).and_then(|_| file.sync_all()).is_err() {
            // Write failed — attempt to restore from backup.
            // The restore error is handled separately so it doesn't mask
            // the original write failure.
            if backup_path.exists()
                && let Err(restore_err) = std::fs::copy(&backup_path, &self.path)
            {
                eprintln!(
                    "CRITICAL: vault write failed and backup restore also failed: {}",
                    restore_err
                );
            }
            return Err(StorageError::IntegrityError);
        }

        Ok(())
    }

    fn load(&self) -> Result<std::vec::Vec<u8>, StorageError> {
        let mut file = File::open(&self.path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        Ok(buffer)
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }

    fn list_vaults(&self) -> Result<Vec<String>, StorageError> {
        let vault_dir = &self.base_path;

        let mut vaults = Vec::new();

        if !vault_dir.exists() {
            return Ok(vaults);
        }

        for entry in fs::read_dir(vault_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file()
                && path.extension().and_then(|e| e.to_str()) == Some("vault")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                vaults.push(stem.to_string());
            }
        }

        Ok(vaults)
    }

    fn rename(&mut self, new_name: String) -> Result<(), StorageError> {
        let new_path = self.base_path.join(format!("{}.vault", new_name));
        let old_bkp = self.path.with_extension("bkp");
        let new_bkp = new_path.with_extension("bkp");

        fs::rename(&self.path, &new_path)?;

        // Best-effort rename of the backup; not fatal if it doesn't exist.
        if old_bkp.exists() {
            fs::rename(&old_bkp, &new_bkp).ok();
        }

        self.path = new_path;
        Ok(())
    }

    fn delete(&self, name: String) -> Result<(), StorageError> {
        let vault_path = self.base_path.join(format!("{}.vault", name));
        let bkp_path = vault_path.with_extension("bkp");

        if !vault_path.exists() {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Vault '{}' not found", name),
            )));
        }

        fs::remove_file(&vault_path)?;

        // Best-effort removal of the backup.
        if bkp_path.exists() {
            fs::remove_file(&bkp_path).ok();
        }

        Ok(())
    }
}
