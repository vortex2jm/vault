use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, create_dir_all},
    io::{BufReader, Read, Write},
    path::PathBuf,
};

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

        let mut file = File::create(&self.path)?;
        if file.write_all(data).and_then(|_| file.sync_all()).is_err() {
            // If write fails, restores backup
            if backup_path.exists() {
                std::fs::copy(&backup_path, &self.path)?;
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
        // Unrecoverable error
        let home = dirs_2::home_dir().expect("Error: Could not found home dir!");
        let vault_dir = home.join(".vault");
        
        let mut vaults = Vec::new();
        
        if !vault_dir.exists() {
            return Ok(vaults);
        }

        for entry in fs::read_dir(&vault_dir)? {
            let entry = entry?;
            let path = entry.path();

            // Filters files with ".vault" only
            if path.is_file()
                && path.extension().and_then(|e| e.to_str()) == Some("vault")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                vaults.push(stem.to_string());
            }
        }

        Ok(vaults)
    }
}
