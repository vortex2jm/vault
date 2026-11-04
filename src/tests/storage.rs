//! `FileStorage`: vault files, backups, listing, rename and delete.

use std::fs;

use super::support::TempDir;
use crate::{adapters::file_storage::FileStorage, domain::ports::StoragePort};

fn storage(dir: &TempDir, name: &str) -> FileStorage {
    let mut storage = FileStorage::with_base_path(dir.path().to_path_buf());
    storage.set_path(name.to_string());
    storage
}

#[test]
fn save_and_load_round_trip() {
    let dir = TempDir::new();
    let storage = storage(&dir, "personal");
    assert!(!storage.exists());

    storage.save(b"first").unwrap();
    assert!(storage.exists());
    assert_eq!(storage.load().unwrap(), b"first");
    assert_eq!(storage.get_path().as_deref(), Some("personal"));
}

#[test]
fn save_keeps_the_previous_version_in_the_backup() {
    let dir = TempDir::new();
    let storage = storage(&dir, "personal");

    storage.save(b"v1").unwrap();
    assert!(!dir.file("personal.bkp").exists());

    storage.save(b"v2").unwrap();
    assert_eq!(fs::read(dir.file("personal.bkp")).unwrap(), b"v1");
    assert_eq!(storage.load().unwrap(), b"v2");
}

#[test]
fn save_creates_the_base_directory() {
    let dir = TempDir::new();
    let mut storage = FileStorage::with_base_path(dir.file("nested"));
    storage.set_path("personal".into());

    storage.save(b"data").unwrap();
    assert!(dir.file("nested").join("personal.vault").exists());
}

#[cfg(unix)]
#[test]
fn new_vault_files_are_private() {
    use super::support::mode;

    let dir = TempDir::new();
    let storage = storage(&dir, "personal");
    storage.save(b"v1").unwrap();
    storage.save(b"v2").unwrap();

    assert_eq!(mode(&dir.file("personal.vault")), 0o600);
    assert_eq!(mode(&dir.file("personal.bkp")), 0o600);
}

#[test]
fn list_vaults_only_returns_vault_files() {
    let dir = TempDir::new();
    storage(&dir, "work").save(b"x").unwrap();
    let personal = storage(&dir, "personal");
    personal.save(b"v1").unwrap();
    personal.save(b"v2").unwrap(); // creates personal.bkp
    fs::write(dir.file("notes.txt"), b"x").unwrap();
    fs::create_dir(dir.file("folder.vault")).unwrap();

    let mut vaults = personal.list_vaults().unwrap();
    vaults.sort();
    assert_eq!(vaults, ["personal", "work"]);
}

#[test]
fn list_vaults_without_a_base_directory_is_empty() {
    let dir = TempDir::new();
    let storage = FileStorage::with_base_path(dir.file("missing"));
    assert!(storage.list_vaults().unwrap().is_empty());
}

#[test]
fn rename_moves_the_vault_and_its_backup() {
    let dir = TempDir::new();
    let mut storage = storage(&dir, "old");
    storage.save(b"v1").unwrap();
    storage.save(b"v2").unwrap();

    storage.rename("new".into()).unwrap();
    assert_eq!(storage.get_path().as_deref(), Some("new"));
    assert_eq!(storage.load().unwrap(), b"v2");
    assert!(dir.file("new.bkp").exists());
    assert!(!dir.file("old.vault").exists());
    assert!(!dir.file("old.bkp").exists());
}

#[test]
fn delete_removes_the_vault_and_its_backup() {
    let dir = TempDir::new();
    let storage = storage(&dir, "personal");
    storage.save(b"v1").unwrap();
    storage.save(b"v2").unwrap();

    storage.delete("personal".into()).unwrap();
    assert!(!dir.file("personal.vault").exists());
    assert!(!dir.file("personal.bkp").exists());
    assert!(storage.delete("personal".into()).is_err());
}
