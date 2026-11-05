//! `FileStorage`: vault files, backups, atomic saves, sessions, listing,
//! rename and delete.

use std::fs;

use super::support::TempDir;
use crate::{
    adapters::file_storage::FileStorage,
    domain::{errors::StorageError, ports::StoragePort},
};

fn storage(dir: &TempDir, name: &str) -> FileStorage {
    let mut storage = FileStorage::with_base_path(dir.path().to_path_buf());
    storage.set_path(name.to_string());
    storage
}

/// Names of the files in `dir`, sorted.
fn files_in(dir: &TempDir) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn save_and_load_round_trip() {
    let dir = TempDir::new();
    let mut storage = storage(&dir, "personal");
    assert!(!storage.exists());

    storage.save(b"first").unwrap();
    assert!(storage.exists());
    assert_eq!(storage.load().unwrap(), b"first");
    assert_eq!(storage.get_path().as_deref(), Some("personal"));
}

#[test]
fn save_keeps_the_previous_version_in_the_backup() {
    let dir = TempDir::new();
    let mut storage = storage(&dir, "personal");

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

#[test]
fn saves_leave_no_temporary_files_behind() {
    let dir = TempDir::new();
    let mut storage = storage(&dir, "personal");
    storage.save(b"v1").unwrap();
    storage.save(b"v2").unwrap();
    assert_eq!(files_in(&dir), [".lock", "personal.bkp", "personal.vault"]);
}

#[test]
fn a_failed_save_leaves_the_vault_untouched() {
    let dir = TempDir::new();
    let mut storage = storage(&dir, "personal");
    storage.save(b"v1").unwrap();

    // A directory where the temporary file should go makes the write fail.
    fs::create_dir(dir.file("personal.vault.tmp")).unwrap();
    assert!(storage.save(b"v2").is_err());
    assert_eq!(fs::read(dir.file("personal.vault")).unwrap(), b"v1");

    fs::remove_dir(dir.file("personal.vault.tmp")).unwrap();
    storage.save(b"v2").unwrap();
    assert_eq!(fs::read(dir.file("personal.vault")).unwrap(), b"v2");
}

#[test]
fn save_refuses_to_overwrite_what_another_session_saved() {
    let dir = TempDir::new();
    let mut first = storage(&dir, "shared");
    first.save(b"v1").unwrap();
    let mut second = storage(&dir, "shared");
    assert_eq!(second.load().unwrap(), b"v1");

    first.save(b"v2").unwrap();
    assert!(matches!(second.save(b"v3"), Err(StorageError::Conflict)));
    assert_eq!(fs::read(dir.file("shared.vault")).unwrap(), b"v2");

    // Once it has read the latest version, the second session can save.
    second.load().unwrap();
    second.save(b"v3").unwrap();
    assert_eq!(first.load().unwrap(), b"v3");
}

#[test]
fn save_refuses_a_vault_created_or_deleted_by_another_session() {
    let dir = TempDir::new();

    // Created elsewhere after this session found no file.
    let mut late = storage(&dir, "new");
    storage(&dir, "new").save(b"theirs").unwrap();
    assert!(matches!(late.save(b"mine"), Err(StorageError::Conflict)));
    assert_eq!(fs::read(dir.file("new.vault")).unwrap(), b"theirs");

    // Deleted elsewhere while this session had it open.
    let mut open = storage(&dir, "old");
    open.save(b"v1").unwrap();
    storage(&dir, "old").delete("old".into()).unwrap();
    assert!(matches!(open.save(b"v2"), Err(StorageError::Conflict)));
    assert!(!dir.file("old.vault").exists());
}

#[cfg(unix)]
#[test]
fn new_vault_files_are_private() {
    use super::support::mode;

    let dir = TempDir::new();
    let mut storage = storage(&dir, "personal");
    storage.save(b"v1").unwrap();
    storage.save(b"v2").unwrap();

    assert_eq!(mode(&dir.file("personal.vault")), 0o600);
    assert_eq!(mode(&dir.file("personal.bkp")), 0o600);
}

#[cfg(unix)]
#[test]
fn saving_makes_an_old_vault_private() {
    use super::support::mode;
    use std::os::unix::fs::PermissionsExt;

    // Vaults written before the 0600 change were left with the umask's mode.
    let dir = TempDir::new();
    let mut storage = storage(&dir, "personal");
    storage.save(b"v1").unwrap();
    fs::set_permissions(dir.file("personal.vault"), fs::Permissions::from_mode(0o664)).unwrap();

    storage.save(b"v2").unwrap();
    assert_eq!(mode(&dir.file("personal.vault")), 0o600);
    assert_eq!(mode(&dir.file("personal.bkp")), 0o600);
}

#[cfg(unix)]
#[test]
fn the_vault_directory_is_private() {
    use super::support::mode;
    use std::os::unix::fs::PermissionsExt;

    // Created private by the first save…
    let dir = TempDir::new();
    let mut storage = FileStorage::with_base_path(dir.file("vaults"));
    storage.set_path("personal".into());
    storage.save(b"v1").unwrap();
    assert_eq!(mode(&dir.file("vaults")), 0o700);

    // …and tightened on the next save if an older version left it open.
    fs::set_permissions(dir.file("vaults"), fs::Permissions::from_mode(0o775)).unwrap();
    storage.save(b"v2").unwrap();
    assert_eq!(mode(&dir.file("vaults")), 0o700);
}

#[test]
fn list_vaults_only_returns_vault_files() {
    let dir = TempDir::new();
    storage(&dir, "work").save(b"x").unwrap();
    let mut personal = storage(&dir, "personal");
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
fn rename_refuses_to_replace_another_vault() {
    let dir = TempDir::new();
    let mut other = storage(&dir, "other");
    other.save(b"other-v1").unwrap();
    other.save(b"other-v2").unwrap();
    let mut storage = storage(&dir, "mine");
    storage.save(b"mine-v1").unwrap();
    storage.save(b"mine-v2").unwrap();

    assert!(matches!(storage.rename("other".into()), Err(StorageError::AlreadyExists)));
    assert_eq!(storage.get_path().as_deref(), Some("mine"));
    assert_eq!(storage.load().unwrap(), b"mine-v2");
    assert_eq!(fs::read(dir.file("other.vault")).unwrap(), b"other-v2");
    assert_eq!(fs::read(dir.file("other.bkp")).unwrap(), b"other-v1");
}

#[test]
fn delete_removes_the_vault_and_its_backup() {
    let dir = TempDir::new();
    let mut storage = storage(&dir, "personal");
    storage.save(b"v1").unwrap();
    storage.save(b"v2").unwrap();

    storage.delete("personal".into()).unwrap();
    assert!(!dir.file("personal.vault").exists());
    assert!(!dir.file("personal.bkp").exists());
    assert!(storage.delete("personal".into()).is_err());
}
