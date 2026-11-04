//! `VaultEngine` flows, with the real adapters on a temporary directory.

use std::fs;

use super::support::{TempDir, created, engine, path_str};
use crate::domain::errors::VaultError;

#[test]
fn create_leaves_the_vault_unlocked_and_on_disk() {
    let dir = TempDir::new();
    let engine = created(&dir, "personal", "pw");

    assert!(!engine.is_locked());
    assert!(!engine.is_dirty());
    assert_eq!(engine.current_vault().as_deref(), Some("personal"));
    assert!(engine.get_entries().unwrap().is_empty());
    assert!(dir.file("personal.vault").exists());
}

#[test]
fn create_refuses_an_existing_vault() {
    let dir = TempDir::new();
    created(&dir, "personal", "pw").lock().unwrap();

    let mut engine = engine(&dir);
    assert!(matches!(
        engine.create_vault("personal", "other"),
        Err(VaultError::VaultAlreadyExists)
    ));
    assert!(engine.is_locked());
}

#[test]
fn invalid_vault_names_are_rejected() {
    let dir = TempDir::new();
    let mut engine = engine(&dir);
    for name in ["", "../evil", "a/b", "a.b", "with space", "~"] {
        assert!(
            matches!(engine.create_vault(name, "pw"), Err(VaultError::InvalidVaultName)),
            "create {name:?}"
        );
        assert!(
            matches!(engine.unlock(name, "pw"), Err(VaultError::InvalidVaultName)),
            "unlock {name:?}"
        );
    }
    assert!(engine.get_vaults().unwrap().is_empty());
}

#[test]
fn entries_survive_commit_lock_and_unlock() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "master");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.add("bank", "0042", "0099").unwrap(); // leading zeros are kept verbatim
    assert!(engine.is_dirty());

    engine.commit().unwrap();
    assert!(!engine.is_dirty());
    engine.lock().unwrap();
    assert!(engine.is_locked());

    engine.unlock("personal", "master").unwrap();
    assert_eq!(engine.get_entries().unwrap(), ["bank", "github"]);
    assert_eq!(engine.info().unwrap(), ("personal".to_string(), 2));
    let bank = engine.get("bank").unwrap();
    assert_eq!((bank.username.as_str(), bank.passwd.as_str()), ("0042", "0099"));
    assert_eq!(engine.get("github").unwrap().passwd, "hunter2");
}

#[test]
fn uncommitted_changes_are_discarded_by_lock() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "pw");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.lock().unwrap();

    engine.unlock("personal", "pw").unwrap();
    assert!(engine.get_entries().unwrap().is_empty());
}

#[test]
fn wrong_password_keeps_the_vault_locked() {
    let dir = TempDir::new();
    created(&dir, "personal", "right").lock().unwrap();

    let mut engine = engine(&dir);
    assert!(matches!(engine.unlock("personal", "wrong"), Err(VaultError::InvalidPassword)));
    assert!(engine.is_locked());
    assert!(matches!(engine.get_entries(), Err(VaultError::Locked)));

    engine.unlock("personal", "right").unwrap();
}

#[test]
fn unlocking_a_missing_vault_fails() {
    let dir = TempDir::new();
    let mut engine = engine(&dir);
    assert!(matches!(engine.unlock("nope", "pw"), Err(VaultError::VaultNotFound)));
    assert!(engine.is_locked());
}

#[test]
fn operations_require_an_unlocked_vault() {
    let dir = TempDir::new();
    let mut engine = engine(&dir);
    let csv = dir.file("out.csv");

    assert!(matches!(engine.add("s", "u", "p"), Err(VaultError::Locked)));
    assert!(matches!(engine.get("s"), Err(VaultError::Locked)));
    assert!(matches!(engine.update("s", None, None), Err(VaultError::Locked)));
    assert!(matches!(engine.delete("s"), Err(VaultError::Locked)));
    assert!(matches!(engine.commit(), Err(VaultError::Locked)));
    assert!(matches!(engine.lock(), Err(VaultError::Locked)));
    assert!(matches!(engine.info(), Err(VaultError::Locked)));
    assert!(matches!(engine.rename_vault("x"), Err(VaultError::Locked)));
    assert!(matches!(engine.change_password("a", "b"), Err(VaultError::Locked)));
    assert!(matches!(engine.export(path_str(&csv)), Err(VaultError::Locked)));
    assert!(matches!(engine.import(path_str(&csv)), Err(VaultError::Locked)));
    assert!(!csv.exists());
}

#[test]
fn vault_level_operations_are_refused_while_unlocked() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "pw");

    assert!(matches!(engine.create_vault("other", "pw"), Err(VaultError::Unlocked)));
    assert!(matches!(engine.unlock("personal", "pw"), Err(VaultError::Unlocked)));
    assert!(matches!(engine.delete_vault("personal"), Err(VaultError::Unlocked)));
    assert!(dir.file("personal.vault").exists());
}

#[test]
fn duplicate_and_missing_entries_do_not_change_state() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "pw");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();

    assert!(matches!(engine.add("github", "bob", "x"), Err(VaultError::EntryExists)));
    assert!(matches!(engine.get("missing"), Err(VaultError::EntryNotFound)));
    assert!(matches!(engine.delete("missing"), Err(VaultError::EntryNotFound)));
    assert!(matches!(
        engine.update("missing", Some("u".into()), None),
        Err(VaultError::EntryNotFound)
    ));
    assert!(!engine.is_dirty());
    assert_eq!(engine.get("github").unwrap().username, "alice");
}

#[test]
fn update_keeps_the_fields_left_blank() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "pw");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();

    engine.update("github", None, Some("new-pass".into())).unwrap();
    assert!(engine.is_dirty());
    let entry = engine.get("github").unwrap();
    assert_eq!((entry.username.as_str(), entry.passwd.as_str()), ("alice", "new-pass"));

    engine.update("github", Some("bob".into()), None).unwrap();
    let entry = engine.get("github").unwrap();
    assert_eq!((entry.username.as_str(), entry.passwd.as_str()), ("bob", "new-pass"));
}

#[test]
fn delete_removes_the_entry() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "pw");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();

    let removed = engine.delete("github").unwrap();
    assert_eq!(removed.service, "github");
    assert!(engine.is_dirty());
    assert!(matches!(engine.get("github"), Err(VaultError::EntryNotFound)));
}

#[test]
fn change_password_requires_the_current_one_and_re_encrypts() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "old");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();

    assert!(matches!(
        engine.change_password("wrong", "new"),
        Err(VaultError::InvalidPassword)
    ));
    engine.change_password("old", "new").unwrap();
    engine.lock().unwrap();

    assert!(matches!(engine.unlock("personal", "old"), Err(VaultError::InvalidPassword)));
    engine.unlock("personal", "new").unwrap();
    assert_eq!(engine.get("github").unwrap().passwd, "hunter2");
}

#[test]
fn export_then_import_round_trip() {
    let dir = TempDir::new();
    let csv = dir.file("export.csv");

    let mut source = created(&dir, "source", "pw");
    source.add("github", "alice", "hunter2").unwrap();
    source.add("bank", "0042", "0099").unwrap();
    source.export(path_str(&csv)).unwrap();
    source.lock().unwrap();

    let mut target = created(&dir, "target", "pw");
    target.add("github", "existing", "keep-me").unwrap();
    target.commit().unwrap();

    assert_eq!(target.import(path_str(&csv)).unwrap(), 1); // github already exists
    assert!(target.is_dirty());
    assert_eq!(target.get("github").unwrap().passwd, "keep-me");
    let bank = target.get("bank").unwrap();
    assert_eq!((bank.username.as_str(), bank.passwd.as_str()), ("0042", "0099"));
}

#[test]
fn rename_vault_moves_it_to_the_new_name() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "old", "pw");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();

    engine.rename_vault("new").unwrap();
    assert_eq!(engine.current_vault().as_deref(), Some("new"));
    engine.lock().unwrap();

    assert!(matches!(engine.unlock("old", "pw"), Err(VaultError::VaultNotFound)));
    engine.unlock("new", "pw").unwrap();
    assert_eq!(engine.get("github").unwrap().passwd, "hunter2");
}

#[test]
fn rename_vault_refuses_a_name_already_taken() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "target", "pw-target");
    engine.add("bank", "alice", "s3cr3t").unwrap();
    engine.commit().unwrap(); // target.bkp exists from here on
    engine.lock().unwrap();

    engine.create_vault("source", "pw-source").unwrap();
    engine.add("github", "bob", "hunter2").unwrap();
    engine.commit().unwrap(); // and so does source.bkp
    assert!(matches!(engine.rename_vault("target"), Err(VaultError::VaultAlreadyExists)));
    assert_eq!(engine.current_vault().as_deref(), Some("source"));
    engine.lock().unwrap();

    // Both vaults and the target's backup are untouched.
    engine.unlock("target", "pw-target").unwrap();
    assert_eq!(engine.get("bank").unwrap().passwd, "s3cr3t");
    engine.lock().unwrap();
    engine.unlock("source", "pw-source").unwrap();
    assert_eq!(engine.get("github").unwrap().passwd, "hunter2");
    engine.lock().unwrap();
    fs::copy(dir.file("target.bkp"), dir.file("target-backup.vault")).unwrap();
    engine.unlock("target-backup", "pw-target").unwrap();
}

#[test]
fn renaming_a_vault_to_its_own_name_changes_nothing() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "pw");
    engine.rename_vault("personal").unwrap();
    assert_eq!(engine.current_vault().as_deref(), Some("personal"));
    assert!(dir.file("personal.vault").exists());
}

#[test]
fn delete_vault_removes_it() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "pw");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();
    engine.lock().unwrap();

    engine.delete_vault("personal").unwrap();
    assert!(engine.get_vaults().unwrap().is_empty());
    assert!(!dir.file("personal.bkp").exists());
    assert!(matches!(engine.unlock("personal", "pw"), Err(VaultError::VaultNotFound)));
    assert!(engine.delete_vault("personal").is_err());
}
