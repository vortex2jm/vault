//! Bugs still open in `BACKLOG.md`, written as the behaviour we want.
//!
//! They are `#[ignore]`d so `cargo test` stays green; `cargo test -- --ignored`
//! shows which ones are still broken. When an item is fixed, remove its
//! `#[ignore]` and move the test to the module of its area.
//!
//! Where several fixes are acceptable (e.g. refusing an operation instead of
//! handling it), the test accepts any of them and checks the invariant.

use std::fs;

use super::support::{TempDir, created, engine, path_str};
use crate::domain::errors::VaultError;

#[test]
#[ignore = "B2: with two sessions on the same vault, the last commit wins"]
fn b2_a_second_session_must_not_drop_the_first_ones_commit() {
    let dir = TempDir::new();
    created(&dir, "shared", "pw").lock().unwrap();

    let mut first = engine(&dir);
    first.unlock("shared", "pw").unwrap();
    let mut second = engine(&dir);
    if second.unlock("shared", "pw").is_err() {
        return; // refusing a second session is a valid fix
    }

    first.add("from-first", "u", "p").unwrap();
    first.commit().unwrap();
    second.add("from-second", "u", "p").unwrap();
    if second.commit().is_err() {
        return; // refusing a stale commit is a valid fix
    }
    first.lock().unwrap();
    second.lock().unwrap();

    let mut check = engine(&dir);
    check.unlock("shared", "pw").unwrap();
    assert!(check.get("from-first").is_ok(), "the first session's entry was dropped");
}

#[test]
#[ignore = "B3: payloads over 4 MiB commit but never open again"]
fn b3_a_committed_vault_must_always_reopen() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "big", "pw");
    let big = "x".repeat(5 * 1024 * 1024);
    engine.add("big", "u", &big).unwrap();
    if engine.commit().is_err() {
        return; // refusing to write an unreadable vault is a valid fix
    }
    engine.lock().unwrap();

    engine.unlock("big", "pw").unwrap();
    assert_eq!(engine.get("big").unwrap().passwd.len(), big.len());
}

#[test]
#[ignore = "B6: CSV import maps columns by position, ignoring the header"]
fn b6_import_must_not_misplace_columns() {
    let dir = TempDir::new();
    let csv = dir.file("browser-export.csv");
    fs::write(
        &csv,
        "name,url,username,password,note\ngithub,https://github.com,alice,hunter2,\n",
    )
    .unwrap();

    let mut engine = created(&dir, "personal", "pw");
    if engine.import(path_str(&csv)).is_err() {
        return; // rejecting an unknown header is a valid fix
    }
    let entry = engine.get("github").unwrap();
    assert_eq!((entry.username.as_str(), entry.passwd.as_str()), ("alice", "hunter2"));
}

#[test]
#[ignore = "B6: a failed import leaves partial entries behind, not marked as changes"]
fn b6_import_must_leave_a_consistent_state() {
    let dir = TempDir::new();
    let csv = dir.file("broken.csv");
    fs::write(&csv, "service,username,password\na,u,p\nb,u,p\nbroken-row\n").unwrap();

    let mut engine = created(&dir, "personal", "pw");
    match engine.import(path_str(&csv)) {
        Err(_) => {
            assert!(engine.get_entries().unwrap().is_empty(), "partial import");
            assert!(!engine.is_dirty());
        }
        Ok(count) => {
            assert_eq!(count, engine.get_entries().unwrap().len());
            assert!(engine.is_dirty());
        }
    }
}

#[cfg(unix)]
mod permissions {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::super::support::{TempDir, created, engine_at, mode, path_str};

    #[test]
    #[ignore = "B7: CSV export follows the umask"]
    fn b7_export_must_be_private() {
        let dir = TempDir::new();
        let csv = dir.file("export.csv");
        created(&dir, "personal", "pw").export(path_str(&csv)).unwrap();
        assert_eq!(mode(&csv), 0o600);
    }

    #[test]
    #[ignore = "B7: CSV export overwrites existing files"]
    fn b7_export_must_not_overwrite_an_existing_file() {
        let dir = TempDir::new();
        let csv = dir.file("precious.csv");
        fs::write(&csv, "precious").unwrap();
        assert!(created(&dir, "personal", "pw").export(path_str(&csv)).is_err());
        assert_eq!(fs::read_to_string(&csv).unwrap(), "precious");
    }

    #[test]
    #[ignore = "B7: the vault directory is created with the umask"]
    fn b7_vault_directory_must_be_private() {
        let dir = TempDir::new();
        let base = dir.file("vaults");
        engine_at(&base).create_vault("personal", "pw").unwrap();
        assert_eq!(mode(&base), 0o700);
    }

    #[test]
    #[ignore = "B7: vaults created before the 0600 change keep their old mode"]
    fn b7_commit_must_make_an_old_vault_private() {
        let dir = TempDir::new();
        let mut engine = created(&dir, "personal", "pw");
        let file = dir.file("personal.vault");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o664)).unwrap();

        engine.add("github", "alice", "hunter2").unwrap();
        engine.commit().unwrap();
        assert_eq!(mode(&file), 0o600);
    }
}

#[test]
#[ignore = "B8: after passwd, the .bkp still opens with the old password"]
fn b8_backup_must_not_open_with_the_old_password() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "old");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();
    engine.change_password("old", "new").unwrap();
    engine.lock().unwrap();

    let backup = dir.file("personal.bkp");
    if !backup.exists() {
        return; // removing the old backup is a valid fix
    }
    fs::copy(&backup, dir.file("from-backup.vault")).unwrap();
    assert!(matches!(
        engine.unlock("from-backup", "old"),
        Err(VaultError::InvalidPassword)
    ));
}

#[test]
#[ignore = "B9: empty master passwords are accepted"]
fn b9_empty_master_password_must_be_rejected() {
    let dir = TempDir::new();
    let mut engine = engine(&dir);
    assert!(engine.create_vault("personal", "").is_err());
    assert!(engine.is_locked());

    let mut engine = created(&dir, "other", "pw");
    assert!(engine.change_password("pw", "").is_err());
}
