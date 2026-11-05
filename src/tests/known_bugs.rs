//! Bugs still open in `BACKLOG.md`, written as the behaviour we want.
//!
//! They are `#[ignore]`d so `cargo test` stays green; `cargo test -- --ignored`
//! shows which ones are still broken. When an item is fixed, remove its
//! `#[ignore]` and move the test to the module of its area.
//!
//! Where several fixes are acceptable (e.g. refusing an operation instead of
//! handling it), the test accepts any of them and checks the invariant.

use std::fs;

use super::support::{TempDir, created, path_str};

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
