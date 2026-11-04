//! Domain models: `Entry` and `VaultState`.

use crate::domain::models::{Entry, VaultState};

fn github() -> Entry {
    Entry::new("github".into(), "alice".into(), "hunter2".into())
}

#[test]
fn a_new_entry_keeps_its_fields() {
    let entry = github();
    assert_eq!(entry.service, "github");
    assert_eq!(entry.username, "alice");
    assert_eq!(entry.passwd, "hunter2");
}

#[test]
fn update_replaces_only_the_given_fields() {
    let mut entry = github();

    entry.update(None, None);
    assert_eq!((entry.username.as_str(), entry.passwd.as_str()), ("alice", "hunter2"));

    entry.update(Some("bob".into()), None);
    assert_eq!((entry.username.as_str(), entry.passwd.as_str()), ("bob", "hunter2"));

    entry.update(None, Some("new-pass".into()));
    assert_eq!((entry.username.as_str(), entry.passwd.as_str()), ("bob", "new-pass"));
    assert_eq!(entry.service, "github");
}

#[test]
fn a_new_vault_state_has_its_salt_and_no_ciphertext_yet() {
    let state = VaultState::new(&[9; 16]);
    assert_eq!(state.salt, [9; 16]);
    assert_eq!(state.nonce, [0; 12]);
    assert!(state.cipher.is_empty());
}
