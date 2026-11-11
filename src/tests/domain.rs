//! Domain models: `Entry` and `KdfParams`.

use zeroize::ZeroizeOnDrop;

use crate::domain::models::{Entry, HISTORY_LEN, KdfParams, OldPassword};

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

fn history_of(entry: &Entry) -> Vec<&str> {
    entry.history.iter().map(|old| old.passwd.as_str()).collect()
}

#[test]
fn a_changed_password_goes_to_the_front_of_the_history() {
    let mut entry = github();
    assert!(entry.history.is_empty());

    entry.update(None, Some("second".into()));
    entry.update(None, Some("third".into()));
    assert_eq!(entry.passwd, "third");
    assert_eq!(history_of(&entry), ["second", "hunter2"]);
    // Each one is stamped with the moment it was replaced.
    assert_eq!(entry.history[0].replaced_at, entry.updated_at);
    assert!(entry.history[1].replaced_at >= entry.created_at);
    assert!(entry.history[0].replaced_at >= entry.history[1].replaced_at);
}

#[test]
fn the_same_password_or_a_new_username_leaves_the_history_alone() {
    let mut entry = github();
    entry.update(None, Some("hunter2".into()));
    entry.update(Some("bob".into()), None);
    assert!(entry.history.is_empty());
}

#[test]
fn the_history_keeps_only_the_latest_passwords() {
    let mut entry = github();
    for i in 0..HISTORY_LEN + 3 {
        entry.update(None, Some(format!("p{i}")));
    }
    assert_eq!(entry.history.len(), HISTORY_LEN);
    assert_eq!(entry.history[0].passwd, format!("p{}", HISTORY_LEN + 1));
    assert!(!history_of(&entry).contains(&"hunter2"), "the oldest ones are dropped");
}

#[test]
fn notes_start_empty_and_can_be_replaced() {
    let mut entry = github();
    assert_eq!(entry.notes, "");
    entry.set_notes("2FA on the phone".into());
    assert_eq!(entry.notes, "2FA on the phone");
    entry.set_notes(String::new());
    assert_eq!(entry.notes, "");
}

/// Compiles only for types that wipe themselves when dropped.
fn wiped_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn entries_and_their_old_passwords_are_wiped_when_dropped() {
    // `rm`, `lock`, a failed import and exiting the program all just drop
    // entries: the type itself makes sure that wipes them.
    wiped_on_drop::<Entry>();
    wiped_on_drop::<OldPassword>();
}

#[test]
fn debug_output_leaves_the_secrets_out() {
    let mut entry = github();
    entry.set_notes("recovery codes 1234".into());
    entry.update(None, Some("new-secret".into()));
    let debug = format!("{entry:?}");
    assert!(debug.contains("github") && debug.contains("alice"), "{debug}");
    for secret in ["hunter2", "new-secret", "recovery codes"] {
        assert!(!debug.contains(secret), "{secret:?} in {debug}");
    }
}

#[test]
fn a_cost_is_weaker_if_it_takes_less_memory_or_fewer_passes() {
    let base = KdfParams { m_cost: 1024, t_cost: 2, p_cost: 1 };
    assert!(KdfParams { m_cost: 512, ..base }.is_weaker_than(&base));
    assert!(KdfParams { t_cost: 1, ..base }.is_weaker_than(&base));
    assert!(!base.is_weaker_than(&base));
    assert!(!KdfParams { m_cost: 2048, ..base }.is_weaker_than(&base));
    assert!(KdfParams::LEGACY.is_weaker_than(&KdfParams::DEFAULT));
}
