//! Domain models: `Entry` and `KdfParams`.

use crate::domain::models::{Entry, KdfParams};

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
fn notes_start_empty_and_can_be_replaced() {
    let mut entry = github();
    assert_eq!(entry.notes, "");
    entry.set_notes("2FA on the phone".into());
    assert_eq!(entry.notes, "2FA on the phone");
    entry.set_notes(String::new());
    assert_eq!(entry.notes, "");
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
