//! The health report (`domain::health`): reused and short passwords, and
//! how old each is.

use crate::domain::{
    health::{self, Health, SHORT_PASSWORD},
    models::{Entry, OldPassword},
};

/// An entry created at `created` whose password is `password`.
fn entry(service: &str, password: &str, created: i64) -> Entry {
    let mut entry = Entry::new(service.into(), "user".into(), password.into());
    entry.created_at = created;
    entry
}

#[test]
fn reused_passwords_come_in_sorted_groups() {
    let entries = [
        entry("wifi", "shared-password-1", 1),
        entry("bank", "shared-password-2", 1),
        entry("github", "shared-password-1", 1),
        entry("mail", "shared-password-2", 1),
        entry("gitlab", "shared-password-1", 1),
        entry("unique", "only-here-password", 1),
    ];
    let report = health::report(&entries);
    assert_eq!(report.reused, [vec!["bank", "mail"], vec!["github", "gitlab", "wifi"]]);
}

#[test]
fn short_passwords_are_counted_in_characters() {
    // "ç" is one character in two bytes.
    let (eleven, twelve) = ("ç".repeat(11), "ç".repeat(12));
    let entries = [
        entry("pin", "1234", 1),
        entry("empty", "", 1),
        entry("eleven", &eleven, 1),
        entry("twelve", &twelve, 1), // long enough
        entry("long", "a-much-longer-password", 1),
    ];
    assert_eq!(SHORT_PASSWORD, 12);
    let report = health::report(&entries);
    assert_eq!(
        report.short,
        [("eleven".to_string(), 11), ("empty".to_string(), 0), ("pin".to_string(), 4)]
    );
    assert!(report.reused.is_empty());
}

#[test]
fn a_password_is_as_old_as_its_last_change() {
    let mut changed = entry("changed", "second-password", 10);
    changed.history = vec![OldPassword { passwd: "first-password".into(), replaced_at: 50 }];
    let entries = [entry("newer", "pw-number-three", 30), changed, entry("older", "pw-number-four", 20)];
    let report = health::report(&entries);
    let ages: Vec<(&str, i64)> = report.ages.iter().map(|(s, t)| (s.as_str(), *t)).collect();
    assert_eq!(ages, [("older", 20), ("newer", 30), ("changed", 50)]);
}

#[test]
fn an_empty_vault_is_healthy() {
    assert_eq!(
        health::report(&[]),
        Health { reused: Vec::new(), short: Vec::new(), ages: Vec::new() }
    );
}
