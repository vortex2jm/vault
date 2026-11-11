//! A lean health report on a vault's passwords: which are reused, which are
//! short, and how old each is (that last one only as information). It never
//! shows a password.

use std::collections::HashMap;

use crate::domain::models::Entry;

/// Passwords shorter than this many characters are reported as short.
pub const SHORT_PASSWORD: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    /// Services sharing a password, in groups of two or more. Each group is
    /// sorted, and the groups by their first service.
    pub reused: Vec<Vec<String>>,
    /// Services whose password is shorter than [`SHORT_PASSWORD`], with its
    /// length in characters.
    pub short: Vec<(String, usize)>,
    /// Every service with when its password was set (Unix time), oldest first.
    pub ages: Vec<(String, i64)>,
}

/// The report for `entries`.
pub fn report<'a>(entries: impl IntoIterator<Item = &'a Entry>) -> Health {
    let entries: Vec<&Entry> = entries.into_iter().collect();

    let mut by_password: HashMap<&str, Vec<String>> = HashMap::new();
    for entry in &entries {
        by_password.entry(&entry.passwd).or_default().push(entry.service.clone());
    }
    let mut reused: Vec<Vec<String>> = by_password
        .into_values()
        .filter(|services| services.len() > 1)
        .map(|mut services| {
            services.sort();
            services
        })
        .collect();
    reused.sort();

    let mut short: Vec<(String, usize)> = entries
        .iter()
        .map(|entry| (entry.service.clone(), entry.passwd.chars().count()))
        .filter(|&(_, length)| length < SHORT_PASSWORD)
        .collect();
    short.sort();

    let mut ages: Vec<(String, i64)> = entries
        .iter()
        .map(|entry| (entry.service.clone(), entry.password_set_at()))
        .collect();
    ages.sort_by(|(a, a_set), (b, b_set)| a_set.cmp(b_set).then_with(|| a.cmp(b)));

    Health { reused, short, ages }
}
