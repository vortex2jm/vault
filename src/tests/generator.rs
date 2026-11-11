//! Generated passwords and passphrases (`domain::generator`), drawn from a
//! fake source of randomness that just counts.

use std::collections::HashSet;

use crate::domain::generator::{self, PasswordOptions};

/// "Random" numbers 0, 1, 2, … (modulo the range asked for).
fn counting() -> impl FnMut(usize) -> usize {
    let mut next = 0;
    move |n| {
        next += 1;
        (next - 1) % n
    }
}

const ALL: PasswordOptions = PasswordOptions { symbols: true, ambiguous: true };

#[test]
fn the_charset_follows_the_options() {
    let cases = [
        (ALL, 70),
        (PasswordOptions { symbols: false, ..ALL }, 62),
        (PasswordOptions { ambiguous: false, ..ALL }, 64),
        (PasswordOptions { symbols: false, ambiguous: false }, 56),
    ];
    for (options, size) in cases {
        let charset = generator::charset(options);
        assert_eq!(charset.len(), size, "{options:?}");
        assert_eq!(charset.iter().collect::<HashSet<_>>().len(), size, "repeated characters");
    }
    let plain = generator::charset(PasswordOptions { symbols: false, ambiguous: false });
    assert!(plain.iter().all(|c| c.is_ascii_alphanumeric() && !"Il1O0o".contains(*c)), "{plain:?}");
    assert_eq!(PasswordOptions::default(), ALL);
}

#[test]
fn a_password_takes_each_character_from_the_charset() {
    let options = PasswordOptions { symbols: false, ..ALL };
    let charset = generator::charset(options);
    let password = generator::password(charset.len() + 3, options, counting());
    let expected: String = charset.iter().chain(&charset[..3]).collect();
    assert_eq!(password, expected);
}

#[test]
fn the_word_list_is_the_eff_one() {
    let words = generator::words();
    assert_eq!(words.len(), 7776);
    assert_eq!((words[0], words[7775]), ("abacus", "zoom"));
    assert_eq!(words.iter().collect::<HashSet<_>>().len(), 7776);
}

#[test]
fn a_passphrase_is_words_joined_by_hyphens() {
    assert_eq!(generator::passphrase(3, counting()), "abacus-abdomen-abdominal");
}

#[test]
fn strength_is_reported_in_bits() {
    // 20 of 70 characters, and 6 of 7776 words.
    assert_eq!(generator::password_bits(20, ALL).round(), 123.0);
    assert_eq!(generator::password_bits(16, PasswordOptions { symbols: false, ambiguous: false }).round(), 93.0);
    assert_eq!(generator::passphrase_bits(6).round(), 78.0);
}
