//! Generated passwords and passphrases. The randomness comes from outside
//! (the crypto port's `random_below`), so this stays pure and testable.

use std::sync::LazyLock;

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*";
/// Easy to mistake for one another in many fonts.
const AMBIGUOUS: &str = "Il1O0o";

/// Which characters a generated password may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordOptions {
    pub symbols: bool,
    pub ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self { symbols: true, ambiguous: true }
    }
}

/// The characters a password with `options` draws from.
pub fn charset(options: PasswordOptions) -> Vec<char> {
    let symbols = if options.symbols { SYMBOLS } else { "" };
    [UPPER, LOWER, DIGITS, symbols]
        .concat()
        .chars()
        .filter(|c| options.ambiguous || !AMBIGUOUS.contains(*c))
        .collect()
}

/// `length` characters from `charset(options)`. `below(n)` must return a
/// uniformly random number in `0..n`.
pub fn password(length: usize, options: PasswordOptions, mut below: impl FnMut(usize) -> usize) -> String {
    let charset = charset(options);
    (0..length).map(|_| charset[below(charset.len())]).collect()
}

/// The EFF large wordlist (eff.org, CC BY 3.0 US), unchanged: a five-dice
/// code and a word per line. 7776 words, about 12.9 bits each.
static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    include_str!("eff_large_wordlist.txt")
        .lines()
        .filter_map(|line| line.split_once('\t').map(|(_, word)| word))
        .collect()
});

/// The words passphrases are made of.
pub fn words() -> &'static [&'static str] {
    &WORDS
}

/// `count` words from the list, joined by `-`. `below` as for [`password`].
pub fn passphrase(count: usize, mut below: impl FnMut(usize) -> usize) -> String {
    let words = words();
    (0..count).map(|_| words[below(words.len())]).collect::<Vec<_>>().join("-")
}

/// How hard a password with `options` is to guess, in bits.
pub fn password_bits(length: usize, options: PasswordOptions) -> f64 {
    length as f64 * (charset(options).len() as f64).log2()
}

/// How hard a passphrase of `count` words is to guess, in bits.
pub fn passphrase_bits(count: usize) -> f64 {
    count as f64 * (words().len() as f64).log2()
}
