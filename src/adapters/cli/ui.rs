use rustyline::{
    Context, Helper,
    completion::{Completer, FilenameCompleter, Pair},
    highlight::Highlighter,
    hint::Hinter,
    validate::Validator,
};

use super::commands::{Argument, Command, Split, quoted};

/* =======================
   ANSI COLORS
======================= */
pub const BLUE: &str = "\x1b[34m";
pub const GREEN: &str = "\x1b[32m";
pub const RED: &str = "\x1b[31m";
pub const YELLOW: &str = "\x1b[33m";
pub const CYAN: &str = "\x1b[36m";
pub const RESET: &str = "\x1b[0m";

/// Line-editing helper: context-aware Tab completion.
pub struct VaultHelper {
    commands: Vec<&'static str>,
    entries: Vec<String>,
    vaults: Vec<String>,
    files: FilenameCompleter,
}

/// Implementing traits for VaultHelper to enable autocompletion, validation, and hints in the CLI
impl Helper for VaultHelper {}

/// Empty implementations for Validator and Highlighter, as we don't have specific validation or highlighting logic
impl Validator for VaultHelper {}

/// Empty implementation for Highlighter, as we don't have specific highlighting logic
impl Highlighter for VaultHelper {}

/// Implementing Hinter to provide hints for commands, currently unused but can be extended in the future
impl Hinter for VaultHelper {
    type Hint = String;
}

/// Completes the word under the cursor according to where it is:
/// - first word: command names;
/// - first argument: entry names (`get`, `copy`, `update`, `rm`), vault names
///   (`unlock`, `drop`) or file paths (`import`, `export`);
/// - anywhere else, or where a new name goes: nothing.
impl Completer for VaultHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        // Only the word under the cursor is replaced, quotes and all: words
        // are split as the parser splits them.
        let split = Split::of(&line[..pos]);
        let word = split.current.as_deref().unwrap_or("");
        let in_quotes = split.quote.is_some();

        let candidates = match split.words.as_slice() {
            [] => self.complete_command(word),
            [command] => match Command::first_argument(command) {
                Some(Argument::Entry) => matching(&self.entries, word, in_quotes),
                Some(Argument::Vault) => matching(&self.vaults, word, in_quotes),
                Some(Argument::Path) => return self.files.complete(line, pos, ctx),
                Some(Argument::Free) | None => Vec::new(),
            },
            _ => Vec::new(),
        };
        Ok((split.start, candidates))
    }
}

impl VaultHelper {
    pub fn new(commands: Vec<&'static str>) -> Self {
        Self {
            commands,
            entries: Vec::new(),
            vaults: Vec::new(),
            files: FilenameCompleter::new(),
        }
    }

    /// Sets the entry and vault names Tab offers. The CLI calls this before
    /// each prompt, so the names follow `add`, `rm`, `lock`, `create`…
    pub fn set_names(&mut self, mut entries: Vec<String>, mut vaults: Vec<String>) {
        entries.sort();
        vaults.sort();
        self.entries = entries;
        self.vaults = vaults;
    }

    /// Command names starting with `word`. Commands that take an argument get
    /// a trailing space, so the argument can be typed (or completed) next.
    fn complete_command(&self, word: &str) -> Vec<Pair> {
        self.commands
            .iter()
            .filter(|name| name.starts_with(word))
            .map(|name| Pair {
                display: name.to_string(),
                replacement: match Command::first_argument(name) {
                    Some(_) => format!("{name} "),
                    None => name.to_string(),
                },
            })
            .collect()
    }
}

/// The `names` that start with `word`, written so they come back as one
/// word: in quotes if they need them, or if the user opened one.
fn matching(names: &[String], word: &str, in_quotes: bool) -> Vec<Pair> {
    names
        .iter()
        .filter(|name| name.starts_with(word))
        .map(|name| Pair {
            display: name.clone(),
            replacement: match quoted(name) {
                plain if in_quotes && &plain == name => format!("\"{name}\""),
                written => written,
            },
        })
        .collect()
}
