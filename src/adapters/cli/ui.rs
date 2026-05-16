use rustyline::{
    Helper,
    completion::{Completer, Pair},
    highlight::Highlighter,
    hint::Hinter,
    validate::Validator,
};

/* =======================
   ANSI COLORS
======================= */
pub const BLUE: &str = "\x1b[34m";
pub const GREEN: &str = "\x1b[32m";
pub const RED: &str = "\x1b[31m";
pub const YELLOW: &str = "\x1b[33m";
pub const CYAN: &str = "\x1b[36m";
pub const RESET: &str = "\x1b[0m";

/// Helper struct for command autocompletion and hints
pub struct VaultHelper {
    commands: Vec<&'static str>,
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

/// Implements command autocompletion based on available commands
impl Completer for VaultHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        // Find where the current token starts so only that token is replaced,
        // not the entire line. Scan backwards from the cursor position for a space.
        let start = line[..pos].rfind(' ').map(|i| i + 1).unwrap_or(0);
        let input = &line[start..pos];

        let matches = self
            .commands
            .iter()
            .filter(|cmd| cmd.starts_with(input))
            .map(|cmd| Pair {
                display: cmd.to_string(),
                replacement: cmd.to_string(),
            })
            .collect();

        Ok((start, matches))
    }
}

/// Constructor for VaultHelper to initialize it with a list of commands
impl VaultHelper {
    pub fn new(commands: Vec<&'static str>) -> Self {
        Self { commands }
    }
}
