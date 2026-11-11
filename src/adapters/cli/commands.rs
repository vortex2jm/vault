use crate::domain::{generator::PasswordOptions, models::Entry};

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Lock,
    List,
    Info,
    Help,
    Exit,
    Commit,
    Status,
    Discard,
    Restore,
    Health,
    Clear,
    Passwd,
    Get(String),
    Unlock(String),
    Create(String),
    Remove(String),
    Rename(String),
    Copy { service: String, field: Field },
    Export(String),
    Import(String),
    Update(String),
    Drop(String),
    Find(Option<String>),
    History(String),
    Gen(Generate),
    Add { service: String, username: String },
    Move { from: String, to: String },
}

/// What `gen` makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generate {
    /// `gen [length] [nosymbols] [noambiguous]`
    Password { length: Option<usize>, options: PasswordOptions },
    /// `gen words [count]`
    Passphrase { words: Option<usize> },
}

impl Generate {
    /// `gen`'s arguments, in any order; `None` for one it doesn't know.
    fn parse<'a>(mut args: impl Iterator<Item = &'a str>) -> Option<Self> {
        let mut first = args.next();
        if first == Some("words") {
            let words = args.next().map(str::parse).transpose().ok()?;
            return args.next().is_none().then_some(Generate::Passphrase { words });
        }
        let (mut length, mut options) = (None, PasswordOptions::default());
        while let Some(arg) = first.take().or_else(|| args.next()) {
            match arg {
                "nosymbols" => options.symbols = false,
                "noambiguous" => options.ambiguous = false,
                _ if length.is_none() => length = Some(arg.parse().ok()?),
                _ => return None,
            }
        }
        Some(Generate::Password { length, options })
    }
}

/// Which field of an entry `copy` takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Password,
    Username,
}

impl Field {
    /// `copy`'s optional second argument: the password unless it says
    /// otherwise.
    fn parse(word: Option<&str>) -> Option<Self> {
        match word {
            None | Some("pass" | "password") => Some(Field::Password),
            Some("user" | "username") => Some(Field::Username),
            Some(_) => None,
        }
    }

    pub fn of(self, entry: &Entry) -> &str {
        match self {
            Field::Password => &entry.passwd,
            Field::Username => &entry.username,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Field::Password => "Password",
            Field::Username => "Username",
        }
    }
}

/// What a command's first argument refers to, so Tab knows what to offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argument {
    /// An entry of the unlocked vault.
    Entry,
    /// An existing vault.
    Vault,
    /// A file path.
    Path,
    /// Free text, such as a new name or a length: nothing to offer.
    Free,
}

impl Command {
    /// What the first argument of command `name` refers to, or `None` if the
    /// command takes no argument.
    pub fn first_argument(name: &str) -> Option<Argument> {
        match name {
            "get" | "copy" | "update" | "rm" | "find" | "history" | "mv" => Some(Argument::Entry),
            "unlock" | "drop" => Some(Argument::Vault),
            "import" | "export" => Some(Argument::Path),
            "create" | "add" | "rename" | "gen" => Some(Argument::Free),
            _ => None,
        }
    }

    /// Every command name, as offered by Tab completion.
    pub const NAMES: &'static [&'static str] = &[
        "create", "unlock", "lock", "add", "get", "find", "history", "rm", "mv", "commit", "status", "discard", "restore", "health", "ls", "list",
        "update", "rename", "copy", "gen", "info", "export", "import",
        "drop", "passwd",
        "help", "exit", "clear",
    ];

    /// Parses a line typed at the prompt. Returns `None` for unknown commands
    /// and for commands missing a required argument.
    pub fn parse(input: &str) -> Option<Self> {
        let words = words(input).ok()?;
        let mut p = words.iter().map(String::as_str);
        let cmd = p.next()?;

        Some(match cmd {
            "unlock" => Command::Unlock(p.next()?.into()),
            "create" => Command::Create(p.next()?.into()),
            "add" => Command::Add {
                service: p.next()?.into(),
                username: p.next()?.into(),
            },
            "get"    => Command::Get(p.next()?.into()),
            "find"   => Command::Find(p.next().map(Into::into)),
            "history" => Command::History(p.next()?.into()),
            "rm"     => Command::Remove(p.next()?.into()),
            "mv"     => Command::Move {
                from: p.next()?.into(),
                to: p.next()?.into(),
            },
            "update" => Command::Update(p.next()?.into()),
            "rename" => Command::Rename(p.next()?.into()),
            "copy"   => Command::Copy {
                service: p.next()?.into(),
                field: Field::parse(p.next())?,
            },
            "export" => Command::Export(p.next()?.into()),
            "import" => Command::Import(p.next()?.into()),
            "gen"    => Command::Gen(Generate::parse(p)?),
            "commit" => Command::Commit,
            "status" => Command::Status,
            "discard" => Command::Discard,
            "restore" => Command::Restore,
            "health" => Command::Health,
            "ls" | "list" => Command::List,
            "lock"   => Command::Lock,
            "info"   => Command::Info,
            "drop"   => Command::Drop(p.next()?.into()),
            "passwd" => Command::Passwd,
            "help"   => Command::Help,
            "clear"  => Command::Clear,
            "exit"   => Command::Exit,
            _ => return None,
        })
    }
}

/// A quote opened in a line but never closed.
#[derive(Debug, PartialEq, Eq)]
pub struct UnclosedQuote;

/// The words of a typed line, as a shell splits them: `"..."` or `'...'`
/// keep spaces inside a word (`"My Bank"`), and outside single quotes `\`
/// takes the next character as it is (`My\ Bank`, `"say \"hi\""`).
pub fn words(input: &str) -> Result<Vec<String>, UnclosedQuote> {
    let split = Split::of(input);
    match split.quote {
        Some(_) => Err(UnclosedQuote),
        None => Ok(split.words.into_iter().chain(split.current).collect()),
    }
}

/// A line split into words up to some point, possibly in the middle of one:
/// what Tab completion needs to know.
pub struct Split {
    /// The finished words.
    pub words: Vec<String>,
    /// The word being typed, if any, as it reads without quotes and escapes.
    pub current: Option<String>,
    /// Byte index where the word being typed starts (at its opening quote,
    /// if it has one); the end of the text if no word is being typed.
    pub start: usize,
    /// The quote still open, if any.
    pub quote: Option<char>,
}

impl Split {
    pub fn of(text: &str) -> Self {
        let mut split = Split { words: Vec::new(), current: None, start: text.len(), quote: None };
        let mut chars = text.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            match (split.quote, c) {
                (None, c) if c.is_whitespace() => {
                    split.words.extend(split.current.take());
                    split.start = text.len();
                    continue;
                }
                (Some(q), c) if c == q => split.quote = None,
                (None, '"' | '\'') => split.quote = Some(c),
                (Some('\''), c) => split.current.get_or_insert_default().push(c),
                (_, '\\') => {
                    // Escapes anything outside quotes, only `"` and `\` inside
                    // double quotes. A lone one at the end is itself.
                    let escapes = |next: char| split.quote.is_none() || next == '"' || next == '\\';
                    let c = match chars.peek() {
                        Some(&(_, next)) if escapes(next) => {
                            chars.next();
                            next
                        }
                        _ => c,
                    };
                    split.current.get_or_insert_default().push(c);
                }
                (_, c) => split.current.get_or_insert_default().push(c),
            }
            if split.current.is_none() {
                split.current = Some(String::new()); // an opening quote starts a word
            }
            if split.start == text.len() {
                split.start = i;
            }
        }
        split
    }
}

/// `name` as it must be typed to come back as one word.
pub fn quoted(name: &str) -> String {
    let plain = !name.is_empty()
        && !name.chars().any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\'));
    if plain {
        name.to_string()
    } else {
        format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
    }
}
