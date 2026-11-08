#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Lock,
    List,
    Info,
    Help,
    Exit,
    Commit,
    Clear,
    Passwd,
    Get(String),
    Unlock(String),
    Create(String),
    Remove(String),
    Rename(String),
    Copy(String),
    Export(String),
    Import(String),
    Update(String),
    Drop(String),
    Find(Option<String>),
    History(String),
    Gen(Option<usize>),
    Add { service: String, username: String },
    Move { from: String, to: String },
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
        "create", "unlock", "lock", "add", "get", "find", "history", "rm", "mv", "commit", "ls", "list",
        "update", "rename", "copy", "gen", "info", "export", "import",
        "drop", "passwd",
        "help", "exit", "clear",
    ];

    /// Parses a line typed at the prompt. Returns `None` for unknown commands
    /// and for commands missing a required argument.
    pub fn parse(input: &str) -> Option<Self> {
        let mut p = input.split_whitespace();
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
            "copy"   => Command::Copy(p.next()?.into()),
            "export" => Command::Export(p.next()?.into()),
            "import" => Command::Import(p.next()?.into()),
            "gen"    => Command::Gen(p.next().and_then(|s| s.parse().ok())),
            "commit" => Command::Commit,
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
