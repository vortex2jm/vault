pub(crate) mod clipboard;
pub(crate) mod commands;
mod input;
pub(crate) mod ui;

use anyhow::Result;
use dialoguer::{FuzzySelect, Select, theme::ColorfulTheme};
use rustyline::{Editor, error::ReadlineError, history::DefaultHistory};
use std::{
    io::{self, Write},
    time::Duration,
};
use zeroize::Zeroizing;

use crate::{
    application::engine::{Upgrade, VaultEngine},
    domain::ports::{CryptoPort, StoragePort},
};

use clipboard::{CLEAR_AFTER, SecretClipboard, SystemClipboard};
use commands::{Command, Field};
use input::Input;
use ui::{BLUE, CYAN, GREEN, RED, RESET, VaultHelper, YELLOW};

/// Vault CLI struct, containing the engine and readline editors
pub struct VaultCli<S: StoragePort, C: CryptoPort> {
    engine: VaultEngine<S, C>,
    /// The main prompt, read on its own thread.
    input: Input,
    /// Time at the main prompt without a command before an unlocked vault
    /// locks itself; `None`: never.
    auto_lock: Option<Duration>,
    /// Editor for answers (`update`'s username, confirmations, menus): line
    /// editing works, but there is no Tab completion and no history.
    answers: Editor<(), DefaultHistory>,
    /// Opened on the first copy: without a display there is none to open.
    /// Dropping it clears a copy still on the clipboard.
    clipboard: Option<SecretClipboard<SystemClipboard>>,
}

impl<S: StoragePort, C: CryptoPort> VaultCli<S, C> {
    pub fn new(engine: VaultEngine<S, C>, auto_lock: Option<Duration>) -> Result<Self> {
        let helper = VaultHelper::new(Command::NAMES.to_vec());

        let mut rl = Editor::<VaultHelper, DefaultHistory>::new()?;
        rl.set_helper(Some(helper));
        let input = Input::new(rl);
        let answers = Editor::<(), DefaultHistory>::new()?;

        Ok(Self { engine, input, auto_lock, answers, clipboard: None })
    }

    /// Main loop
    pub fn run(&mut self) -> Result<()> {
        println!("--- Vault CLI ---\n");

        loop {
            let line = match self.next_line()? {
                Ok(l) => l,
                Err(ReadlineError::Interrupted) => continue,
                Err(ReadlineError::Eof) => {
                    if self.confirm_exit()? {
                        break;
                    }
                    continue;
                }
                Err(e) => return Err(e.into()),
            };

            let input = line.trim();
            if input.is_empty() {
                continue;
            }

            let cmd = match Command::parse(input) {
                Some(c) => c,
                None => {
                    println!("Unknown command. Type 'help' for a list of commands.\n");
                    continue;
                }
            };

            if let Command::Exit = cmd {
                if self.confirm_exit()? {
                    break;
                }
                continue;
            }

            if let Err(e) = self.handle_command(cmd) {
                eprintln!("Error: {:#}\n", e);
            }
        }

        Ok(())
    }

    fn handle_command(&mut self, cmd: Command) -> Result<()> {
        match cmd {
            Command::Unlock(v) => {
                let pw = self.request_password("Vault password: ")?;
                let upgrade = self.engine.unlock(&v, &pw)?;
                println!("Vault '{}' unlocked.", v);
                match upgrade {
                    Upgrade::None => println!(),
                    Upgrade::Done => println!(
                        "Upgraded to the current file format and key strength. \
                         The previous file stays as the backup until your next commit.\n"
                    ),
                    Upgrade::Failed(e) => println!(
                        "{YELLOW}Warning:{RESET} could not upgrade the vault file ({e}); \
                         the next unlock will try again.\n"
                    ),
                }
            }

            Command::Create(v) => {
                let pw = self.request_password("New vault password: ")?;
                let pw2 = self.request_password("Confirm password: ")?;
                if pw != pw2 {
                    println!("{}Error:{} Passwords do not match.\n", RED, RESET);
                    return Ok(());
                }
                self.engine.create_vault(&v, &pw)?;
                println!("Vault '{}' created.\n", v);
            }

            Command::Add { service, username } => {
                let pw = self.request_password("Service password: ")?;
                let Some(notes) = self.ask("Notes (optional): ").map(Zeroizing::new) else {
                    println!("Aborted.\n");
                    return Ok(());
                };
                self.engine.add(&service, &username, &pw)?;
                let notes = notes.trim();
                if !notes.is_empty() {
                    self.engine.set_notes(&service, notes.to_string())?;
                }
                println!("Entry '{}' added.\n", service);
            }

            Command::Update(s) => {
                // An unknown entry fails right away, before any question.
                let current_notes = Zeroizing::new(self.engine.get(&s)?.notes.clone());
                println!("Updating entry '{s}'.");

                let Some(raw) = self.ask("New username (blank to keep): ") else {
                    println!("Aborted.\n");
                    return Ok(());
                };
                let new_username = raw.trim().to_string();

                let new_pw = self.request_password("New password (blank to keep): ")?;

                // The current notes come pre-filled, ready to be edited.
                let Some(notes) = self.ask_with_initial("Notes: ", &current_notes).map(Zeroizing::new)
                else {
                    println!("Aborted.\n");
                    return Ok(());
                };

                let username_opt = if new_username.is_empty() { None } else { Some(new_username) };
                let passwd_opt   = if new_pw.is_empty()       { None } else { Some(new_pw.to_string()) };

                self.engine
                    .update(&s, username_opt, passwd_opt)
                    .and_then(|()| self.engine.set_notes(&s, notes.trim().to_string()))?;
                println!("Entry '{}' updated.\n", s);
            }

            Command::Move { from, to } => {
                self.engine.rename_entry(&from, &to)?;
                println!("Entry '{from}' renamed to '{to}'.\n");
            }

            Command::Commit => {
                self.engine.commit()?;
                println!("Changes committed.\n");
            }

            Command::Remove(s) => {
                if self.confirm(&format!("Remove '{}'?", s)) {
                    self.engine.delete(&s)?;
                    println!("Entry '{}' removed.\n", s);
                } else {
                    println!("Aborted.\n");
                }
            }

            Command::Get(s) => {
                let e = self.engine.get(&s)?;
                println!("{}\n  user: {}\n  pass: {}", e.service, e.username, e.passwd);
                if !e.notes.is_empty() {
                    println!("  notes: {}", e.notes);
                }
                println!();
            }

            Command::History(s) => {
                let e = self.engine.get(&s)?;
                if e.history.is_empty() {
                    println!("  (no previous passwords for '{s}')\n");
                } else {
                    println!("{s}: previous passwords, newest first");
                    for old in &e.history {
                        println!("  {}  {}", local_time(old.replaced_at), old.passwd);
                    }
                    println!();
                }
            }

            Command::Copy { service, field } => {
                let text = Zeroizing::new(field.of(self.engine.get(&service)?).to_string());
                self.copy(&text)?;
                println!(
                    "{} for '{service}' copied to clipboard (cleared in {} s).\n",
                    field.label(),
                    CLEAR_AFTER.as_secs()
                );
            }

            Command::Find(filter) => self.find(filter.unwrap_or_default())?,

            Command::Gen(length) => {
                let len = length.unwrap_or(20);
                let pw = Zeroizing::new(self.engine.gen_password(len)?);
                println!("Generated: {}{}{}\n", CYAN, *pw, RESET);
            }

            Command::Info => {
                let (name, count) = self.engine.info()?;
                let kdf = self.engine.kdf_params()?;
                println!("{}Vault{} : {}{}{}", BLUE, RESET, GREEN, name, RESET);
                println!("{}Entries{}: {}{}{}", BLUE, RESET, CYAN, count, RESET);
                println!(
                    "{BLUE}Key{RESET}    : Argon2id, {} MiB, {} passes\n",
                    kdf.m_cost / 1024,
                    kdf.t_cost
                );
            }

            Command::Rename(new_name) => {
                self.engine.rename_vault(&new_name)?;
                println!("Vault renamed to '{}'.\n", new_name);
            }

            Command::Export(path) => {
                let path = expand_path(&path);
                println!(
                    "{}WARNING:{} This will write all passwords as plain text to '{}'.",
                    YELLOW, RESET, path
                );
                if self.confirm("Continue?") {
                    self.engine.export(&path)?;
                    println!("Vault exported to '{}'.\n", path);
                } else {
                    println!("Aborted.\n");
                }
            }

            Command::Import(path) => {
                let path = expand_path(&path);
                let count = self.engine.import(&path)?;
                if count > 0 {
                    println!(
                        "{} {} imported. Use 'commit' to save.\n",
                        count,
                        if count == 1 { "entry" } else { "entries" }
                    );
                } else {
                    println!("No new entries found (all services already exist).\n");
                }
            }

            Command::List => {
                if self.engine.is_locked() {
                    let vaults = self.engine.get_vaults()?;
                    if vaults.is_empty() {
                        println!("  (no vaults found)\n");
                    } else {
                        for v in vaults {
                            println!("  {}", v);
                        }
                        println!();
                    }
                } else {
                    let entries = self.engine.get_entries()?;
                    if entries.is_empty() {
                        println!("  (no entries)\n");
                    } else {
                        for e in entries {
                            println!("  {}", e);
                        }
                        println!();
                    }
                }
            }

            Command::Lock => {
                if self.confirm_lock()? {
                    self.engine.lock()?;
                    println!("Vault locked.\n");
                } else {
                    println!("Aborted.\n");
                }
            }

            Command::Drop(name) => {
                println!(
                    "{}WARNING:{} This permanently deletes vault '{}' and its backup.",
                    YELLOW, RESET, name
                );
                if self.confirm(&format!("Delete vault '{}'?", name)) {
                    self.engine.delete_vault(&name)?;
                    println!("Vault '{}' deleted.\n", name);
                } else {
                    println!("Aborted.\n");
                }
            }

            Command::Passwd => {
                let old_pw = self.request_password("Current password: ")?;
                let new_pw = self.request_password("New password: ")?;
                let new_pw2 = self.request_password("Confirm new password: ")?;
                if new_pw != new_pw2 {
                    println!("{}Error:{} New passwords do not match.\n", RED, RESET);
                    return Ok(());
                }
                self.engine.change_password(&old_pw, &new_pw)?;
                println!("Password changed and vault re-committed.\n");
            }

            Command::Clear => {
                // Home, erase the screen (2J) and the scrollback (3J): without
                // 3J, passwords shown by `get` stay one scroll away.
                print!("\x1b[H\x1b[2J\x1b[3J");
                io::stdout().flush().ok();
            }

            Command::Help => {
                Self::print_help();
                println!();
            }

            Command::Exit => unreachable!(),
        }
        Ok(())
    }

    fn confirm_exit(&mut self) -> Result<bool> {
        if self.engine.is_dirty() {
            println!("You have uncommitted changes.");
            println!("1) Commit and exit");
            println!("2) Exit without committing");
            println!("3) Cancel\n");

            match self.ask("Choose an option [1-3]: ").as_deref().map(str::trim) {
                Some("1") => Ok(self.commit_before_leaving()),
                Some("2") => Ok(true),
                _ => Ok(false),
            }
        } else {
            Ok(true)
        }
    }

    /// Commits for the exit and lock menus. If that fails, says why and keeps
    /// the session open, instead of leaving and losing the changes.
    fn commit_before_leaving(&mut self) -> bool {
        match self.engine.commit() {
            Ok(()) => true,
            Err(e) => {
                eprintln!("Error: {e}\n");
                false
            }
        }
    }

    fn confirm_lock(&mut self) -> Result<bool> {
        if self.engine.is_dirty() {
            println!("You have uncommitted changes.");
            println!("1) Commit and lock");
            println!("2) Lock without committing");
            println!("3) Cancel\n");

            match self.ask("Choose an option [1-3]: ").as_deref().map(str::trim) {
                Some("1") => Ok(self.commit_before_leaving()),
                Some("2") => Ok(true),
                _ => Ok(false),
            }
        } else {
            Ok(true)
        }
    }

    fn prompt(&self) -> String {
        if self.engine.is_locked() {
            format!("{BLUE}vault{RESET}[{RED}locked{RESET}]> ")
        } else {
            let name  = self.engine.current_vault().unwrap_or("unknown".into());
            let dirty = self.engine.is_dirty();
            let count = self.engine.get_entries().unwrap_or_default().len();

            if dirty {
                format!("{BLUE}vault{RESET}[{GREEN}{name}{RESET}{YELLOW}*{RESET}|{CYAN}{count}{RESET}]> ")
            } else {
                format!("{BLUE}vault{RESET}[{GREEN}{name}{RESET}|{CYAN}{count}{RESET}]> ")
            }
        }
    }

    /// Hands Tab completion the current entry and vault names.
    /// Shows the prompt and returns the line typed at it. While nobody types,
    /// an unlocked vault locks itself after `auto_lock`; with uncommitted
    /// changes it stays open instead, and a warning says so once.
    fn next_line(&mut self) -> Result<Result<String, ReadlineError>> {
        let entries = self.engine.get_entries().unwrap_or_default();
        let vaults = self.engine.get_vaults().unwrap_or_default();
        self.input.ask(self.prompt(), entries, vaults);

        let mut timeout = self.auto_lock.filter(|_| !self.engine.is_locked());
        loop {
            if let Some(line) = self.input.wait(timeout)? {
                return Ok(line);
            }
            let idle = describe(timeout.unwrap_or_default());
            timeout = None; // once per wait
            match self.engine.lock_if_clean() {
                Ok(true) => self.input.print(&format!("Vault locked after {idle} without activity.")),
                Ok(false) => self.input.print(&format!(
                    "{YELLOW}{idle} without activity, but the vault has uncommitted changes:{RESET} \
                     it stays open. Commit or discard them."
                )),
                Err(_) => {}
            }
        }
    }

    /// Prompts user for password without echoing.
    /// Reads a password without echoing it. It is wiped when dropped, on
    /// every path: a later prompt failing with `?` included.
    fn request_password(&self, label: &str) -> Result<Zeroizing<String>> {
        print!("{}", label);
        io::stdout().flush()?;
        Ok(Zeroizing::new(rpassword::read_password()?))
    }

    /// Interactive selector: pick an entry (arrows move, typing filters, Esc
    /// cancels), then choose what to do with it.
    fn find(&mut self, filter: String) -> Result<()> {
        let entries = self.engine.get_entries()?;
        if entries.is_empty() {
            println!("  (no entries)\n");
            return Ok(());
        }
        let theme = ColorfulTheme::default();

        let picked = FuzzySelect::with_theme(&theme)
            .with_prompt("Entry")
            .items(&entries)
            .with_initial_text(filter)
            // Highlight the best match from the start, so Enter picks it.
            .default(0)
            .max_length(10)
            .interact_opt();
        let Some(service) = chosen(picked)?.map(|i| entries[i].clone()) else {
            println!("Aborted.\n");
            return Ok(());
        };

        let action = Select::with_theme(&theme)
            .with_prompt(&service)
            .items(["Copy password", "Copy username", "Show", "History", "Update", "Remove"])
            .default(0)
            .interact_opt();
        match chosen(action)? {
            Some(0) => self.handle_command(Command::Copy { service, field: Field::Password }),
            Some(1) => self.handle_command(Command::Copy { service, field: Field::Username }),
            Some(2) => self.handle_command(Command::Get(service)),
            Some(3) => self.handle_command(Command::History(service)),
            Some(4) => self.handle_command(Command::Update(service)),
            Some(_) => self.handle_command(Command::Remove(service)),
            None => {
                println!("Aborted.\n");
                Ok(())
            }
        }
    }

    /// Puts `text` on the clipboard, kept out of clipboard managers' history
    /// and cleared after [`CLEAR_AFTER`] or when the program exits.
    fn copy(&mut self, text: &str) -> Result<()> {
        let clipboard = match &self.clipboard {
            Some(clipboard) => clipboard,
            None => {
                let system = SystemClipboard::new()
                    .map_err(|e| anyhow::anyhow!("Clipboard unavailable: {e}"))?;
                self.clipboard.insert(SecretClipboard::new(system, Some(CLEAR_AFTER)))
            }
        };
        clipboard.copy(text).map_err(|e| anyhow::anyhow!("Failed to copy: {e}"))?;
        Ok(())
    }

    /// Asks a yes/no question. Anything but `y` (Ctrl-C and Ctrl-D included) means no.
    fn confirm(&mut self, msg: &str) -> bool {
        matches!(
            self.ask(&format!("{msg} (y/N): ")).as_deref().map(str::trim),
            Some("y" | "Y")
        )
    }

    /// Asks a question answered on one line, with line editing (arrows,
    /// Ctrl-U…). `None` if the user pressed Ctrl-C or Ctrl-D.
    fn ask(&mut self, question: &str) -> Option<String> {
        self.answers.readline(question).ok()
    }

    /// Like [`Self::ask`], with `initial` already typed in, ready to edit.
    fn ask_with_initial(&mut self, question: &str, initial: &str) -> Option<String> {
        self.answers.readline_with_initial(question, (initial, "")).ok()
    }

    fn print_help() {
        println!(
            r#"
create <name>        Create vault (asks for password twice, 8+ characters)
unlock <name>        Unlock vault
lock                 Lock vault
passwd               Change vault master password (8+ characters)
drop <name>          Permanently delete a vault (must be locked first)
add <svc> <user>     Add entry (asks for its password and optional notes)
get <svc>            Show entry (user, pass, notes)
find [term]          Pick an entry from a list (arrows, type to filter)
history <svc>        Show the previous passwords of an entry
copy <svc> [user]    Copy password (or username) to clipboard, cleared after 30 s
update <svc>         Update username, password or notes of entry
mv <svc> <new>       Rename an entry
rm <svc>             Remove entry
commit               Save changes to disk
rename <new>         Rename current vault
gen [length]         Generate random password (8-256 chars, default: 20)
info                 Show vault info
ls                   List vaults (locked) or entries (unlocked)
export <path>        Export entries to CSV (plaintext!)
import <path>        Import entries from CSV file
clear                Clear the screen and the scrollback
help                 Show this help
exit                 Exit (prompts if unsaved changes)
"#
        );
    }
}

/// The choice made in a dialoguer list, with Ctrl-C treated like Esc: `None`.
fn chosen(result: dialoguer::Result<Option<usize>>) -> Result<Option<usize>> {
    match result {
        Err(dialoguer::Error::IO(e)) if e.kind() == io::ErrorKind::Interrupted => {
            // dialoguer leaves the cursor hidden when Ctrl-C interrupts it.
            eprint!("\x1b[?25h");
            println!();
            Ok(None)
        }
        other => Ok(other?),
    }
}

/// A Unix timestamp as local date and time, e.g. `2026-11-05 14:32`.
fn local_time(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "?".to_string())
}

/// Expands a leading `~` to the user's home directory.
pub(crate) fn expand_path(path: &str) -> String {
    if path.starts_with("~/") || path == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            let home = home.to_string_lossy();
            return format!("{}{}", home, &path[1..]);
        }
    }
    path.to_string()
}

/// How long an unlocked vault waits at the prompt before locking itself:
/// `VAULT_AUTO_LOCK` seconds, 5 minutes if unset, never if 0.
pub fn auto_lock(setting: Option<&str>) -> Result<Option<Duration>, String> {
    let Some(setting) = setting else {
        return Ok(Some(Duration::from_secs(5 * 60)));
    };
    match setting.trim().parse::<u64>() {
        Ok(0) => Ok(None),
        Ok(seconds) => Ok(Some(Duration::from_secs(seconds))),
        Err(_) => Err(format!("VAULT_AUTO_LOCK must be a number of seconds, not {setting:?}")),
    }
}

/// `5 min`, or `90 s` when it isn't whole minutes.
pub(crate) fn describe(duration: Duration) -> String {
    match duration.as_secs() {
        s if s % 60 == 0 => format!("{} min", s / 60),
        s => format!("{s} s"),
    }
}
