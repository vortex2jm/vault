mod commands;
mod ui;

use anyhow::Result;
use rustyline::{Editor, error::ReadlineError, history::DefaultHistory};
use std::io::{self, Write};
use zeroize::Zeroize;

use crate::{
    application::engine::VaultEngine,
    domain::ports::{CryptoPort, StoragePort},
};

use commands::Command;
use ui::{BLUE, CYAN, GREEN, RED, RESET, VaultHelper, YELLOW};

/// Vault CLI struct, containing the engine and readline editor
pub struct VaultCli<S: StoragePort, C: CryptoPort> {
    engine: VaultEngine<S, C>,
    rl: Editor<VaultHelper, DefaultHistory>,
}

impl<S: StoragePort, C: CryptoPort> VaultCli<S, C> {
    pub fn new(engine: VaultEngine<S, C>) -> Result<Self> {
        let helper = VaultHelper::new(vec![
            "create", "unlock", "lock", "add", "get", "rm", "commit", "ls", "list",
            "update", "rename", "copy", "gen", "info", "export", "import",
            "drop", "passwd",
            "help", "exit", "clear",
        ]);

        let mut rl = Editor::<VaultHelper, DefaultHistory>::new()?;
        rl.set_helper(Some(helper));

        Ok(Self { engine, rl })
    }

    /// Main loop
    pub fn run(&mut self) -> Result<()> {
        println!("--- Vault CLI ---\n");

        loop {
            let line = match self.rl.readline(&self.prompt()) {
                Ok(l) => {
                    self.rl.add_history_entry(l.as_str())?;
                    l
                }
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

            let cmd = match self.parse_command(input) {
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

    fn parse_command(&self, input: &str) -> Option<Command> {
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
            "rm"     => Command::Remove(p.next()?.into()),
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

    fn handle_command(&mut self, cmd: Command) -> Result<()> {
        match cmd {
            Command::Unlock(v) => {
                let mut pw = self.request_password("Vault password: ")?;
                let result = self.engine.unlock(&v, &pw);
                pw.zeroize();
                result?;
                println!("Vault '{}' unlocked.\n", v);
            }

            Command::Create(v) => {
                let mut pw = self.request_password("New vault password: ")?;
                let mut pw2 = self.request_password("Confirm password: ")?;
                let matches = pw == pw2;
                pw2.zeroize();
                if !matches {
                    pw.zeroize();
                    println!("{}Error:{} Passwords do not match.\n", RED, RESET);
                    return Ok(());
                }
                let result = self.engine.create_vault(&v, &pw);
                pw.zeroize();
                result?;
                println!("Vault '{}' created.\n", v);
            }

            Command::Add { service, username } => {
                let mut pw = self.request_password("Service password: ")?;
                let result = self.engine.add(&service, &username, &pw);
                pw.zeroize();
                result?;
                println!("Entry '{}' added.\n", service);
            }

            Command::Update(s) => {
                println!("Updating entry '{}'.", &s);

                print!("New username (blank to keep): ");
                io::stdout().flush().ok();
                let mut raw = String::new();
                io::stdin().read_line(&mut raw)?;
                let new_username = raw.trim().to_string();

                let mut new_pw = self.request_password("New password (blank to keep): ")?;
                println!();

                let username_opt = if new_username.is_empty() { None } else { Some(new_username) };
                let passwd_opt   = if new_pw.is_empty()       { None } else { Some(new_pw.clone()) };

                let result = self.engine.update(&s, username_opt, passwd_opt);
                new_pw.zeroize();
                result?;
                println!("Entry '{}' updated.\n", s);
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
                println!(
                    "{}\n  user: {}\n  pass: {}\n",
                    e.service, e.username, e.passwd
                );
            }

            Command::Copy(s) => {
                let e = self.engine.get(&s)?;
                let mut clipboard = arboard::Clipboard::new()
                    .map_err(|e| anyhow::anyhow!("Clipboard unavailable: {}", e))?;
                clipboard
                    .set_text(e.passwd.clone())
                    .map_err(|e| anyhow::anyhow!("Failed to copy: {}", e))?;
                println!("Password for '{}' copied to clipboard.\n", s);
            }

            Command::Gen(length) => {
                let len = length.unwrap_or(20);
                let pw = self.engine.gen_password(len);
                println!("Generated: {}{}{}\n", CYAN, pw, RESET);
            }

            Command::Info => {
                let (name, count) = self.engine.info()?;
                println!("{}Vault{} : {}{}{}", BLUE, RESET, GREEN, name, RESET);
                println!("{}Entries{}: {}{}{}\n", BLUE, RESET, CYAN, count, RESET);
            }

            Command::Rename(new_name) => {
                self.engine.rename_vault(&new_name)?;
                println!("Vault renamed to '{}'.\n", new_name);
            }

            Command::Export(path) => {
                let path = Self::expand_path(&path);
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
                let path = Self::expand_path(&path);
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
                let mut old_pw = self.request_password("Current password: ")?;
                let mut new_pw = self.request_password("New password: ")?;
                let mut new_pw2 = self.request_password("Confirm new password: ")?;
                let matches = new_pw == new_pw2;
                new_pw2.zeroize();
                if !matches {
                    old_pw.zeroize();
                    new_pw.zeroize();
                    println!("{}Error:{} New passwords do not match.\n", RED, RESET);
                    return Ok(());
                }
                let result = self.engine.change_password(&old_pw, &new_pw);
                old_pw.zeroize();
                new_pw.zeroize();
                result?;
                println!("Password changed and vault re-committed.\n");
            }

            Command::Clear => {
                print!("\x1b[2J\x1b[H");
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
            print!("Choose an option [1-3]: ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            match input.trim() {
                "1" => {
                    self.engine.commit()?;
                    Ok(true)
                }
                "2" => Ok(true),
                _   => Ok(false),
            }
        } else {
            Ok(true)
        }
    }

    fn confirm_lock(&mut self) -> Result<bool> {
        if self.engine.is_dirty() {
            println!("You have uncommitted changes.");
            println!("1) Commit and lock");
            println!("2) Lock without committing");
            println!("3) Cancel\n");
            print!("Choose an option [1-3]: ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;

            match input.trim() {
                "1" => {
                    self.engine.commit()?;
                    Ok(true)
                }
                "2" => Ok(true),
                _   => Ok(false),
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

    /// Prompts user for password without echoing.
    fn request_password(&self, label: &str) -> Result<String> {
        print!("{}", label);
        io::stdout().flush()?;
        Ok(rpassword::read_password()?)
    }

    fn confirm(&self, msg: &str) -> bool {
        print!("{} (y/N): ", msg);
        io::stdout().flush().ok();
        let mut input = String::new();
        io::stdin().read_line(&mut input).ok();
        matches!(input.trim(), "y" | "Y")
    }

    /// Expands a leading `~` to the user's home directory.
    fn expand_path(path: &str) -> String {
        if path.starts_with("~/") || path == "~" {
            if let Some(home) = std::env::var_os("HOME") {
                let home = home.to_string_lossy();
                return format!("{}{}", home, &path[1..]);
            }
        }
        path.to_string()
    }

    fn print_help() {
        println!(
            r#"
create <name>        Create vault (asks for password twice)
unlock <name>        Unlock vault
lock                 Lock vault
passwd               Change vault master password
drop <name>          Permanently delete a vault (must be locked first)
add <svc> <user>     Add entry
get <svc>            Show entry (user + pass)
copy <svc>           Copy password to clipboard
update <svc>         Update username/password of entry
rm <svc>             Remove entry
commit               Save changes to disk
rename <new>         Rename current vault
gen [length]         Generate random password (default: 20 chars)
info                 Show vault info
ls                   List vaults (locked) or entries (unlocked)
export <path>        Export entries to CSV (plaintext!)
import <path>        Import entries from CSV file
clear                Clear terminal
help                 Show this help
exit                 Exit (prompts if unsaved changes)
"#
        );
    }
}
