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

/// Main CLI implementation, handling user input, commands, and interactions with the engine
impl<S: StoragePort, C: CryptoPort> VaultCli<S, C> {
    pub fn new(engine: VaultEngine<S, C>) -> Result<Self> {
        let helper = VaultHelper::new(vec![
            "create", "unlock", "lock", "add", "get", "rm", "commit", "ls", "list", "help", "exit",
            "clear",
        ]);

        let mut rl = Editor::<VaultHelper, DefaultHistory>::new()?;
        rl.set_helper(Some(helper));

        Ok(Self { engine, rl })
    }

    /// Main loop that runs the CLI, handling user input and commands
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
                    println!("Unknown command.\n");
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

    /// Parses user input into Command enum
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
            "get" => Command::Get(p.next()?.into()),
            "rm" => Command::Remove(p.next()?.into()),
            "commit" => Command::Commit,
            "ls" | "list" => Command::List,
            "lock" => Command::Lock,
            "help" => Command::Help,
            "clear" => Command::Clear,
            "exit" => Command::Exit,
            _ => return None,
        })
    }

    /// Handles parsed command and interacts with engine
    fn handle_command(&mut self, cmd: Command) -> Result<()> {
        match cmd {
            Command::Unlock(v) => {
                let mut pw = self.request_password("Vault password: ");
                self.engine.unlock(&v, &pw)?;
                pw.zeroize();
                println!("Vault '{}' unlocked.\n", v);
            }

            Command::Create(v) => {
                let mut pw = self.request_password("New vault password: ");
                self.engine.create_vault(&v, &pw)?;
                pw.zeroize();
                println!("Vault '{}' created.\n", v);
            }

            Command::Add { service, username } => {
                let mut pw = self.request_password("Service password: ");
                self.engine.add(&service, &username, &pw)?;
                pw.zeroize();
                println!("Entry '{}' added.\n", service);
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

            Command::List => {
                if self.engine.is_locked() {
                    for v in self.engine.get_vaults()? {
                        println!("  {}", v);
                    }
                } else {
                    for e in self.engine.get_entries()? {
                        println!("  {}", e);
                    }
                }
                println!();
            }

            Command::Lock => {
                if self.confirm_lock()? {
                    self.engine.lock()?;
                    println!("Vault locked.\n");
                } else {
                    println!("Aborted.\n");
                }
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

    /// Prints confirmation message when exiting with unsaved changes
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
                _ => Ok(false),
            }
        } else {
            Ok(true)
        }
    }

    /// Prints confirmation message when locking with unsaved changes
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
                _ => Ok(false),
            }
        } else {
            Ok(true)
        }
    }

    /// Generates dynamic prompt based on vault state
    /// - Locked: vault[locked]>
    /// - Unlocked: vault[vault_name|entry_count]>
    /// - Unlocked and dirty: vault[vault_name*|entry_count]>
    fn prompt(&self) -> String {
        if self.engine.is_locked() {
            format!("{BLUE}vault{RESET}[{RED}locked{RESET}]> ")
        } else {
            let name = self.engine.current_vault().unwrap_or("unknown".into());
            let dirty = self.engine.is_dirty();
            let count = self.engine.get_entries().unwrap_or_default().len();

            if dirty {
                format!(
                    "{BLUE}vault{RESET}[{GREEN}{name}{RESET}{YELLOW}*{RESET}|{CYAN}{count}{RESET}]> "
                )
            } else {
                format!("{BLUE}vault{RESET}[{GREEN}{name}{RESET}|{CYAN}{count}{RESET}]> ")
            }
        }
    }

    /// Prompts user for password without echoing
    fn request_password(&self, label: &str) -> String {
        print!("{}", label);
        io::stdout().flush().unwrap();
        rpassword::read_password().unwrap()
    }

    /// Prints confirmation message
    fn confirm(&self, msg: &str) -> bool {
        print!("{} (y/N): ", msg);
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).ok();
        matches!(input.trim(), "y" | "Y")
    }

    /// Prints help message
    fn print_help() {
        println!(
            r#"
create <name>        Create vault
unlock <name>        Unlock vault
lock                 Lock vault
add <svc> <user>     Add entry
get <svc>            Get entry
rm <svc>             Remove entry
commit               Save changes
ls                   List vaults or entries
clear                Clear terminal
help                 Show help
exit                 Exit
"#
        );
    }
}
