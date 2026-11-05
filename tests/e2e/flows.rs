//! Everyday flows through the CLI.

use crate::support::{CTRL_U, MENU, Session, TempDir};

#[test]
fn entries_survive_commit_and_a_new_session() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "master-pw");
    s.add("github", "alice", "hunter2");
    assert_eq!(s.command("get github"), "vault[personal*|1]> ");
    let out = s.output();
    assert!(out.contains("user: alice") && out.contains("pass: hunter2"), "{out}");
    s.command("commit");
    s.expect("Changes committed.");
    assert_eq!(s.command("exit"), "vault[personal|1]> ");
    assert!(s.wait().success());

    let mut s = Session::start(home.path());
    s.unlock("personal", "master-pw");
    s.command("get github");
    assert!(s.output().contains("pass: hunter2"));
    s.exit();
}

#[test]
fn exit_offers_to_commit_pending_changes() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.add("github", "alice", "hunter2");
    s.command("exit");
    s.answer(MENU, "1");
    assert!(s.wait().success());

    let mut s = Session::start(home.path());
    s.unlock("personal", "password");
    s.command("ls");
    assert!(s.output().contains("github"));
    s.exit();
}

#[test]
fn a_stale_session_cannot_overwrite_newer_changes() {
    let home = TempDir::new();
    let mut first = Session::start(home.path());
    first.create("shared", "password");
    let mut second = Session::start(home.path());
    second.unlock("shared", "password");

    first.add("from-first", "u", "p");
    first.command("commit");
    first.expect("Changes committed.");
    second.add("from-second", "u", "p");
    second.command("commit");
    assert!(second.output().contains("changed on disk"));

    // "Commit and exit" fails the same way, and keeps the session open
    // instead of quitting with the changes.
    second.command("exit");
    second.answer(MENU, "1");
    second.expect("changed on disk");
    assert_eq!(second.command("exit"), "vault[shared*|1]> ");
    second.answer(MENU, "2");
    assert!(second.wait().success());
    first.exit();

    let mut check = Session::start(home.path());
    check.unlock("shared", "password");
    check.command("ls");
    let out = check.output();
    assert!(out.contains("from-first") && !out.contains("from-second"), "{out}");
    check.exit();
}

#[test]
fn exit_can_be_cancelled_or_discard_changes() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.add("github", "alice", "hunter2");
    s.command("exit");
    s.answer(MENU, "3"); // cancel: still running, changes still pending
    assert_eq!(s.command("exit"), "vault[personal*|1]> ");
    s.answer(MENU, "2");
    assert!(s.wait().success());

    let mut s = Session::start(home.path());
    s.unlock("personal", "password");
    s.command("ls");
    assert!(s.output().contains("(no entries)"));
    s.exit();
}

#[test]
fn a_wrong_password_keeps_the_vault_locked() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "right-password");
    s.exit();

    let mut s = Session::start(home.path());
    s.command("unlock personal");
    s.answer("Vault password: ", "wrong-password");
    s.expect("Invalid password or corrupted vault");
    assert_eq!(s.command("ls"), "vault[locked]> ");
    assert!(s.output().contains("personal"));
    s.exit();
}

#[test]
fn a_mismatched_confirmation_creates_nothing() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.command("create personal");
    s.answer("New vault password: ", "one");
    s.answer("Confirm password: ", "two");
    s.expect("Passwords do not match.");
    assert_eq!(s.command("ls"), "vault[locked]> ");
    assert!(s.output().contains("(no vaults found)"));
    s.exit();
}

#[test]
fn a_short_master_password_is_refused() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.command("create personal");
    s.answer("New vault password: ", "short");
    s.answer("Confirm password: ", "short");
    s.expect("The master password must have at least 8 characters");
    assert_eq!(s.command("ls"), "vault[locked]> ");
    assert!(s.output().contains("(no vaults found)"));

    s.create("personal", "long-enough");
    s.command("passwd");
    s.answer("Current password: ", "long-enough");
    s.answer("New password: ", "short");
    s.answer("Confirm new password: ", "short");
    s.expect("The master password must have at least 8 characters");
    s.command("lock");
    s.expect("Vault locked.");
    s.unlock("personal", "long-enough");
    s.exit();
}

#[test]
fn rm_asks_for_confirmation() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.add("github", "alice", "hunter2");
    s.command("rm github");
    s.answer("Remove 'github'? (y/N): ", "n");
    s.expect("Aborted.");
    s.command("rm github");
    s.answer("Remove 'github'? (y/N): ", "y");
    s.expect("Entry 'github' removed.");
    s.command("ls");
    assert!(s.output().contains("(no entries)"));
    s.exit_discarding();
}

#[test]
fn update_changes_only_the_fields_given() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.add("github", "alice", "hunter2");
    s.command("update github");
    s.answer("New username (blank to keep): ", "bob");
    s.answer("New password (blank to keep): ", "");
    s.answer("Notes: ", ""); // Enter keeps the pre-filled notes
    s.expect("Entry 'github' updated.");
    s.command("get github");
    let out = s.output();
    assert!(out.contains("user: bob") && out.contains("pass: hunter2"), "{out}");
    s.exit_discarding();
}

#[test]
fn notes_can_be_added_shown_and_edited() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.add_with_notes("github", "alice", "hunter2", "2FA on the phone");
    s.command("get github");
    assert!(s.output().contains("notes: 2FA on the phone"));

    // update shows the current notes pre-filled; Ctrl-U clears them.
    s.command("update github");
    s.answer("New username (blank to keep): ", "");
    s.answer("New password (blank to keep): ", "");
    s.expect("Notes: 2FA on the phone");
    s.send(&[CTRL_U, b"backup codes in the safe\r"].concat());
    s.expect("Entry 'github' updated.");
    s.command("get github");
    let out = s.output();
    assert!(out.contains("notes: backup codes in the safe") && !out.contains("2FA"), "{out}");

    // An entry without notes has no notes line.
    s.add("bank", "bob", "s3cr3t");
    s.command("get bank");
    assert!(!s.output().contains("notes:"));
    s.exit_discarding();
}

#[test]
fn history_lists_the_previous_passwords_newest_first() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.add("github", "alice", "first-pw");
    s.command("history github");
    s.expect("(no previous passwords for 'github')");

    for password in ["second-pw", "third-pw"] {
        s.command("update github");
        s.answer("New username (blank to keep): ", "");
        s.answer("New password (blank to keep): ", password);
        s.answer("Notes: ", "");
        s.expect("Entry 'github' updated.");
    }
    s.command("history github");
    let out = s.output();
    let (second, first) = (out.find("second-pw"), out.find("first-pw"));
    assert!(second.is_some() && first.is_some() && second < first, "newest first: {out}");
    assert!(!out.contains("third-pw"), "the current password is not history: {out}");

    s.command("history nope");
    s.expect("Entry not found");
    s.exit_discarding();
}

#[test]
fn ls_lists_vaults_when_locked_and_entries_when_unlocked() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("work", "password");
    s.command("lock");
    s.expect("Vault locked.");
    s.create("personal", "password");
    s.add("github", "alice", "hunter2");
    s.command("ls");
    let out = s.output();
    assert!(out.contains("github") && !out.contains("work"), "{out}");
    s.command("lock");
    s.answer(MENU, "1");
    s.expect("Vault locked.");
    s.command("ls");
    let out = s.output();
    assert!(out.contains("personal") && out.contains("work"), "{out}");
    s.exit();
}

#[test]
fn an_old_vault_is_upgraded_when_unlocked() {
    let home = TempDir::new();
    std::fs::create_dir(home.file(".vault")).unwrap();
    std::fs::copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v0.vault"),
        home.file(".vault").join("fixture.vault"),
    )
    .unwrap();

    let mut s = Session::start(home.path());
    s.command("unlock fixture");
    s.answer("Vault password: ", "fixture-password");
    s.expect("Upgraded to the current file format and key strength.");
    s.command("info");
    let out = s.output();
    assert!(out.contains("Key    : Argon2id, 128 MiB, 3 passes"), "{out}");
    s.command("get github");
    assert!(s.output().contains("pass: hunter2"));
    s.exit();
}

#[test]
fn info_shows_the_vault_name_and_entry_count() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.add("github", "alice", "hunter2");
    s.command("info");
    let out = s.output();
    assert!(out.contains("Vault : personal") && out.contains("Entries: 1"), "{out}");
    s.exit_discarding();
}

#[test]
fn gen_prints_a_password_of_the_requested_length() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.command("gen 16");
    let out = s.output();
    let password = out
        .lines()
        .find_map(|line| line.strip_prefix("Generated: "))
        .unwrap_or_else(|| panic!("no password printed: {out}"));
    assert_eq!(password.len(), 16);
    s.exit();
}

#[test]
fn gen_rejects_lengths_out_of_range_without_crashing() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    for length in ["4", "99999999999"] {
        s.command(&format!("gen {length}"));
        let out = s.output();
        assert!(out.contains("Error: Password length must be between 8 and 256"), "{out}");
    }
    s.exit();
}

#[test]
fn clear_erases_the_screen_and_the_scrollback() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.command("clear");
    s.output();
    let raw = s.raw();
    // 3J matters most: it removes passwords shown by `get` from the scrollback.
    for sequence in [b"\x1b[2J".as_slice(), b"\x1b[3J"] {
        assert!(
            raw.windows(sequence.len()).any(|w| w == sequence),
            "missing {:?}",
            String::from_utf8_lossy(sequence)
        );
    }
    s.exit();
}

#[test]
fn unknown_commands_show_a_hint() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.command("frobnicate");
    assert!(s.output().contains("Unknown command"));
    s.exit();
}

#[test]
fn export_and_import_between_vaults() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("source", "password");
    s.add("github", "alice", "hunter2");
    s.command("export ~/out.csv");
    s.answer("Continue? (y/N): ", "y");
    s.expect("Vault exported to");
    assert!(home.file("out.csv").exists());
    s.command("lock");
    s.answer(MENU, "2");
    s.expect("Vault locked.");

    s.create("target", "password");
    s.command("import ~/out.csv");
    assert!(s.output().contains("1 entry imported"));
    s.command("get github");
    assert!(s.output().contains("pass: hunter2"));
    s.exit_discarding();
}

#[test]
fn export_refuses_to_overwrite_an_existing_file() {
    let home = TempDir::new();
    std::fs::write(home.file("precious.csv"), "precious").unwrap();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.command("export ~/precious.csv");
    s.answer("Continue? (y/N): ", "y");
    s.expect("already exists: choose another file");
    assert_eq!(std::fs::read_to_string(home.file("precious.csv")).unwrap(), "precious");
    s.exit();
}

#[test]
fn passwd_changes_the_master_password() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "old-password");
    s.command("passwd");
    s.answer("Current password: ", "old-password");
    s.answer("New password: ", "new-password");
    s.answer("Confirm new password: ", "new-password");
    s.expect("Password changed and vault re-committed.");
    s.command("lock");
    s.expect("Vault locked.");

    s.command("unlock personal");
    s.answer("Vault password: ", "old-password");
    s.expect("Invalid password or corrupted vault");
    s.unlock("personal", "new-password");
    s.exit();
}

#[test]
fn rename_and_drop_vaults() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("old", "password");
    s.command("rename new");
    s.expect("Vault renamed to 'new'.");
    s.command("lock");
    s.expect("Vault locked.");
    s.command("ls");
    let out = s.output();
    assert!(out.contains("new") && !out.contains("old"), "{out}");

    s.command("drop new");
    s.answer("Delete vault 'new'? (y/N): ", "y");
    s.expect("Vault 'new' deleted.");
    s.command("ls");
    assert!(s.output().contains("(no vaults found)"));
    s.exit();
}

#[test]
fn rename_refuses_a_name_already_taken() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("work", "password");
    s.command("lock");
    s.expect("Vault locked.");
    s.create("personal", "password");
    s.command("rename work");
    assert!(s.output().contains("Error: Vault already exists"));
    assert_eq!(s.command("lock"), "vault[personal|0]> ");
    s.expect("Vault locked.");
    s.command("ls");
    let out = s.output();
    assert!(out.contains("personal") && out.contains("work"), "{out}");
    s.exit();
}
