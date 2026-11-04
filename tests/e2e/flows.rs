//! Everyday flows through the CLI.

use crate::support::{MENU, Session, TempDir};

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
    s.create("personal", "pw");
    s.add("github", "alice", "hunter2");
    s.command("exit");
    s.answer(MENU, "1");
    assert!(s.wait().success());

    let mut s = Session::start(home.path());
    s.unlock("personal", "pw");
    s.command("ls");
    assert!(s.output().contains("github"));
    s.exit();
}

#[test]
fn exit_can_be_cancelled_or_discard_changes() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "pw");
    s.add("github", "alice", "hunter2");
    s.command("exit");
    s.answer(MENU, "3"); // cancel: still running, changes still pending
    assert_eq!(s.command("exit"), "vault[personal*|1]> ");
    s.answer(MENU, "2");
    assert!(s.wait().success());

    let mut s = Session::start(home.path());
    s.unlock("personal", "pw");
    s.command("ls");
    assert!(s.output().contains("(no entries)"));
    s.exit();
}

#[test]
fn a_wrong_password_keeps_the_vault_locked() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "right");
    s.exit();

    let mut s = Session::start(home.path());
    s.command("unlock personal");
    s.answer("Vault password: ", "wrong");
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
fn rm_asks_for_confirmation() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "pw");
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
    s.create("personal", "pw");
    s.add("github", "alice", "hunter2");
    s.command("update github");
    s.answer("New username (blank to keep): ", "bob");
    s.answer("New password (blank to keep): ", "");
    s.expect("Entry 'github' updated.");
    s.command("get github");
    let out = s.output();
    assert!(out.contains("user: bob") && out.contains("pass: hunter2"), "{out}");
    s.exit_discarding();
}

#[test]
fn ls_lists_vaults_when_locked_and_entries_when_unlocked() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("work", "pw");
    s.command("lock");
    s.expect("Vault locked.");
    s.create("personal", "pw");
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
fn info_shows_the_vault_name_and_entry_count() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "pw");
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
    s.create("source", "pw");
    s.add("github", "alice", "hunter2");
    s.command("export ~/out.csv");
    s.answer("Continue? (y/N): ", "y");
    s.expect("Vault exported to");
    assert!(home.file("out.csv").exists());
    s.command("lock");
    s.answer(MENU, "2");
    s.expect("Vault locked.");

    s.create("target", "pw");
    s.command("import ~/out.csv");
    assert!(s.output().contains("1 entry imported"));
    s.command("get github");
    assert!(s.output().contains("pass: hunter2"));
    s.exit_discarding();
}

#[test]
fn passwd_changes_the_master_password() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "old-pw");
    s.command("passwd");
    s.answer("Current password: ", "old-pw");
    s.answer("New password: ", "new-pw");
    s.answer("Confirm new password: ", "new-pw");
    s.expect("Password changed and vault re-committed.");
    s.command("lock");
    s.expect("Vault locked.");

    s.command("unlock personal");
    s.answer("Vault password: ", "old-pw");
    s.expect("Invalid password or corrupted vault");
    s.unlock("personal", "new-pw");
    s.exit();
}

#[test]
fn rename_and_drop_vaults() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("old", "pw");
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
    s.create("work", "pw");
    s.command("lock");
    s.expect("Vault locked.");
    s.create("personal", "pw");
    s.command("rename work");
    assert!(s.output().contains("Error: Vault already exists"));
    assert_eq!(s.command("lock"), "vault[personal|0]> ");
    s.expect("Vault locked.");
    s.command("ls");
    let out = s.output();
    assert!(out.contains("personal") && out.contains("work"), "{out}");
    s.exit();
}
