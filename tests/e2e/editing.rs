//! Line editing at the REPL prompt: Tab, history and cursor keys.

use crate::support::{CTRL_C, CTRL_D, CTRL_U, LEFT, Session, TAB, TempDir, UP};

#[test]
fn tab_completes_command_names() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.keys(&[b"hel".as_slice(), TAB, b"\r"].concat());
    assert!(s.output().contains("create <name>"));
    s.exit();
}

#[test]
fn names_with_spaces_go_in_quotes() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.command(r#"add "My Bank" "joao silva""#);
    s.answer("Service password: ", "0099");
    s.answer("Notes (optional): ", "");
    s.expect("Entry 'My Bank' added.");
    // Tab writes the quotes.
    s.keys(&[b"get My".as_slice(), TAB].concat());
    s.expect(r#"get "My Bank""#);
    s.send(b"\r");
    let out = s.output();
    assert!(out.contains("user: joao silva") && out.contains("pass: 0099"), "{out}");
    s.command(r#"get "My Bank"#);
    s.expect("A quote is never closed.");
    s.exit_discarding();
}

#[test]
fn tab_completes_entry_names() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.add("github", "alice", "hunter2");
    s.add("bank", "bob", "s3cr3t");
    s.keys(&[b"get gi".as_slice(), TAB, b"\r"].concat());
    assert!(s.output().contains("pass: hunter2"));
    s.exit_discarding();
}

#[test]
fn tab_chains_a_command_and_its_argument() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.add("github", "alice", "hunter2");
    // "up" + Tab → "update ", then "gi" + Tab → "update github".
    s.keys(&[b"up".as_slice(), TAB, b"gi", TAB, b"\r"].concat());
    s.answer("New username (blank to keep): ", "");
    s.answer("New password (blank to keep): ", "");
    s.answer("Notes: ", ""); // Enter keeps the pre-filled notes
    s.expect("Entry 'github' updated.");
    s.exit_discarding();
}

#[test]
fn tab_completes_vault_names() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.command("lock");
    s.expect("Vault locked.");
    s.keys(&[b"unlock pe".as_slice(), TAB, b"\r"].concat());
    s.answer("Vault password: ", "password");
    s.expect("Vault 'personal' unlocked.");
    s.exit();
}

#[test]
fn tab_completes_file_paths() {
    let home = TempDir::new();
    std::fs::write(
        home.file("passwords.csv"),
        "service,username,password\ngithub,alice,hunter2\n",
    )
    .unwrap();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.keys(&[b"import ~/pass".as_slice(), TAB, b"\r"].concat());
    assert!(s.output().contains("1 entry imported"));
    s.exit_discarding();
}

#[test]
fn up_arrow_recalls_the_previous_command() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.command("ls");
    assert!(s.output().contains("(no vaults found)"));
    s.keys(&[UP, b"\r"].concat());
    assert!(s.output().contains("(no vaults found)"));
    s.exit();
}

#[test]
fn left_arrow_moves_the_cursor() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    // Types "s", moves left, inserts "l": the line becomes "ls".
    s.keys(&[b"s".as_slice(), LEFT, b"l\r"].concat());
    assert!(s.output().contains("(no vaults found)"));
    s.exit();
}

#[test]
fn arrow_keys_edit_the_update_prompt() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.add("site", "alice", "pw");
    s.command("update site");
    s.expect("New username (blank to keep): ");
    // Ctrl-U clears the line; then "bob", left, "X" → "boXb". Arrow keys used
    // to end up in the username as escape sequences (B4).
    s.send(&[CTRL_U, b"bob", LEFT, b"X\r"].concat());
    s.answer("New password (blank to keep): ", "");
    s.answer("Notes: ", ""); // Enter keeps the pre-filled notes
    s.expect("Entry 'site' updated.");
    s.command("get site");
    let out = s.output();
    assert!(out.contains("user: boXb"), "{out}");
    s.exit_discarding();
}

#[test]
fn arrow_keys_work_in_confirmations() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.add("github", "alice", "hunter2");
    s.command("rm github");
    s.expect("Remove 'github'? (y/N): ");
    s.send(&[b"y".as_slice(), LEFT, b"\r"].concat());
    s.expect("Entry 'github' removed.");
    s.exit(); // added, then removed: nothing to commit
}

#[test]
fn ctrl_c_cancels_an_update() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.add("github", "alice", "hunter2");
    s.command("update github");
    s.expect("New username (blank to keep): ");
    s.send(CTRL_C);
    s.expect("Aborted.");
    s.command("get github");
    assert!(s.output().contains("user: alice"));
    s.exit_discarding();
}

#[test]
fn tab_does_not_offer_commands_in_answers() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "password");
    s.add("github", "alice", "hunter2");
    s.command("update github");
    s.expect("New username (blank to keep): ");
    s.send(&[b"c".as_slice(), TAB, b"\r"].concat());
    s.answer("New password (blank to keep): ", "");
    s.answer("Notes: ", ""); // Enter keeps the pre-filled notes
    s.expect("Entry 'github' updated.");
    s.command("get github");
    let out = s.output();
    assert!(out.contains("user: c\n"), "{out}");
    s.exit_discarding();
}

#[test]
fn ctrl_c_discards_the_line_without_exiting() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.keys(&[b"frobnicate".as_slice(), CTRL_C].concat());
    s.command("ls");
    let out = s.output();
    assert!(out.contains("(no vaults found)") && !out.contains("Unknown command"), "{out}");
    s.exit();
}

#[test]
fn ctrl_d_exits() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.keys(CTRL_D);
    assert!(s.wait().success());
}
