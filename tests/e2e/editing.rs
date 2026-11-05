//! Line editing at the REPL prompt: Tab, history and cursor keys.

use crate::support::{CTRL_C, CTRL_D, LEFT, Session, TAB, TempDir, UP};

#[test]
fn tab_completes_command_names() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.keys(&[b"he".as_slice(), TAB, b"\r"].concat());
    assert!(s.output().contains("create <name>"));
    s.exit();
}

#[test]
fn tab_completes_entry_names() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "pw");
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
    s.create("personal", "pw");
    s.add("github", "alice", "hunter2");
    // "up" + Tab → "update ", then "gi" + Tab → "update github".
    s.keys(&[b"up".as_slice(), TAB, b"gi", TAB, b"\r"].concat());
    s.answer("New username (blank to keep): ", "");
    s.answer("New password (blank to keep): ", "");
    s.expect("Entry 'github' updated.");
    s.exit_discarding();
}

#[test]
fn tab_completes_vault_names() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "pw");
    s.command("lock");
    s.expect("Vault locked.");
    s.keys(&[b"unlock pe".as_slice(), TAB, b"\r"].concat());
    s.answer("Vault password: ", "pw");
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
    s.create("personal", "pw");
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
