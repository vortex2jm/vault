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
