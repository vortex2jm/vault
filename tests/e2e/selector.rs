//! The interactive selector (`find`): arrows, fuzzy filter, action menu.
//!
//! Every key waits for the redraw it causes before the next one is sent.
//! The copy actions are left out: they would need a real clipboard.

use crate::support::{CTRL_C, DOWN, ESC, Session, TempDir};

/// An unlocked vault with three entries: bank, github and gitlab.
fn with_entries(home: &TempDir) -> Session {
    let mut s = Session::start(home.path());
    s.create("personal", "pw");
    s.add("bank", "bob", "s3cr3t");
    s.add("github", "alice", "hunter2");
    s.add("gitlab", "carol", "tanuki");
    s
}

const ACTIONS: [&str; 5] = ["Copy password", "Copy username", "Show", "Update", "Remove"];

/// In the action menu of `service`, moves down to `action` and picks it.
fn choose(s: &mut Session, service: &str, action: &str) {
    let target = ACTIONS.iter().position(|a| *a == action).expect("unknown action");
    s.expect(&format!("? {service} ›"));
    s.expect(&format!("❯ {}", ACTIONS[0]));
    for next in &ACTIONS[1..=target] {
        s.send(DOWN);
        s.expect(&format!("❯ {next}"));
    }
    s.send(b"\r");
}

#[test]
fn arrows_pick_an_entry() {
    let home = TempDir::new();
    let mut s = with_entries(&home);
    s.command("find");
    s.expect("❯ bank");
    s.send(DOWN);
    s.expect("❯ github");
    s.send(b"\r");
    choose(&mut s, "github", "Show");
    s.expect("pass: hunter2");
    s.exit_discarding();
}

#[test]
fn typing_filters_the_list_fuzzily() {
    let home = TempDir::new();
    let mut s = with_entries(&home);
    s.command("find");
    s.expect("❯ bank");
    s.send(b"glb"); // g…l…b: only "gitlab" matches
    s.expect("❯ gitlab");
    s.send(b"\r");
    choose(&mut s, "gitlab", "Show");
    s.expect("pass: tanuki");
    s.exit_discarding();
}

#[test]
fn a_search_term_starts_the_list_filtered() {
    let home = TempDir::new();
    let mut s = with_entries(&home);
    s.command("find gitl");
    s.expect("❯ gitlab");
    s.send(b"\r");
    choose(&mut s, "gitlab", "Show");
    s.expect("pass: tanuki");
    s.exit_discarding();
}

#[test]
fn the_menu_runs_the_usual_commands() {
    let home = TempDir::new();
    let mut s = with_entries(&home);
    s.command("find bank");
    s.expect("❯ bank");
    s.send(b"\r");
    choose(&mut s, "bank", "Remove");
    s.answer("Remove 'bank'? (y/N): ", "y");
    s.expect("Entry 'bank' removed.");
    s.command("ls");
    let out = s.output();
    assert!(out.contains("github") && !out.contains("bank"), "{out}");
    s.exit_discarding();
}

#[test]
fn esc_cancels_the_list_and_the_menu() {
    let home = TempDir::new();
    let mut s = with_entries(&home);
    s.command("find");
    s.expect("❯ bank");
    s.send(ESC);
    s.expect("Aborted.");

    s.command("find");
    s.expect("❯ bank");
    s.send(b"\r");
    s.expect("? bank ›");
    s.send(ESC);
    s.expect("Aborted.");
    s.exit_discarding();
}

#[test]
fn ctrl_c_cancels_and_brings_the_cursor_back() {
    let home = TempDir::new();
    let mut s = with_entries(&home);
    s.command("find");
    s.expect("❯ bank");
    s.send(CTRL_C);
    s.expect("Aborted.");
    s.command("get bank");
    assert!(s.output().contains("pass: s3cr3t"));

    // The selector hides the cursor while it runs; it must be visible again.
    let raw = s.raw();
    let last = |seq: &[u8]| raw.windows(seq.len()).rposition(|w| w == seq);
    assert!(last(b"\x1b[?25h") > last(b"\x1b[?25l"), "cursor left hidden");
    s.exit_discarding();
}

#[test]
fn find_needs_an_unlocked_vault_with_entries() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.command("find");
    assert!(s.output().contains("Error: Vault is locked"));
    s.create("personal", "pw");
    s.command("find");
    assert!(s.output().contains("(no entries)"));
    s.exit();
}
