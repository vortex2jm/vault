//! Bugs still open in `BACKLOG.md` that only show up in a real terminal.
//! Same rules as `src/tests/known_bugs.rs`: remove the `#[ignore]` when the
//! item is fixed and move the test to the module of its area.

use crate::support::{CTRL_U, LEFT, Session, TempDir};

#[test]
#[ignore = "B4: arrow keys in sub-prompts are stored as escape sequences"]
fn b4_arrow_keys_must_edit_the_update_prompt() {
    let home = TempDir::new();
    let mut s = Session::start(home.path());
    s.create("personal", "pw");
    s.add("site", "alice", "pw");
    s.command("update site");
    s.expect("New username (blank to keep): ");
    // Ctrl-U clears whatever is pre-filled; then "bob", left, "X" → "boXb".
    s.send(&[CTRL_U, b"bob", LEFT, b"X\r"].concat());
    s.answer("New password (blank to keep): ", "");
    s.expect("Entry 'site' updated.");
    s.command("get site");
    let out = s.output();
    assert!(out.contains("user: boXb"), "{out}");
    s.exit_discarding();
}
