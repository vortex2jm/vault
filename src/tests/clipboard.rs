//! The CLI's clipboard for secrets (`adapters::cli::clipboard`), on a fake
//! clipboard: a test must never touch the real one.

use std::{
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use crate::adapters::cli::clipboard::{Backend, SecretClipboard};

/// A clipboard in memory, shared with the test so it can look at it and
/// play another program.
#[derive(Clone, Default)]
struct Fake(Arc<Mutex<FakeState>>);

#[derive(Default)]
struct FakeState {
    text: Option<String>,
    secret: bool,
}

impl Fake {
    fn text(&self) -> Option<String> {
        self.0.lock().unwrap().text.clone()
    }

    fn is_secret(&self) -> bool {
        self.0.lock().unwrap().secret
    }

    /// Another program copies `text`.
    fn copy_elsewhere(&self, text: &str) {
        *self.0.lock().unwrap() = FakeState { text: Some(text.into()), secret: false };
    }
}

impl Backend for Fake {
    fn set_secret(&mut self, text: &str) -> Result<(), String> {
        *self.0.lock().unwrap() = FakeState { text: Some(text.into()), secret: true };
        Ok(())
    }

    fn text(&mut self) -> Result<String, String> {
        self.0.lock().unwrap().text.clone().ok_or_else(|| "empty".into())
    }

    fn clear(&mut self) -> Result<(), String> {
        *self.0.lock().unwrap() = FakeState::default();
        Ok(())
    }
}

/// A clipboard with no timer: copies expire only through `expire`.
fn without_timer() -> (Fake, SecretClipboard<Fake>) {
    let fake = Fake::default();
    (fake.clone(), SecretClipboard::new(fake, None))
}

#[test]
fn a_copy_is_marked_secret_and_cleared_when_it_expires() {
    let (fake, clipboard) = without_timer();
    let copy = clipboard.copy("hunter2").unwrap();
    assert_eq!(fake.text().as_deref(), Some("hunter2"));
    assert!(fake.is_secret(), "clipboard managers would keep it in their history");
    clipboard.expire(copy);
    assert_eq!(fake.text(), None);
}

#[test]
fn an_older_copy_expiring_leaves_a_newer_one_alone() {
    let (fake, clipboard) = without_timer();
    let first = clipboard.copy("hunter2").unwrap();
    let second = clipboard.copy("alice").unwrap();
    clipboard.expire(first);
    assert_eq!(fake.text().as_deref(), Some("alice"));
    clipboard.expire(second);
    assert_eq!(fake.text(), None);
}

#[test]
fn what_another_program_copied_is_never_cleared() {
    let (fake, clipboard) = without_timer();
    let copy = clipboard.copy("hunter2").unwrap();
    fake.copy_elsewhere("a link");
    clipboard.expire(copy);
    drop(clipboard);
    assert_eq!(fake.text().as_deref(), Some("a link"));
}

#[test]
fn closing_clears_a_copy_still_on_the_clipboard() {
    // The CLI's clipboard is dropped when the program exits.
    let (fake, clipboard) = without_timer();
    clipboard.copy("hunter2").unwrap();
    drop(clipboard);
    assert_eq!(fake.text(), None);
}

#[test]
fn the_timer_clears_the_copy() {
    let fake = Fake::default();
    let clipboard = SecretClipboard::new(fake.clone(), Some(Duration::from_millis(20)));
    clipboard.copy("hunter2").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while fake.text().is_some() {
        assert!(Instant::now() < deadline, "the timer never cleared the clipboard");
        thread::sleep(Duration::from_millis(5));
    }
    drop(clipboard); // alive until here: the timer cleared it, not the drop
}
