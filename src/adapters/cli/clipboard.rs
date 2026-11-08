//! The clipboard, for secrets: what `copy` puts there stays out of clipboard
//! managers' history and is cleared after a while.

use std::{
    sync::{Arc, Mutex, PoisonError},
    thread,
    time::Duration,
};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// How long a copied secret stays on the clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(30);

/// The system clipboard as the CLI uses it. Tests use a fake.
pub trait Backend: Send + 'static {
    /// Puts `text` on the clipboard, marked as a secret so that clipboard
    /// managers leave it out of their history.
    fn set_secret(&mut self, text: &str) -> Result<(), String>;
    /// What the clipboard holds now, whoever put it there.
    fn text(&mut self) -> Result<String, String>;
    fn clear(&mut self) -> Result<(), String>;
}

/// Copies secrets and clears each one `clear_after` later, unless the
/// clipboard changed in the meantime: a newer copy, here or in another
/// program, is left alone. Dropping it clears a copy still pending.
pub struct SecretClipboard<B: Backend> {
    state: Arc<Mutex<State<B>>>,
    /// `None`: no timer, copies stay until [`Self::expire`] (tests).
    clear_after: Option<Duration>,
}

struct State<B> {
    backend: B,
    /// Number of the latest copy.
    copies: u64,
    /// SHA-256 of the latest copy while it may still be on the clipboard.
    /// A hash, so the secret itself isn't kept around for the timer.
    pending: Option<[u8; 32]>,
}

impl<B: Backend> SecretClipboard<B> {
    pub fn new(backend: B, clear_after: Option<Duration>) -> Self {
        let state = State { backend, copies: 0, pending: None };
        Self { state: Arc::new(Mutex::new(state)), clear_after }
    }

    /// Puts `text` on the clipboard and schedules its clearing. Returns the
    /// number of this copy.
    pub fn copy(&self, text: &str) -> Result<u64, String> {
        let copy = {
            let mut state = lock(&self.state);
            state.backend.set_secret(text)?;
            state.copies += 1;
            state.pending = Some(Sha256::digest(text.as_bytes()).into());
            state.copies
        };
        if let Some(delay) = self.clear_after {
            let state = Arc::clone(&self.state);
            thread::spawn(move || {
                thread::sleep(delay);
                lock(&state).clear(copy);
            });
        }
        Ok(copy)
    }

    /// What the timer of copy number `copy` does, without the wait: clears
    /// the clipboard if it still holds that copy and no newer one was made.
    #[cfg(test)]
    pub fn expire(&self, copy: u64) {
        lock(&self.state).clear(copy);
    }
}

impl<B: Backend> Drop for SecretClipboard<B> {
    fn drop(&mut self) {
        let mut state = lock(&self.state);
        let latest = state.copies;
        state.clear(latest);
    }
}

impl<B: Backend> State<B> {
    fn clear(&mut self, copy: u64) {
        if copy != self.copies {
            return; // a newer copy has its own timer
        }
        let Some(pending) = self.pending.take() else {
            return; // already cleared
        };
        // Only what we put there: the user may have copied something else.
        let still_ours = self.backend.text().is_ok_and(|text| {
            let text = Zeroizing::new(text);
            Sha256::digest(text.as_bytes())[..] == pending[..]
        });
        if still_ours {
            let _ = self.backend.clear();
        }
    }
}

/// A timer thread can't panic while holding the lock, but don't make that a
/// reason for the CLI to die.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The system clipboard, through `arboard`.
pub struct SystemClipboard(arboard::Clipboard);

impl SystemClipboard {
    pub fn new() -> Result<Self, String> {
        arboard::Clipboard::new().map(Self).map_err(|e| e.to_string())
    }
}

impl Backend for SystemClipboard {
    fn set_secret(&mut self, text: &str) -> Result<(), String> {
        let set = self.0.set();
        // The `x-kde-passwordManagerHint` convention, honoured by most Linux
        // clipboard managers. It also keeps arboard from handing the text to
        // a clipboard manager when the program exits.
        #[cfg(all(
            unix,
            not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
        ))]
        let set = arboard::SetExtLinux::exclude_from_history(set);
        set.text(text).map_err(|e| e.to_string())
    }

    fn text(&mut self) -> Result<String, String> {
        self.0.get_text().map_err(|e| e.to_string())
    }

    fn clear(&mut self) -> Result<(), String> {
        self.0.clear().map_err(|e| e.to_string())
    }
}
