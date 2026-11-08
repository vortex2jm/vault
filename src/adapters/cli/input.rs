//! The main prompt, read on a thread of its own, so the CLI can still act
//! while nobody types: that is how an idle vault locks itself.
//!
//! Only the main prompt lives here. Everything else (password prompts, the
//! answers editor, the `find` selector) runs on the main thread while this
//! one waits for its next request, so the two never read the terminal at
//! the same time.

use std::{
    io::{self, Write},
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender},
    thread,
    time::Duration,
};

use rustyline::{Editor, error::ReadlineError, history::DefaultHistory};

use super::ui::VaultHelper;

/// What the reader needs to show the next prompt.
struct Request {
    prompt: String,
    entries: Vec<String>,
    vaults: Vec<String>,
}

/// The main prompt's line editor, on its own thread.
pub struct Input {
    requests: Sender<Request>,
    lines: Receiver<Result<String, ReadlineError>>,
    /// The prompt being shown, to show it again after [`Self::print`].
    prompt: String,
}

impl Input {
    pub fn new(mut editor: Editor<VaultHelper, DefaultHistory>) -> Self {
        let (requests, incoming) = mpsc::channel::<Request>();
        let (outgoing, lines) = mpsc::channel();
        thread::spawn(move || {
            for request in incoming {
                if let Some(helper) = editor.helper_mut() {
                    helper.set_names(request.entries, request.vaults);
                }
                let line = editor.readline(&request.prompt);
                if let Ok(line) = &line {
                    let _ = editor.add_history_entry(line.as_str());
                }
                if outgoing.send(line).is_err() {
                    break;
                }
            }
        });
        Self { requests, lines, prompt: String::new() }
    }

    /// Shows `prompt` and starts reading a line, with `entries` and `vaults`
    /// offered by Tab.
    pub fn ask(&mut self, prompt: String, entries: Vec<String>, vaults: Vec<String>) {
        self.prompt.clone_from(&prompt);
        // The reader only stops if this struct is gone.
        let _ = self.requests.send(Request { prompt, entries, vaults });
    }

    /// Waits for the line asked for, up to `timeout` (`None`: as long as it
    /// takes). `Ok(None)` means nobody typed it in time.
    pub fn wait(&self, timeout: Option<Duration>) -> anyhow::Result<Option<Result<String, ReadlineError>>> {
        let line = match timeout {
            None => self.lines.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(timeout) => self.lines.recv_timeout(timeout),
        };
        match line {
            Ok(line) => Ok(Some(line)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(anyhow::anyhow!("the prompt stopped")),
        }
    }

    /// Prints `text` on its own line while the prompt waits, then shows the
    /// prompt again. The reader thread is blocked reading meanwhile, so
    /// nothing else writes. Anything typed but not yet entered stays in the
    /// line, though no longer on screen.
    ///
    /// (rustyline's external printer would redraw that too, but in 17.0.2 it
    /// stalls on input arriving several bytes at once, such as a paste.)
    pub fn print(&self, text: &str) {
        let mut out = io::stdout().lock();
        let _ = write!(out, "\r\x1b[K{text}\r\n{}", self.prompt);
        let _ = out.flush();
    }
}
