//! A pseudo-terminal harness. The binary runs attached to a real terminal
//! device, so line editing, Tab and the `/dev/tty` password prompts behave
//! exactly as in daily use. `$HOME` points at a temporary directory, so the
//! real `~/.vault` is never touched.

use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// How long to wait for expected output before failing.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Marks the start of a new prompt in the cleaned output. Rustyline switches
/// bracketed paste on (`ESC[?2004h`) each time it starts reading a line, but
/// not when it redraws the line being edited. Answers (`update`'s username,
/// confirmations, menus) are read through rustyline too, so `output` stops
/// at them as well: reply to those with `answer`.
const PROMPT_START: &str = "\u{1}";

pub const MENU: &str = "Choose an option [1-3]: ";
pub const UP: &[u8] = b"\x1b[A";
pub const LEFT: &[u8] = b"\x1b[D";
pub const TAB: &[u8] = b"\t";
pub const CTRL_C: &[u8] = b"\x03";
pub const CTRL_D: &[u8] = b"\x04";
pub const CTRL_U: &[u8] = b"\x15";

/// A fresh directory, used as `$HOME` for one test and removed when dropped.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let path = std::env::temp_dir().join(format!(
            "vault-e2e-{}-{}-{}",
            std::process::id(),
            nanos,
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("failed to create test directory");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

type Transcript = Arc<(Mutex<Vec<u8>>, Condvar)>;

/// One run of the binary, attached to a pseudo-terminal.
pub struct Session {
    child: Child,
    terminal: File,
    transcript: Transcript,
    /// How much of the cleaned transcript has already been consumed.
    seen: usize,
}

impl Session {
    /// Starts `vault` with `home` as `$HOME`.
    pub fn start(home: &Path) -> Self {
        let (master, slave) = open_pty();
        let mut command = Command::new(env!("CARGO_BIN_EXE_vault"));
        command
            .env("HOME", home)
            .env("TERM", "xterm-256color")
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        // SAFETY: only async-signal-safe calls run between fork and exec.
        unsafe {
            command.pre_exec(|| {
                // New session with the pty as its controlling terminal, so
                // `/dev/tty` (used by the password prompts) points at it.
                if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().expect("failed to start the vault binary");
        drop(command); // closes our copies of the slave side

        let terminal = File::from(master);
        let mut reader = terminal.try_clone().unwrap();
        let transcript = Transcript::default();
        let sink = Arc::clone(&transcript);
        thread::spawn(move || {
            let mut buf = [0; 4096];
            // Fails with EIO once the program exits and the slave side closes.
            while let Ok(n @ 1..) = reader.read(&mut buf) {
                let (bytes, changed) = &*sink;
                bytes.lock().unwrap().extend_from_slice(&buf[..n]);
                changed.notify_all();
            }
        });

        Self { child, terminal, transcript, seen: 0 }
    }

    /// Types raw bytes.
    pub fn send(&mut self, keys: &[u8]) {
        self.terminal.write_all(keys).unwrap();
        self.terminal.flush().unwrap();
    }

    /// Waits for `needle` in the output after everything consumed so far and
    /// returns the text up to the end of the match. Colours and other escape
    /// sequences are stripped before matching.
    pub fn expect(&mut self, needle: &str) -> String {
        let deadline = Instant::now() + TIMEOUT;
        let (bytes, changed) = &*self.transcript;
        let mut raw = bytes.lock().unwrap();
        loop {
            let text = clean(&raw);
            if let Some(i) = text[self.seen..].find(needle) {
                let start = self.seen;
                self.seen += i + needle.len();
                return text[start..self.seen].to_string();
            }
            let now = Instant::now();
            if now >= deadline {
                drop(raw);
                panic!("timed out waiting for {needle:?}; terminal output:\n{text}");
            }
            raw = changed.wait_timeout(raw, deadline - now).unwrap().0;
        }
    }

    /// Waits for a sub-prompt (password, confirmation, menu) and answers it.
    pub fn answer(&mut self, prompt: &str, reply: &str) {
        self.expect(prompt);
        self.send(format!("{reply}\r").as_bytes());
    }

    /// Waits for the next REPL prompt and types `keys` (no Enter). Returns
    /// the prompt that was shown, e.g. `vault[personal*|1]> `.
    pub fn keys(&mut self, keys: &[u8]) -> String {
        self.expect(PROMPT_START);
        let prompt = self.expect("]> ");
        self.send(keys);
        prompt
    }

    /// Waits for the next REPL prompt and runs `line`. Returns the prompt.
    pub fn command(&mut self, line: &str) -> String {
        self.keys(format!("{line}\r").as_bytes())
    }

    /// Output of the last command: everything up to the next REPL prompt,
    /// which is left for the next `command`.
    pub fn output(&mut self) -> String {
        let mut text = self.expect(PROMPT_START);
        text.truncate(text.len() - PROMPT_START.len());
        self.seen -= PROMPT_START.len();
        text
    }

    /// Everything printed so far, escape sequences included.
    pub fn raw(&self) -> Vec<u8> {
        self.transcript.0.lock().unwrap().clone()
    }

    /// Waits for the program to exit.
    pub fn wait(mut self) -> ExitStatus {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= deadline {
                panic!("vault did not exit; terminal output:\n{}", clean(&self.raw()));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// `create <name>`, answering both password prompts.
    pub fn create(&mut self, name: &str, password: &str) {
        self.command(&format!("create {name}"));
        self.answer("New vault password: ", password);
        self.answer("Confirm password: ", password);
        self.expect(&format!("Vault '{name}' created."));
    }

    /// `unlock <name>`.
    pub fn unlock(&mut self, name: &str, password: &str) {
        self.command(&format!("unlock {name}"));
        self.answer("Vault password: ", password);
        self.expect(&format!("Vault '{name}' unlocked."));
    }

    /// `add <service> <username>`, answering the password prompt.
    pub fn add(&mut self, service: &str, username: &str, password: &str) {
        self.command(&format!("add {service} {username}"));
        self.answer("Service password: ", password);
        self.expect(&format!("Entry '{service}' added."));
    }

    /// `exit` with no uncommitted changes; the program must end cleanly.
    pub fn exit(mut self) {
        self.command("exit");
        assert!(self.wait().success());
    }

    /// `exit`, discarding uncommitted changes.
    pub fn exit_discarding(mut self) {
        self.command("exit");
        self.answer(MENU, "2");
        assert!(self.wait().success());
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Never leave a process behind when a test fails halfway.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn open_pty() -> (OwnedFd, OwnedFd) {
    let (mut master, mut slave) = (-1, -1);
    let size = libc::winsize { ws_row: 40, ws_col: 120, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: on success openpty returns two new descriptors that we own.
    unsafe {
        let rc = libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &size,
        );
        assert_eq!(rc, 0, "openpty failed: {}", std::io::Error::last_os_error());
        for fd in [master, slave] {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
        (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave))
    }
}

/// Terminal output as plain text: escape sequences and carriage returns
/// removed, and the start of each REPL prompt marked with `PROMPT_START`.
/// An incomplete sequence at the end is left out until the rest arrives, so
/// positions in the text never shift as more output comes in.
fn clean(raw: &[u8]) -> String {
    let mut text = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            0x1b => match raw.get(i + 1) {
                None => break,
                Some(b'[') => {
                    // CSI: parameter bytes, then a final byte in 0x40..=0x7e.
                    let Some(len) = raw[i + 2..].iter().position(|b| (0x40..=0x7e).contains(b))
                    else {
                        break;
                    };
                    let end = i + 2 + len + 1;
                    if &raw[i..end] == b"\x1b[?2004h" {
                        text.extend_from_slice(PROMPT_START.as_bytes());
                    }
                    i = end;
                }
                Some(_) => i += 2,
            },
            b'\r' => i += 1,
            byte => {
                text.push(byte);
                i += 1;
            }
        }
    }
    match std::str::from_utf8(&text) {
        Ok(s) => s.to_string(),
        // A multi-byte character cut in half at the end: wait for the rest.
        Err(e) if e.error_len().is_none() => {
            String::from_utf8_lossy(&text[..e.valid_up_to()]).into_owned()
        }
        Err(_) => String::from_utf8_lossy(&text).into_owned(),
    }
}
