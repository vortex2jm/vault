//! The process itself: no core dumps, and no peeking from other programs of
//! the same user. Both read the running binary's `/proc` entries (Linux).
#![cfg(target_os = "linux")]

use std::{fs, os::unix::fs::MetadataExt};

use crate::support::{Session, TempDir};

/// A session whose prompt is up, so the binary has finished starting.
fn started(home: &TempDir) -> Session {
    let mut s = Session::start(home.path());
    s.command("help");
    s
}

#[test]
fn the_process_cannot_dump_core() {
    let home = TempDir::new();
    let s = started(&home);
    let limits = fs::read_to_string(format!("/proc/{}/limits", s.pid())).unwrap();
    let core = limits.lines().find(|l| l.starts_with("Max core file size")).unwrap();
    // Soft and hard limit: the hard one keeps the process from raising it.
    let values: Vec<&str> = core.split_whitespace().skip(4).take(2).collect();
    assert_eq!(values, ["0", "0"], "{core}");
    s.exit();
}

#[test]
fn other_processes_of_the_user_cannot_read_its_memory() {
    // SAFETY: a plain system call.
    if unsafe { libc::geteuid() } == 0 {
        return; // root reads any process's memory: nothing to check
    }
    let home = TempDir::new();
    let s = started(&home);
    // A non-dumpable process's /proc files belong to root, so neither a
    // debugger nor a plain read of /proc/<pid>/mem works for its own user.
    let mem = format!("/proc/{}/mem", s.pid());
    assert_eq!(fs::metadata(&mem).unwrap().uid(), 0, "{mem} still belongs to the user");
    assert!(fs::File::open(&mem).is_err(), "{mem} opened");
    s.exit();
}
