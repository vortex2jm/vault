//! The process itself: keeping its memory away from disk and from other
//! programs.

use std::io;

/// Stops the kernel from writing a core dump of this process, which would put
/// the key and the open entries on disk. On Linux it also marks the process
/// non-dumpable, so other processes of the same user can neither attach a
/// debugger nor read its memory through `/proc`. Root still can.
///
/// Call it first thing, before any secret is read.
pub fn harden() -> io::Result<()> {
    #[cfg(unix)]
    {
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: a plain system call on this process, with a valid struct.
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: a plain system call on this process.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
