use zeroize::Zeroize;

/// How many previous passwords an entry keeps.
pub const HISTORY_LEN: usize = 10;

/// A password an entry used before, and when it was replaced (Unix time).
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct OldPassword {
    pub passwd: String,
    pub replaced_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct Entry {
    pub service: String,
    pub username: String,
    pub passwd: String,
    /// Free text about the entry; empty when there is none.
    pub notes: String,
    /// Previous passwords, newest first, at most [`HISTORY_LEN`].
    pub history: Vec<OldPassword>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}

impl Entry {
    pub fn new(service: String, username: String, passwd: String) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            service,
            username,
            passwd,
            notes: String::new(),
            history: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Replaces the notes, wiping the old text first: notes can hold
    /// recovery codes or PINs.
    pub fn set_notes(&mut self, notes: String) {
        self.notes.zeroize();
        self.notes = notes;
        self.updated_at = chrono::Utc::now().timestamp();
    }

    /// Replaces the username and/or the password. A password that actually
    /// changes goes to the front of the history; the oldest one beyond
    /// [`HISTORY_LEN`] is wiped and dropped.
    pub fn update(&mut self, username: Option<String>, passwd: Option<String>) {
        let now = chrono::Utc::now().timestamp();
        if let Some(u) = username {
            self.username = u;
        }
        if let Some(mut p) = passwd {
            if p == self.passwd {
                p.zeroize();
            } else {
                let old = std::mem::replace(&mut self.passwd, p);
                self.history.insert(
                    0,
                    OldPassword {
                        passwd: old,
                        replaced_at: now,
                    },
                );
                if self.history.len() > HISTORY_LEN {
                    for mut dropped in self.history.drain(HISTORY_LEN..) {
                        dropped.zeroize();
                    }
                }
            }
        }
        self.updated_at = now;
    }
}

/// Argon2id cost parameters. Every vault file records the ones its key was
/// derived with, so the defaults can be raised without breaking old vaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory, in KiB.
    pub m_cost: u32,
    /// Passes over that memory.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u32,
}

impl KdfParams {
    /// For new vaults, password changes and upgrades: 128 MiB and three
    /// passes, about 0.3 s per attempt on a recent laptop.
    pub const DEFAULT: Self = Self {
        m_cost: 128 * 1024,
        t_cost: 3,
        p_cost: 1,
    };

    /// What vaults written before the versioned file format used (the
    /// argon2 crate's defaults at the time).
    pub const LEGACY: Self = Self {
        m_cost: 19 * 1024,
        t_cost: 2,
        p_cost: 1,
    };

    /// True if `self` costs an attacker less memory or less time than `other`.
    pub fn is_weaker_than(&self, other: &Self) -> bool {
        self.m_cost < other.m_cost || self.t_cost < other.t_cost
    }
}

/// What the engine keeps about the open vault's key: its salt and how it
/// was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultState {
    pub salt: [u8; 16],
    pub kdf: KdfParams,
}
