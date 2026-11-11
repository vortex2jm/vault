use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::ErrorKind,
};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use zeroize::Zeroize;

use crate::domain::{
    errors::{StorageError, VaultError},
    format::{self, CURRENT_VERSION, FormatError, VaultFile},
    generator::{self, PasswordOptions},
    models::{Entry, KdfParams, VaultState},
    ports::{CryptoPort, StoragePort},
};

/// Shortest password `gen_password` produces.
pub const MIN_GENERATED_LENGTH: usize = 8;
/// Longest password `gen_password` produces.
pub const MAX_GENERATED_LENGTH: usize = 256;
/// Fewest words `gen_passphrase` uses (about 52 bits).
pub const MIN_PASSPHRASE_WORDS: usize = 4;
/// Most words `gen_passphrase` uses.
pub const MAX_PASSPHRASE_WORDS: usize = 20;
/// Shortest master password a new vault or `change_password` accepts, in
/// characters. Vaults whose password predates the rule still unlock.
pub const MIN_MASTER_PASSWORD_LENGTH: usize = 8;

/// One difference between the open vault and its last commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Added(String),
    Removed(String),
    Renamed { from: String, to: String },
    /// The fields that changed: `username`, `password` (or only `password
    /// history`, when it was changed and changed back) and `notes`.
    Changed { service: String, fields: Vec<&'static str> },
}

/// What `unlock` did to the vault file besides opening it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upgrade {
    /// Nothing: the file was already in the current format and key cost.
    None,
    /// The file was rewritten in the current format, with a key derived at
    /// the current cost. The previous file is the backup until the next commit.
    Done,
    /// The file is outdated but couldn't be rewritten now (the error); the
    /// next unlock tries again.
    Failed(String),
}

/// VaultEngine is the core of the application, responsible for managing vault state, entries and interactions with storage and crypto ports
pub struct VaultEngine<S: StoragePort, C: CryptoPort> {
    storage: S,
    crypto: C,
    vault_state: Option<VaultState>,
    entries: BTreeMap<String, Entry>,
    /// The entries as last committed or loaded: what `changes` compares the
    /// current ones with, and what `discard` goes back to.
    committed: BTreeMap<String, Entry>,
    /// Key derivation cost for new vaults, password changes and upgrades.
    kdf: KdfParams,
}

/// VaultEngine is the core of the application, responsible for managing vault state, entries and interactions with storage and crypto ports
impl<S: StoragePort, C: CryptoPort> VaultEngine<S, C> {
    pub fn new(storage: S, crypto: C) -> Self {
        Self::with_kdf(storage, crypto, KdfParams::DEFAULT)
    }

    /// An engine that derives new keys at `kdf` instead of the default cost.
    pub fn with_kdf(storage: S, crypto: C, kdf: KdfParams) -> Self {
        Self {
            storage,
            crypto,
            vault_state: None,
            entries: BTreeMap::new(),
            committed: BTreeMap::new(),
            kdf,
        }
    }

    /// Rejects vault names that contain path separators or dots
    fn validate_name(name: &str) -> Result<(), VaultError> {
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(VaultError::InvalidVaultName);
        }
        Ok(())
    }

    /// Refuses a new master password shorter than [`MIN_MASTER_PASSWORD_LENGTH`]
    /// characters. Unlocking never checks it, so older vaults keep opening.
    fn check_new_password(password: &str) -> Result<(), VaultError> {
        if password.chars().count() < MIN_MASTER_PASSWORD_LENGTH {
            return Err(VaultError::MasterPasswordTooShort {
                min: MIN_MASTER_PASSWORD_LENGTH,
            });
        }
        Ok(())
    }

    /// A service name may have spaces inside (commands take it in quotes),
    /// but not at its ends, where nobody would see them, nor control
    /// characters; and it can't be empty.
    fn check_service_name(name: &str) -> Result<(), VaultError> {
        if name.is_empty() || name.trim() != name || name.chars().any(char::is_control) {
            return Err(VaultError::InvalidServiceName(name.to_string()));
        }
        Ok(())
    }

    /// Checks if vault is locked by checking if vault state is None
    pub fn is_locked(&self) -> bool {
        self.vault_state.is_none()
    }

    /// Gets current vault name if exists
    pub fn current_vault(&self) -> Option<String> {
        self.storage.get_path()
    }

    /// Whether the open vault differs from its last commit. Edits that undo
    /// each other (`add`, then `rm`) leave it clean.
    pub fn is_dirty(&self) -> bool {
        self.changes().is_ok_and(|changes| !changes.is_empty())
    }

    /// What changed since the last commit: entries removed, renamed or
    /// changed (in the order of their old names), then entries added.
    pub fn changes(&self) -> Result<Vec<Change>, VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }
        let mut added: Vec<&Entry> = self
            .entries
            .values()
            .filter(|entry| !self.committed.contains_key(&entry.service))
            .collect();
        let mut changes = Vec::new();
        for (service, before) in &self.committed {
            match self.entries.get(service) {
                Some(now) => {
                    let fields = changed_fields(before, now);
                    if !fields.is_empty() {
                        changes.push(Change::Changed { service: service.clone(), fields });
                    }
                }
                // An entry back under another name, unchanged otherwise (`mv`).
                None => match added.iter().position(|now| changed_fields(before, now).is_empty()) {
                    Some(i) => {
                        let now = added.remove(i);
                        changes.push(Change::Renamed { from: service.clone(), to: now.service.clone() });
                    }
                    None => changes.push(Change::Removed(service.clone())),
                },
            }
        }
        changes.extend(added.into_iter().map(|entry| Change::Added(entry.service.clone())));
        Ok(changes)
    }

    /// Whether any entry, current or as last committed, is still in memory.
    #[cfg(test)]
    pub fn holds_entries(&self) -> bool {
        !self.entries.is_empty() || !self.committed.is_empty()
    }

    /// Puts the backup (the version the last commit replaced) in place of the
    /// open entries, as uncommitted changes: `changes` shows what that
    /// undoes, `commit` keeps it, `discard` goes back. Returns how many
    /// changes it makes.
    ///
    /// Takes the master password: the backup may be keyed differently, as
    /// after an upgrade from an older format, when it is the old file.
    pub fn restore_backup(&mut self, password: &str) -> Result<usize, VaultError> {
        let current = self.vault_state.ok_or(VaultError::Locked)?;
        if self.is_dirty() {
            return Err(VaultError::UncommittedChanges);
        }
        if !self.crypto.verify_password(password, &current.salt, &current.kdf) {
            return Err(VaultError::InvalidPassword);
        }
        let bytes = self.storage.load_backup()?.ok_or(VaultError::NoBackup)?;
        let file = VaultFile::decode(&bytes).map_err(|e| match e {
            FormatError::UnsupportedVersion(version) => VaultError::UnsupportedFormat(version),
            _ => VaultError::Corrupted,
        })?;

        let same_key = file.salt == current.salt && file.kdf == current.kdf;
        if !same_key {
            self.crypto.init(password, &file.salt, &file.kdf)?;
        }
        let decrypted = self.crypto.decrypt(&file.cipher, &file.nonce, &file.associated_data());
        if !same_key {
            // Back to the vault's own key, whatever the backup did.
            self.crypto.init(password, &current.salt, &current.kdf)?;
        }
        let mut plaintext = decrypted.map_err(|_| VaultError::BackupUnreadable)?;
        let entries = format::decode_entries(&plaintext, file.version)
            .map_err(|_| VaultError::BackupUnreadable);
        plaintext.zeroize();
        self.entries = entries?;
        Ok(self.changes()?.len())
    }

    /// Goes back to the last commit. The entries dropped wipe themselves.
    pub fn discard(&mut self) -> Result<(), VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }
        self.entries = self.committed.clone();
        Ok(())
    }

    /// Creates new vault with given name and password, initializing vault state and deriving key from password and salt.
    /// Auto-commits an initial empty payload so the file always exists after creation.
    pub fn create_vault(&mut self, name: &str, password: &str) -> Result<(), VaultError> {
        if !self.is_locked() {
            return Err(VaultError::Unlocked);
        }

        // Whitelist-validate the name before touching the filesystem.
        Self::validate_name(name)?;
        Self::check_new_password(password)?;

        // Save current path so we can restore it if the vault already exists,
        // preventing storage from being left pointing at the conflicting name.
        let previous_path = self.storage.get_path();
        self.storage.set_path(name.into());
        if self.storage.exists() {
            if let Some(p) = previous_path {
                self.storage.set_path(p);
            }
            return Err(VaultError::VaultAlreadyExists);
        }

        let salt = self.crypto.salt_gen();
        let kdf = self.kdf;
        self.vault_state = Some(VaultState { salt, kdf });

        // If key derivation fails, clear vault_state so the engine stays locked
        // instead of appearing unlocked with an uninitialized crypto context.
        if let Err(e) = self.crypto.init(password, &salt, &kdf) {
            self.vault_state = None;
            return Err(e.into());
        }

        if let Err(e) = self.commit() {
            // Nothing was written: stay locked instead of looking open on a
            // vault that isn't on disk.
            self.vault_state = None;
            self.crypto.reset();
            return Err(e);
        }

        Ok(())
    }

    /// Commits vault state and entries to storage, encrypting them with crypto port.
    /// The file is always written in the current format.
    pub fn commit(&mut self) -> Result<(), VaultError> {
        let VaultState { salt, kdf } = self.vault_state.ok_or(VaultError::Locked)?;

        let mut plaintext = format::encode_entries(&self.entries);
        let header = format::header(CURRENT_VERSION, &kdf, &salt);
        // Encrypt first, then zeroize the plaintext buffer regardless of outcome.
        let encrypted = self.crypto.encrypt(&plaintext, &header);
        plaintext.zeroize();
        let (cipher, nonce) = encrypted?;

        let file = VaultFile {
            version: CURRENT_VERSION,
            kdf,
            salt,
            nonce,
            cipher,
        };
        self.storage
            .save(&file.encode())
            .map_err(|e| match e {
                StorageError::Conflict => VaultError::ChangedOnDisk,
                other => other.into(),
            })?;

        self.committed = self.entries.clone();
        Ok(())
    }

    /// Unlocks vault by name, loading entries into memory and deriving key from password.
    /// A file in an older format, or with a key cheaper than the engine's, is
    /// rewritten in the current format right away (see [`Upgrade`]).
    pub fn unlock(&mut self, vault: &str, password: &str) -> Result<Upgrade, VaultError> {
        // Do not unlock if it's already unlocked — checked BEFORE set_path to
        // avoid corrupting the storage path when an unlock is attempted while open.
        if !self.is_locked() {
            return Err(VaultError::Unlocked);
        }

        // Whitelist-validate the name before touching the filesystem.
        Self::validate_name(vault)?;

        self.storage.set_path(vault.into());

        if !self.storage.exists() {
            return Err(VaultError::VaultNotFound);
        }

        // Load file bytes and split them into header fields and ciphertext.
        let buffer = self.storage.load()?;
        let file = VaultFile::decode(&buffer).map_err(|e| match e {
            FormatError::UnsupportedVersion(version) => VaultError::UnsupportedFormat(version),
            _ => VaultError::Corrupted,
        })?;
        // NOTE: vault_state is NOT set yet — only after full successful auth below.

        // Derive key — on failure there is nothing to clean up since vault_state
        // was never set and crypto had no key before this call.
        self.crypto.init(password, &file.salt, &file.kdf)?;

        // Decrypt into a plaintext buffer, then zeroize it after decoding so
        // the raw password bytes don't linger on the heap. The header is
        // authenticated too: a changed header fails here like a wrong password.
        let mut plaintext = self
            .crypto
            .decrypt(&file.cipher, &file.nonce, &file.associated_data())
            .map_err(|_| {
                self.crypto.reset();
                VaultError::InvalidPassword
            })?;

        let entries_result = format::decode_entries(&plaintext, file.version).map_err(|_| {
            self.crypto.reset();
            VaultError::Corrupted
        });
        plaintext.zeroize();
        self.entries = entries_result?;
        self.committed = self.entries.clone();

        // Only set vault_state after every authentication step has succeeded.
        // This keeps is_locked() accurate throughout the entire unlock flow.
        self.vault_state = Some(VaultState {
            salt: file.salt,
            kdf: file.kdf,
        });

        if file.version < CURRENT_VERSION || file.kdf.is_weaker_than(&self.kdf) {
            return Ok(self.upgrade(password));
        }
        Ok(Upgrade::None)
    }

    /// Rewrites the open vault in the current format. If its key is cheaper
    /// than the engine's cost, it also gets a fresh salt and a key at that
    /// cost; otherwise the key is kept and nothing is derived again. On
    /// failure, goes back to the old key so the vault stays usable as it was.
    fn upgrade(&mut self, password: &str) -> Upgrade {
        let Some(old) = self.vault_state else {
            return Upgrade::None;
        };
        if !old.kdf.is_weaker_than(&self.kdf) {
            // The key is fine, only the format is old: write it again as it is.
            return match self.commit() {
                Ok(()) => Upgrade::Done,
                Err(e) => Upgrade::Failed(e.to_string()),
            };
        }
        let new = VaultState {
            salt: self.crypto.salt_gen(),
            kdf: self.kdf,
        };
        let result = self
            .crypto
            .init(password, &new.salt, &new.kdf)
            .map_err(VaultError::from)
            .and_then(|()| {
                self.vault_state = Some(new);
                self.commit()
            });
        match result {
            Ok(()) => Upgrade::Done,
            Err(e) => {
                self.vault_state = Some(old);
                let _ = self.crypto.init(password, &old.salt, &old.kdf);
                Upgrade::Failed(e.to_string())
            }
        }
    }

    /// How the open vault's key was derived.
    pub fn kdf_params(&self) -> Result<KdfParams, VaultError> {
        self.vault_state
            .map(|state| state.kdf)
            .ok_or(VaultError::Locked)
    }

    /// Locks vault, clearing all entries from memory and zeroizing them
    /// Locks the vault unless it has uncommitted changes, which locking would
    /// throw away. Returns whether it locked.
    pub fn lock_if_clean(&mut self) -> Result<bool, VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }
        if self.is_dirty() {
            return Ok(false);
        }
        self.lock()?;
        Ok(true)
    }

    pub fn lock(&mut self) -> Result<(), VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }

        // Entries wipe themselves when dropped.
        self.entries.clear();
        self.committed.clear();
        self.vault_state = None;
        // Reset the derived key so it doesn't linger in memory after locking.
        self.crypto.reset();

        Ok(())
    }

    /// Adds new entry to vault, indexed by service name
    pub fn add(&mut self, service: &str, username: &str, password: &str) -> Result<(), VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }

        Self::check_service_name(service)?;
        // Check for duplicate before allocating the Entry.
        if self.entries.contains_key(service) {
            return Err(VaultError::EntryExists);
        }

        let entry = Entry::new(service.into(), username.into(), password.into());
        self.entries.insert(service.into(), entry);

        Ok(())
    }

    /// Deletes entry by service name
    pub fn delete(&mut self, service: &str) -> Result<Entry, VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }
        let entry = self.entries.remove(service).ok_or(VaultError::EntryNotFound)?;
        Ok(entry)
    }

    /// Gets entry by service name
    pub fn get(&self, service: &str) -> Result<&Entry, VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }
        self.entries.get(service).ok_or(VaultError::EntryNotFound)
    }

    /// Lists entries in vault
    pub fn get_entries(&self) -> Result<Vec<String>, VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }
        Ok(self.entries.keys().cloned().collect())
    }

    /// Lists vaults in storage dir
    pub fn get_vaults(&self) -> Result<Vec<String>, VaultError> {
        let vaults = self.storage.list_vaults()?;
        Ok(vaults)
    }

    /// Replaces the notes of an entry; the vault becomes dirty only if they
    /// actually change.
    pub fn set_notes(&mut self, service: &str, mut notes: String) -> Result<(), VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }
        let entry = self
            .entries
            .get_mut(service)
            .ok_or(VaultError::EntryNotFound)?;
        if entry.notes == notes {
            notes.zeroize();
        } else {
            entry.set_notes(notes);
        }
        Ok(())
    }

    /// Updates username and/or password of an existing entry.
    /// Blank strings are treated as "keep current value".
    pub fn update(
        &mut self,
        service: &str,
        username: Option<String>,
        passwd: Option<String>,
    ) -> Result<(), VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }
        let entry = self
            .entries
            .get_mut(service)
            .ok_or(VaultError::EntryNotFound)?;
        entry.update(username, passwd);
        Ok(())
    }

    /// A random password of `length` characters, which must be between
    /// `MIN_GENERATED_LENGTH` and `MAX_GENERATED_LENGTH`.
    pub fn gen_password(&self, length: usize, options: PasswordOptions) -> Result<String, VaultError> {
        if !(MIN_GENERATED_LENGTH..=MAX_GENERATED_LENGTH).contains(&length) {
            return Err(VaultError::InvalidPasswordLength {
                min: MIN_GENERATED_LENGTH,
                max: MAX_GENERATED_LENGTH,
            });
        }
        Ok(generator::password(length, options, |n| self.crypto.random_below(n)))
    }

    /// A random passphrase of `words` words, between `MIN_PASSPHRASE_WORDS`
    /// and `MAX_PASSPHRASE_WORDS`.
    pub fn gen_passphrase(&self, words: usize) -> Result<String, VaultError> {
        if !(MIN_PASSPHRASE_WORDS..=MAX_PASSPHRASE_WORDS).contains(&words) {
            return Err(VaultError::InvalidWordCount {
                min: MIN_PASSPHRASE_WORDS,
                max: MAX_PASSPHRASE_WORDS,
            });
        }
        Ok(generator::passphrase(words, |n| self.crypto.random_below(n)))
    }

    /// Returns a human-readable summary of the current vault.
    pub fn info(&self) -> Result<(String, usize), VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }
        let name = self.storage.get_path().unwrap_or_default();
        let count = self.entries.len();
        Ok((name, count))
    }

    /// Renames the current vault (file + backup) to `new_name`, which must not
    /// belong to another vault.
    pub fn rename_vault(&mut self, new_name: &str) -> Result<(), VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }
        Self::validate_name(new_name)?;
        self.storage
            .rename(new_name.to_string())
            .map_err(|e| match e {
                StorageError::AlreadyExists => VaultError::VaultAlreadyExists,
                other => other.into(),
            })
    }

    /// Exports all entries to a CSV file at `path` (plaintext — caller must warn user).
    /// Format: service,username,password. The file is created readable by its
    /// owner only, and an existing file is never replaced.
    pub fn export(&self, path: &str) -> Result<(), VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(path).map_err(|e| match e.kind() {
            ErrorKind::AlreadyExists => VaultError::FileExists(path.to_string()),
            _ => VaultError::Storage(StorageError::Io(e)),
        })?;
        let mut wtr = csv::Writer::from_writer(file);

        // Header row
        wtr.write_record(["service", "username", "password", "notes"])
            .map_err(|_| VaultError::Serialization)?;

        for e in self.entries.values() {
            wtr.write_record([&e.service, &e.username, &e.passwd, &e.notes])
                .map_err(|_| VaultError::Serialization)?;
        }

        wtr.flush()
            .map_err(|e| VaultError::Storage(StorageError::Io(e)))?;

        Ok(())
    }

    /// Imports the entries of a CSV file with a header row. Columns are found
    /// by name, in any order and any case: `service`, `username`, `password`
    /// and, optionally, `notes`; other columns are ignored. A service already
    /// in the vault, or repeated in the file, keeps its first version.
    ///
    /// All or nothing: the whole file is read before anything is added, and
    /// an error names the line at fault. Returns how many entries were added.
    pub fn import(&mut self, path: &str) -> Result<usize, VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }

        let mut rdr = csv::Reader::from_path(path).map_err(csv_error)?;
        let columns = CsvColumns::find(rdr.headers().map_err(csv_error)?)?;

        // Entries wipe themselves when dropped, so a failed import leaves no
        // secrets behind.
        let mut read = Vec::new();
        let mut seen = BTreeSet::new();
        for record in rdr.records() {
            let record = record.map_err(csv_error)?;
            let line = record.position().map_or(0, |p| p.line());
            let field = |column: usize| record.get(column).unwrap_or_default();

            let service = field(columns.service).trim();
            if Self::check_service_name(service).is_err() {
                return Err(VaultError::Import(format!(
                    "line {line}: service names can't be empty or contain control characters ({service:?})"
                )));
            }
            if self.entries.contains_key(service) || !seen.insert(service.to_string()) {
                continue;
            }
            let mut entry = Entry::new(
                service.to_string(),
                field(columns.username).to_string(),
                field(columns.password).to_string(),
            );
            if let Some(notes) = columns.notes {
                entry.notes = field(notes).to_string();
            }
            read.push(entry);
        }

        let count = read.len();
        for entry in read.drain(..) {
            self.entries.insert(entry.service.clone(), entry);
        }
        Ok(count)
    }

    /// Permanently deletes a vault by name. Requires the vault to be locked
    /// to prevent accidentally deleting the currently open vault.
    /// Renames entry `old` to `new`, keeping everything else: password,
    /// notes, history and creation date.
    pub fn rename_entry(&mut self, old: &str, new: &str) -> Result<(), VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }
        Self::check_service_name(new)?;
        if !self.entries.contains_key(old) {
            return Err(VaultError::EntryNotFound);
        }
        if old == new {
            return Ok(());
        }
        if self.entries.contains_key(new) {
            return Err(VaultError::EntryExists);
        }
        let mut entry = self.entries.remove(old).ok_or(VaultError::EntryNotFound)?;
        entry.rename(new.to_string());
        self.entries.insert(new.to_string(), entry);
        Ok(())
    }

    pub fn delete_vault(&self, name: &str) -> Result<(), VaultError> {
        if !self.is_locked() {
            return Err(VaultError::Unlocked);
        }
        Self::validate_name(name)?;
        self.storage.delete(name.to_string())?;
        Ok(())
    }

    /// Changes the master password of the currently open vault.
    /// Verifies `old_password` before accepting `new_password`.
    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<(), VaultError> {
        let current = self.vault_state.ok_or(VaultError::Locked)?;
        Self::check_new_password(new_password)?;

        // Verify the old password by re-deriving and comparing keys.
        if !self
            .crypto
            .verify_password(old_password, &current.salt, &current.kdf)
        {
            return Err(VaultError::InvalidPassword);
        }

        // A fresh salt, and the engine's current cost for the new key.
        let new = VaultState {
            salt: self.crypto.salt_gen(),
            kdf: self.kdf,
        };
        if let Err(e) = self.crypto.init(new_password, &new.salt, &new.kdf) {
            // Restore the old key so the vault stays usable.
            let _ = self.crypto.init(old_password, &current.salt, &current.kdf);
            return Err(e.into());
        }
        self.vault_state = Some(new);

        if let Err(e) = self.commit() {
            // Nothing was saved: go back to the old password, so that a later
            // commit doesn't switch passwords behind the user's back.
            self.vault_state = Some(current);
            let _ = self.crypto.init(old_password, &current.salt, &current.kdf);
            return Err(e);
        }

        // That commit moved the previous version, still encrypted with the
        // old password, into the backup. Commit once more so the backup is
        // under the new password too: if the old one leaked, nothing on disk
        // should open with it anymore.
        self.commit()
            .map_err(|e| VaultError::StaleBackup(e.to_string()))
    }
}

/// Where the fields of an imported CSV are, found by header name.
struct CsvColumns {
    service: usize,
    username: usize,
    password: usize,
    notes: Option<usize>,
}

impl CsvColumns {
    fn find(header: &csv::StringRecord) -> Result<Self, VaultError> {
        let column = |name: &str| {
            let mut found = header
                .iter()
                .enumerate()
                .filter(|(_, title)| title.trim().eq_ignore_ascii_case(name))
                .map(|(index, _)| index);
            match (found.next(), found.next()) {
                (Some(_), Some(_)) => Err(VaultError::Import(format!(
                    "the header has more than one '{name}' column"
                ))),
                (index, _) => Ok(index),
            }
        };
        let required = |name: &str| {
            column(name)?.ok_or_else(|| {
                VaultError::Import(format!(
                    "the header has no '{name}' column (expected service, username, \
                     password and, optionally, notes)"
                ))
            })
        };
        Ok(Self {
            service: required("service")?,
            username: required("username")?,
            password: required("password")?,
            notes: column("notes")?,
        })
    }
}

/// A CSV reading error, naming the line at fault.
fn csv_error(e: csv::Error) -> VaultError {
    let line = e.position().map_or(0, |p| p.line());
    match e.into_kind() {
        csv::ErrorKind::Io(io) => VaultError::Storage(StorageError::Io(io)),
        csv::ErrorKind::UnequalLengths { expected_len, len, .. } => VaultError::Import(format!(
            "line {line}: expected {expected_len} fields, as in the header, but found {len}"
        )),
        csv::ErrorKind::Utf8 { .. } => VaultError::Import(format!("line {line} isn't valid UTF-8")),
        _ => VaultError::Serialization,
    }
}

/// The fields of an entry that differ between `before` and `now`, its name
/// and dates aside.
fn changed_fields(before: &Entry, now: &Entry) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if before.username != now.username {
        fields.push("username");
    }
    if before.passwd != now.passwd {
        fields.push("password");
    } else if before.history != now.history {
        fields.push("password history");
    }
    if before.notes != now.notes {
        fields.push("notes");
    }
    fields
}
