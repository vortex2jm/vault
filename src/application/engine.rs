use std::collections::BTreeMap;

use zeroize::Zeroize;

use crate::domain::{
    errors::{StorageError, VaultError},
    models::{Entry, VaultState},
    ports::{CryptoPort, StoragePort},
};

/// VaultEngine is the core of the application, responsible for managing vault state, entries and interactions with storage and crypto ports
pub struct VaultEngine<S: StoragePort, C: CryptoPort> {
    storage: S,
    crypto: C,
    vault_state: Option<VaultState>,
    entries: BTreeMap<String, Entry>,
    dirty: bool,
}

/// VaultEngine is the core of the application, responsible for managing vault state, entries and interactions with storage and crypto ports
impl<S: StoragePort, C: CryptoPort> VaultEngine<S, C> {
    pub fn new(storage: S, crypto: C) -> Self {
        Self {
            storage,
            crypto,
            vault_state: None,
            entries: BTreeMap::new(),
            dirty: false,
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

    /// Checks if vault is locked by checking if vault state is None
    pub fn is_locked(&self) -> bool {
        self.vault_state.is_none()
    }

    /// Gets current vault name if exists
    pub fn current_vault(&self) -> Option<String> {
        self.storage.get_path()
    }

    /// Checks if vault has unsaved changes
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Creates new vault with given name and password, initializing vault state and deriving key from password and salt.
    /// Auto-commits an initial empty payload so the file always exists after creation.
    pub fn create_vault(&mut self, name: &str, password: &str) -> Result<(), VaultError> {
        if !self.is_locked() {
            return Err(VaultError::Unlocked);
        }

        // Whitelist-validate the name before touching the filesystem.
        Self::validate_name(name)?;

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
        self.vault_state = Some(VaultState::new(&salt));

        // If key derivation fails, clear vault_state so the engine stays locked
        // instead of appearing unlocked with an uninitialized crypto context.
        if let Err(e) = self.crypto.init(password, &salt) {
            self.vault_state = None;
            return Err(e.into());
        }

        self.commit()?;

        Ok(())
    }

    /// Commits vault state and entries to storage, encrypting them with crypto port
    pub fn commit(&mut self) -> Result<(), VaultError> {
        let vault_state = self.vault_state.as_mut().ok_or(VaultError::Locked)?;

        let mut entries_buffer = Vec::new();
        wincode::serialize_into(&mut entries_buffer, &self.entries)
            .map_err(|_| VaultError::Serialization)?;

        // Encrypt first, then zeroize the plaintext buffer regardless of outcome.
        let encrypt_result = self.crypto.encrypt(&entries_buffer);
        entries_buffer.zeroize();
        let (cipher, nonce) = encrypt_result?;

        vault_state.cipher = cipher;
        vault_state.nonce = nonce;

        let mut vault_buffer = Vec::new();
        wincode::serialize_into(&mut vault_buffer, vault_state)
            .map_err(|_| VaultError::Serialization)?;

        self.storage.save(&vault_buffer)?;

        self.dirty = false;
        Ok(())
    }

    /// Unlocks vault by name, loading entries into memory and deriving key from password
    pub fn unlock(&mut self, vault: &str, password: &str) -> Result<(), VaultError> {
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

        // Load file bytes
        let buffer = self.storage.load()?;

        // Deserialize vault state (salt, nonce, ciphertext)
        let v_state: VaultState = wincode::deserialize_from(&mut buffer.as_slice())
            .map_err(|_| VaultError::Serialization)?;
        // NOTE: vault_state is NOT set yet — only after full successful auth below.

        // Derive key — on failure there is nothing to clean up since vault_state
        // was never set and crypto had no key before this call.
        self.crypto.init(password, &v_state.salt)?;

        // Decrypt into a plaintext buffer, then zeroize it after deserialization
        // so the raw password bytes don't linger on the heap.
        let mut plaintext = self
            .crypto
            .decrypt(&v_state.cipher, &v_state.nonce)
            .map_err(|_| {
                self.crypto.reset();
                VaultError::InvalidPassword
            })?;

        let entries_result = wincode::deserialize_from(&mut plaintext.as_slice())
            .map_err(|_| {
                self.crypto.reset();
                VaultError::Serialization
            });
        plaintext.zeroize();
        self.entries = entries_result?;

        // Only set vault_state after every authentication step has succeeded.
        // This keeps is_locked() accurate throughout the entire unlock flow.
        self.vault_state = Some(v_state);

        Ok(())
    }

    /// Locks vault, clearing all entries from memory and zeroizing them
    pub fn lock(&mut self) -> Result<(), VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }

        for entry in self.entries.values_mut() {
            entry.zeroize();
        }

        self.entries.clear();
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

        // Check for duplicate before allocating the Entry.
        if self.entries.contains_key(service) {
            return Err(VaultError::EntryExists);
        }

        let entry = Entry::new(service.into(), username.into(), password.into());
        self.entries.insert(service.into(), entry);
        self.dirty = true;

        Ok(())
    }

    /// Deletes entry by service name
    pub fn delete(&mut self, service: &str) -> Result<Entry, VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }
        let entry = self.entries.remove(service).ok_or(VaultError::EntryNotFound)?;
        self.dirty = true;
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
        self.dirty = true;
        Ok(())
    }

    /// Returns a cryptographically random password of `length` characters.
    pub fn gen_password(&self, length: usize) -> String {
        self.crypto.gen_password(length)
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

    /// Renames the current vault (file + backup) to `new_name`.
    pub fn rename_vault(&mut self, new_name: &str) -> Result<(), VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }
        Self::validate_name(new_name)?;
        self.storage.rename(new_name.to_string())?;
        Ok(())
    }

    /// Exports all entries to a CSV file at `path` (plaintext — caller must warn user).
    /// Format: service,username,password
    pub fn export(&self, path: &str) -> Result<(), VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }

        let mut wtr = csv::Writer::from_path(path).map_err(|e| match e.into_kind() {
            csv::ErrorKind::Io(io) => VaultError::Storage(StorageError::Io(io)),
            _ => VaultError::Serialization,
        })?;

        // Header row
        wtr.write_record(["service", "username", "password"])
            .map_err(|_| VaultError::Serialization)?;

        for e in self.entries.values() {
            wtr.write_record([&e.service, &e.username, &e.passwd])
                .map_err(|_| VaultError::Serialization)?;
        }

        wtr.flush()
            .map_err(|e| VaultError::Storage(StorageError::Io(e)))?;

        Ok(())
    }

    /// Imports entries from a CSV file at `path`. The file must have a header row
    /// with columns: service, username, password. Skips entries whose service name
    /// already exists. Returns the count of newly added entries.
    pub fn import(&mut self, path: &str) -> Result<usize, VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }

        let mut rdr = csv::Reader::from_path(path).map_err(|e| match e.into_kind() {
            csv::ErrorKind::Io(io) => VaultError::Storage(StorageError::Io(io)),
            _ => VaultError::Serialization,
        })?;

        let mut count = 0;
        for result in rdr.records() {
            let record = result.map_err(|_| VaultError::Serialization)?;
            let service  = record.get(0).ok_or(VaultError::Serialization)?.to_string();
            let username = record.get(1).ok_or(VaultError::Serialization)?.to_string();
            let password = record.get(2).ok_or(VaultError::Serialization)?.to_string();

            if let std::collections::btree_map::Entry::Vacant(e) = self.entries.entry(service.clone()) {
                let entry = Entry::new(service, username, password);
                e.insert(entry);
                count += 1;
            }
        }

        if count > 0 {
            self.dirty = true;
        }

        Ok(count)
    }

    /// Permanently deletes a vault by name. Requires the vault to be locked
    /// to prevent accidentally deleting the currently open vault.
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
        if self.is_locked() {
            return Err(VaultError::Locked);
        }

        let current_salt = self
            .vault_state
            .as_ref()
            .ok_or(VaultError::Locked)?
            .salt;

        // Verify the old password by re-deriving and comparing keys.
        if !self.crypto.verify_password(old_password, &current_salt) {
            return Err(VaultError::InvalidPassword);
        }

        // Generate a fresh salt and re-init with the new password.
        let new_salt = self.crypto.salt_gen();
        if let Err(e) = self.crypto.init(new_password, &new_salt) {
            // Restore the old key so the vault stays usable.
            let _ = self.crypto.init(old_password, &current_salt);
            return Err(e.into());
        }

        // Update salt in vault_state and commit.
        if let Some(vs) = self.vault_state.as_mut() {
            vs.salt = new_salt;
        }

        self.commit()?;
        Ok(())
    }
}
