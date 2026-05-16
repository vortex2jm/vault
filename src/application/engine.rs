use std::collections::BTreeMap;

use zeroize::Zeroize;

use crate::domain::{
    errors::VaultError,
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

        self.storage.set_path(name.into());
        if self.storage.exists() {
            return Err(VaultError::VaultAlreadyExists);
        }

        let salt = self.crypto.salt_gen();
        self.vault_state = Some(VaultState::new(&salt));
        self.crypto.init(password, &salt)?;

        self.commit()?;

        Ok(())
    }

    /// Commits vault state and entries to storage, encrypting them with crypto port
    pub fn commit(&mut self) -> Result<(), VaultError> {
        let vault_state = self.vault_state.as_mut().ok_or(VaultError::Locked)?;

        let mut entries_buffer = Vec::new();
        wincode::serialize_into(&mut entries_buffer, &self.entries)
            .map_err(|_| VaultError::Serialization)?;

        let (cipher, nonce) = self.crypto.encrypt(&entries_buffer)?;

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
        self.storage.set_path(vault.into());

        if !self.storage.exists() {
            return Err(VaultError::VaultNotFound);
        }

        // Do not unlock if it's already unlocked
        if !self.is_locked() {
            return Err(VaultError::Unlocked);
        }

        // Load file bytes
        let buffer = self.storage.load()?;

        // Deserialize into vault state
        let v_state: VaultState = wincode::deserialize_from(&mut buffer.as_slice())
            .map_err(|_| VaultError::Serialization)?;
        self.vault_state = Some(v_state.clone());

        // Derive key
        self.crypto.init(password, &v_state.salt)?;

        let stream = self
            .crypto
            .decrypt(&v_state.cipher, &v_state.nonce)
            .map_err(|_| {
                self.vault_state = None;
                self.crypto.reset();
                VaultError::InvalidPassword
            });

        // Deserialize entries into BTreeMap
        self.entries = wincode::deserialize_from(&mut stream?.as_slice())
            .map_err(|_| VaultError::Serialization)?;

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

        Ok(())
    }

    /// Adds new entry to vault, indexed by service name
    pub fn add(&mut self, service: &str, username: &str, password: &str) -> Result<(), VaultError> {
        if self.is_locked() {
            return Err(VaultError::Locked);
        }

        let entry = Entry::new(service.into(), username.into(), password.into());

        if self.entries.contains_key(service) {
            return Err(VaultError::EntryExists);
        }

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
}
