use crate::domain::{
    errors::{CryptoError, StorageError},
    models::KdfParams,
};

pub trait CryptoPort {
    fn salt_gen(&self) -> [u8; 16];
    /// Derives the key for `password` and `salt` at the cost `kdf`.
    fn init(&mut self, password: &str, salt: &[u8], kdf: &KdfParams) -> Result<(), CryptoError>;
    fn reset(&mut self);
    /// Encrypts `plaintext`. `associated_data` is authenticated, not encrypted.
    fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 12]), CryptoError>;
    /// Decrypts `ciphertext`; fails unless `associated_data` is exactly what
    /// it was encrypted with.
    fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
    /// A cryptographically random number in `0..n`, every value equally
    /// likely. `n` must not be 0.
    fn random_below(&self, n: usize) -> usize;
    /// Returns true if `password` + `salt` at cost `kdf` derives to the
    /// currently held key.
    fn verify_password(&self, password: &str, salt: &[u8], kdf: &KdfParams) -> bool;
}

pub trait StoragePort {
    fn exists(&self) -> bool;
    fn set_path(&mut self, path: String);
    fn get_path(&self) -> Option<String>;
    /// Reads the current vault file.
    fn load(&mut self) -> Result<Vec<u8>, StorageError>;
    /// Replaces the current vault file with `data`, atomically, keeping the
    /// previous version as a backup. Fails with `StorageError::Conflict` if
    /// the file changed since this session last loaded or saved it.
    fn save(&mut self, data: &[u8]) -> Result<(), StorageError>;
    /// Reads the backup of the current vault: the version its last save
    /// replaced. `None` until a second save.
    fn load_backup(&self) -> Result<Option<Vec<u8>>, StorageError>;
    fn list_vaults(&self) -> Result<Vec<String>, StorageError>;
    /// Renames the current vault file (and its backup) to `new_name`. Fails
    /// with `StorageError::AlreadyExists` if another vault has that name.
    fn rename(&mut self, new_name: String) -> Result<(), StorageError>;
    /// Permanently deletes the vault file and backup for `name`.
    fn delete(&self, name: String) -> Result<(), StorageError>;
}
