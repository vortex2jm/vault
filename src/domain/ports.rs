use crate::domain::errors::{CryptoError, StorageError};

pub trait CryptoPort {
    fn salt_gen(&self) -> [u8; 16];
    fn init(&mut self, password: &str, salt: &[u8]) -> Result<(), CryptoError>;
    fn reset(&mut self);
    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12]), CryptoError>;
    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Generates a cryptographically random password of `length` characters.
    fn gen_password(&self, length: usize) -> String;
    /// Returns true if `password` + `salt` derives to the currently held key.
    fn verify_password(&self, password: &str, salt: &[u8]) -> bool;
}

pub trait StoragePort {
    fn exists(&self) -> bool;
    fn set_path(&mut self, path: String);
    fn get_path(&self) -> Option<String>;
    fn load(&self) -> Result<Vec<u8>, StorageError>;
    fn save(&self, data: &[u8]) -> Result<(), StorageError>;
    fn list_vaults(&self) -> Result<Vec<String>, StorageError>;
    /// Renames the current vault file (and its backup) to `new_name`.
    fn rename(&mut self, new_name: String) -> Result<(), StorageError>;
    /// Permanently deletes the vault file and backup for `name`.
    fn delete(&self, name: String) -> Result<(), StorageError>;
}
