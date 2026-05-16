use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Vault is locked")]
    Locked,

    #[error("Vault is already unlocked")]
    Unlocked,

    #[error("Entry already exists")]
    EntryExists,

    #[error("Entry not found")]
    EntryNotFound,

    #[error("Vault not found")]
    VaultNotFound,

    #[error("Vault already exists")]
    VaultAlreadyExists,

    #[error("Serialization failed")]
    Serialization,

    #[error("Invalid password or corrupted vault")]
    InvalidPassword,

    #[error("Cryptography error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Integrity check failed")]
    IntegrityError,
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Crypto not initialized")]
    NotInitialized,

    #[error("Invalid nonce length")]
    InvalidNonce,

    #[error("Aead error: {0}")]
    Aead(String),

    #[error("Error while derivating key")]
    KeyDerivationError,
}
