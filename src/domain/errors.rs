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

    #[error("Invalid vault name: use only letters, digits, hyphens and underscores")]
    InvalidVaultName,

    #[error("Vault already exists")]
    VaultAlreadyExists,

    #[error("Password length must be between {min} and {max}")]
    InvalidPasswordLength { min: usize, max: usize },

    #[error("The master password must have at least {min} characters")]
    MasterPasswordTooShort { min: usize },

    #[error("{0} already exists: choose another file")]
    FileExists(String),

    #[error("Serialization failed")]
    Serialization,

    #[error("Invalid password or corrupted vault")]
    InvalidPassword,

    #[error("The vault file is damaged, or isn't a vault file")]
    Corrupted,

    #[error("This vault uses file format v{0}, newer than this program supports: update vault")]
    UnsupportedFormat(u16),

    #[error(
        "The vault changed on disk since it was opened (another session?). \
         Nothing was saved: lock and unlock it to reload"
    )]
    ChangedOnDisk,

    #[error(
        "Password changed, but the backup could not be refreshed ({0}) and still \
         opens with the old password: run commit again"
    )]
    StaleBackup(String),

    #[error("Cryptography error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Target already exists")]
    AlreadyExists,

    #[error("The file changed since it was last read")]
    Conflict,
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
