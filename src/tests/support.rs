//! Helpers shared by the unit tests.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    adapters::{aes_crypto::AesGcmCrypto, file_storage::FileStorage},
    application::engine::VaultEngine,
    domain::models::KdfParams,
};

pub type Engine = VaultEngine<FileStorage, AesGcmCrypto>;

/// Argon2 cost for unit tests: real Argon2id, tiny memory, so hundreds of
/// derivations stay fast. Production uses `KdfParams::DEFAULT`.
pub const CHEAP: KdfParams = KdfParams {
    m_cost: 64,
    t_cost: 1,
    p_cost: 1,
};

/// A fresh directory under the system temp dir, removed when dropped.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let path = std::env::temp_dir().join(format!(
            "vault-test-{}-{}-{}",
            std::process::id(),
            nanos,
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        // `create_dir` (not `create_dir_all`) fails if the directory already
        // exists, so a test never runs on top of leftover files.
        std::fs::create_dir(&path).expect("failed to create test directory");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Path of a file inside the directory.
    pub fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An engine whose vaults live in `dir`, never in the real `~/.vault`.
pub fn engine(dir: &TempDir) -> Engine {
    engine_at(dir.path())
}

/// An engine whose vaults live in `base`, deriving keys at [`CHEAP`] cost.
pub fn engine_at(base: &Path) -> Engine {
    engine_with_kdf(base, CHEAP)
}

/// An engine whose vaults live in `base`, deriving new keys at `kdf` cost.
pub fn engine_with_kdf(base: &Path, kdf: KdfParams) -> Engine {
    VaultEngine::with_kdf(
        FileStorage::with_base_path(base.to_path_buf()),
        AesGcmCrypto::new(),
        kdf,
    )
}

/// A freshly created (and therefore unlocked) vault.
pub fn created(dir: &TempDir, name: &str, password: &str) -> Engine {
    let mut engine = engine(dir);
    engine.create_vault(name, password).unwrap();
    engine
}

/// `path` as the `&str` that `export` and `import` take.
pub fn path_str(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// Permission bits of `path`, e.g. `0o600`.
#[cfg(unix)]
pub fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}
