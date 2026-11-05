use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::domain::{errors::StorageError, ports::StoragePort};

/// Lock file shared by every session on the vault directory: commits take it
/// so they never interleave.
const COMMIT_LOCK: &str = ".lock";

pub struct FileStorage {
    base_path: PathBuf,
    path: PathBuf,
    /// SHA-256 of the vault file as this session last read or wrote it, or
    /// `None` if there was no file. A save only replaces the file while it
    /// still matches, so what another session saved is never overwritten.
    seen: Option<[u8; 32]>,
}

impl FileStorage {
    /// Stores vaults in `~/.vault`.
    pub fn new() -> Result<Self, StorageError> {
        Ok(Self::with_base_path(vault_dir(std::env::home_dir())?))
    }

    /// Stores vaults under `base_path` instead of `~/.vault`.
    pub fn with_base_path(base_path: PathBuf) -> Self {
        // Complete path
        let path = base_path.join("default.vault");

        Self {
            path,
            base_path,
            seen: None,
        }
    }
}

/// `<home>/.vault`. An empty home would put the vaults in whatever directory
/// the program runs from, so it counts as none.
pub(crate) fn vault_dir(home: Option<PathBuf>) -> Result<PathBuf, StorageError> {
    home.filter(|home| !home.as_os_str().is_empty())
        .map(|home| home.join(".vault"))
        .ok_or(StorageError::NoHomeDir)
}

impl StoragePort for FileStorage {
    fn set_path(&mut self, mut path: String) {
        path.push_str(".vault");

        // Set complete path through base path
        self.path = self.base_path.join(path);
        self.seen = None;
    }

    fn get_path(&self) -> Option<String> {
        self.path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
    }

    fn save(&mut self, data: &[u8]) -> Result<(), StorageError> {
        create_private_dir(&self.base_path)?;
        // Released when `_lock` is dropped, at the end of the save.
        let _lock = open_private(&self.base_path.join(COMMIT_LOCK), false)?;
        _lock.lock()?;

        let current = read_if_exists(&self.path)?;
        if current.as_deref().map(fingerprint) != self.seen {
            return Err(StorageError::Conflict);
        }
        // The version being replaced becomes the backup.
        if let Some(previous) = &current {
            write_atomically(&self.path.with_extension("bkp"), previous)?;
        }
        write_atomically(&self.path, data)?;
        self.seen = Some(fingerprint(data));
        Ok(())
    }

    fn load(&mut self) -> Result<Vec<u8>, StorageError> {
        let buffer = fs::read(&self.path)?;
        self.seen = Some(fingerprint(&buffer));
        Ok(buffer)
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }

    fn list_vaults(&self) -> Result<Vec<String>, StorageError> {
        let vault_dir = &self.base_path;

        let mut vaults = Vec::new();

        if !vault_dir.exists() {
            return Ok(vaults);
        }

        for entry in fs::read_dir(vault_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file()
                && path.extension().and_then(|e| e.to_str()) == Some("vault")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                vaults.push(stem.to_string());
            }
        }

        Ok(vaults)
    }

    fn rename(&mut self, new_name: String) -> Result<(), StorageError> {
        let new_path = self.base_path.join(format!("{}.vault", new_name));
        if new_path == self.path {
            return Ok(());
        }
        // fs::rename silently replaces an existing file: without this check,
        // another vault (and its backup) would be destroyed.
        if new_path.exists() {
            return Err(StorageError::AlreadyExists);
        }

        let old_bkp = self.path.with_extension("bkp");
        let new_bkp = new_path.with_extension("bkp");

        fs::rename(&self.path, &new_path)?;

        // Best-effort rename of the backup; not fatal if it doesn't exist.
        if old_bkp.exists() {
            fs::rename(&old_bkp, &new_bkp).ok();
        }

        self.path = new_path;
        Ok(())
    }

    fn delete(&self, name: String) -> Result<(), StorageError> {
        let vault_path = self.base_path.join(format!("{}.vault", name));
        let bkp_path = vault_path.with_extension("bkp");

        if !vault_path.exists() {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Vault '{}' not found", name),
            )));
        }

        fs::remove_file(&vault_path)?;

        // Best-effort removal of the backup.
        if bkp_path.exists() {
            fs::remove_file(&bkp_path).ok();
        }

        Ok(())
    }
}

/// Creates `dir` if needed and makes sure only its owner can list or enter
/// it (vault names would show otherwise). A directory left open by an older
/// version is tightened here, on the next save.
fn create_private_dir(dir: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        if fs::metadata(dir)?.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(not(unix))]
    fs::create_dir_all(dir)?;
    Ok(())
}

fn fingerprint(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The file's content, or `None` if there is no file.
fn read_if_exists(path: &Path) -> Result<Option<Vec<u8>>, StorageError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Replaces `path` with `data` so that a crash at any point leaves either the
/// old file or the new one, never a mix: the data goes to a temporary file,
/// which is flushed to disk and renamed over `path`; then the directory is
/// flushed so the rename survives a crash too.
fn write_atomically(path: &Path, data: &[u8]) -> Result<(), StorageError> {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    let tmp = path.with_file_name(name);

    let written = open_private(&tmp, true)
        .and_then(|mut file| {
            file.write_all(data)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&tmp, path));
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    sync_dir(path)
}

/// Opens `path` for writing, creating it readable and writable by the owner
/// only; `truncate` empties an existing file.
fn open_private(path: &Path, truncate: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(truncate);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)
}

/// Flushes the directory holding `path`, so a rename inside it is durable.
fn sync_dir(path: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
