//! `VaultEngine` flows, with the real adapters on a temporary directory.

use std::{cell::Cell, collections::BTreeMap, fs, rc::Rc};

use super::support::{CHEAP, Engine, TempDir, created, engine, engine_with_kdf, path_str};
use crate::{
    adapters::{aes_crypto::AesGcmCrypto, file_storage::FileStorage},
    application::engine::{
        Change, MAX_GENERATED_LENGTH, MIN_GENERATED_LENGTH, MIN_MASTER_PASSWORD_LENGTH, Upgrade,
        VaultEngine,
    },
    domain::{
        errors::{StorageError, VaultError},
        format::{self, CURRENT_VERSION, VaultFile},
        models::KdfParams,
        ports::{CryptoPort, StoragePort},
    },
};

/// Real storage whose saves start failing once `saves_left` reaches zero,
/// to reach the error paths. `usize::MAX` never runs out.
struct FailingSaves {
    inner: FileStorage,
    saves_left: Rc<Cell<usize>>,
}

impl FailingSaves {
    /// An engine on `dir` allowing `saves` saves, and the counter to change
    /// that later.
    fn engine(
        dir: &TempDir,
        saves: usize,
    ) -> (VaultEngine<FailingSaves, AesGcmCrypto>, Rc<Cell<usize>>) {
        let saves_left = Rc::new(Cell::new(saves));
        let storage = FailingSaves {
            inner: FileStorage::with_base_path(dir.path().to_path_buf()),
            saves_left: Rc::clone(&saves_left),
        };
        (VaultEngine::with_kdf(storage, AesGcmCrypto::new(), CHEAP), saves_left)
    }
}

impl StoragePort for FailingSaves {
    fn exists(&self) -> bool {
        self.inner.exists()
    }
    fn set_path(&mut self, path: String) {
        self.inner.set_path(path)
    }
    fn get_path(&self) -> Option<String> {
        self.inner.get_path()
    }
    fn load(&mut self) -> Result<Vec<u8>, StorageError> {
        self.inner.load()
    }
    fn save(&mut self, data: &[u8]) -> Result<(), StorageError> {
        match self.saves_left.get() {
            0 => Err(StorageError::Conflict),
            n => {
                self.saves_left.set(n - 1);
                self.inner.save(data)
            }
        }
    }
    fn list_vaults(&self) -> Result<Vec<String>, StorageError> {
        self.inner.list_vaults()
    }
    fn rename(&mut self, new_name: String) -> Result<(), StorageError> {
        self.inner.rename(new_name)
    }
    fn delete(&self, name: String) -> Result<(), StorageError> {
        self.inner.delete(name)
    }
}

#[test]
fn create_leaves_the_vault_unlocked_and_on_disk() {
    let dir = TempDir::new();
    let engine = created(&dir, "personal", "password");

    assert!(!engine.is_locked());
    assert!(!engine.is_dirty());
    assert_eq!(engine.current_vault().as_deref(), Some("personal"));
    assert!(engine.get_entries().unwrap().is_empty());
    assert!(dir.file("personal.vault").exists());
}

#[test]
fn create_refuses_an_existing_vault() {
    let dir = TempDir::new();
    created(&dir, "personal", "password").lock().unwrap();

    let mut engine = engine(&dir);
    assert!(matches!(
        engine.create_vault("personal", "other-password"),
        Err(VaultError::VaultAlreadyExists)
    ));
    assert!(engine.is_locked());
}

#[test]
fn invalid_vault_names_are_rejected() {
    let dir = TempDir::new();
    let mut engine = engine(&dir);
    for name in ["", "../evil", "a/b", "a.b", "with space", "~"] {
        assert!(
            matches!(engine.create_vault(name, "password"), Err(VaultError::InvalidVaultName)),
            "create {name:?}"
        );
        assert!(
            matches!(engine.unlock(name, "password"), Err(VaultError::InvalidVaultName)),
            "unlock {name:?}"
        );
    }
    assert!(engine.get_vaults().unwrap().is_empty());
}

#[test]
fn entries_survive_commit_lock_and_unlock() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "master-password");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.add("bank", "0042", "0099").unwrap(); // leading zeros are kept verbatim
    assert!(engine.is_dirty());

    engine.commit().unwrap();
    assert!(!engine.is_dirty());
    engine.lock().unwrap();
    assert!(engine.is_locked());

    engine.unlock("personal", "master-password").unwrap();
    assert_eq!(engine.get_entries().unwrap(), ["bank", "github"]);
    assert_eq!(engine.info().unwrap(), ("personal".to_string(), 2));
    let bank = engine.get("bank").unwrap();
    assert_eq!((bank.username.as_str(), bank.passwd.as_str()), ("0042", "0099"));
    assert_eq!(engine.get("github").unwrap().passwd, "hunter2");
}

#[test]
fn uncommitted_changes_are_discarded_by_lock() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "password");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.lock().unwrap();

    engine.unlock("personal", "password").unwrap();
    assert!(engine.get_entries().unwrap().is_empty());
}

#[test]
fn a_stale_session_cannot_overwrite_newer_changes() {
    let dir = TempDir::new();
    created(&dir, "shared", "password").lock().unwrap();
    let mut first = engine(&dir);
    first.unlock("shared", "password").unwrap();
    let mut second = engine(&dir);
    second.unlock("shared", "password").unwrap(); // reading at the same time is fine

    first.add("from-first", "u", "p").unwrap();
    first.commit().unwrap();
    second.add("from-second", "u", "p").unwrap();
    assert!(matches!(second.commit(), Err(VaultError::ChangedOnDisk)));
    assert!(second.is_dirty(), "the unsaved change must still be there");

    // Reopening shows the other session's commit, and saving works again.
    second.lock().unwrap();
    second.unlock("shared", "password").unwrap();
    assert!(second.get("from-first").is_ok());
    second.add("from-second", "u", "p").unwrap();
    second.commit().unwrap();

    first.lock().unwrap();
    first.unlock("shared", "password").unwrap();
    assert_eq!(first.get_entries().unwrap(), ["from-first", "from-second"]);
}

#[test]
fn a_create_that_cannot_be_saved_leaves_the_engine_locked() {
    let dir = TempDir::new();
    let (mut engine, _) = FailingSaves::engine(&dir, 0);

    assert!(matches!(engine.create_vault("personal", "password"), Err(VaultError::ChangedOnDisk)));
    assert!(engine.is_locked());
    assert!(matches!(engine.add("s", "u", "p"), Err(VaultError::Locked)));
}

#[test]
fn a_vault_with_a_cheaper_key_is_upgraded_on_unlock() {
    let dir = TempDir::new();
    let weak = KdfParams { m_cost: 32, ..CHEAP };
    let mut old = engine_with_kdf(dir.path(), weak);
    old.create_vault("personal", "password").unwrap();
    old.add("github", "alice", "hunter2").unwrap();
    old.commit().unwrap();
    old.lock().unwrap();

    let mut engine = engine(&dir);
    assert_eq!(engine.unlock("personal", "password").unwrap(), Upgrade::Done);
    assert_eq!(engine.kdf_params().unwrap(), CHEAP);
    assert_eq!(engine.get("github").unwrap().passwd, "hunter2");
    assert!(!engine.is_dirty());
    let file = VaultFile::decode(&fs::read(dir.file("personal.vault")).unwrap()).unwrap();
    assert_eq!(file.kdf, CHEAP);
}

#[test]
fn a_vault_with_a_costlier_key_is_left_alone() {
    let dir = TempDir::new();
    let stronger = KdfParams { m_cost: 128, t_cost: 2, ..CHEAP };
    engine_with_kdf(dir.path(), stronger).create_vault("personal", "password").unwrap();
    let before = fs::read(dir.file("personal.vault")).unwrap();

    let mut engine = engine(&dir);
    assert_eq!(engine.unlock("personal", "password").unwrap(), Upgrade::None);
    assert_eq!(engine.kdf_params().unwrap(), stronger);
    assert_eq!(fs::read(dir.file("personal.vault")).unwrap(), before);
}

#[test]
fn a_failed_upgrade_leaves_the_vault_usable_as_it_was() {
    let dir = TempDir::new();
    let weak = KdfParams { m_cost: 32, ..CHEAP };
    engine_with_kdf(dir.path(), weak).create_vault("personal", "password").unwrap();

    let (mut engine, saves_left) = FailingSaves::engine(&dir, 0);
    assert!(matches!(engine.unlock("personal", "password").unwrap(), Upgrade::Failed(_)));
    assert_eq!(engine.kdf_params().unwrap(), weak);

    // Still works with the key it had, and the next unlock tries again.
    saves_left.set(usize::MAX);
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();
    engine.lock().unwrap();
    assert_eq!(engine.unlock("personal", "password").unwrap(), Upgrade::Done);
    assert_eq!(engine.get("github").unwrap().passwd, "hunter2");
}

#[test]
fn changing_the_header_makes_the_vault_unreadable() {
    let dir = TempDir::new();
    created(&dir, "personal", "password").lock().unwrap();
    let original = fs::read(dir.file("personal.vault")).unwrap();
    let unlock_with = |bytes: &[u8]| {
        fs::write(dir.file("personal.vault"), bytes).unwrap();
        engine(&dir).unlock("personal", "password")
    };

    // Memory cost, passes and salt are all authenticated.
    for offset in [9, 13, 21] {
        let mut bytes = original.clone();
        bytes[offset] ^= 2;
        assert!(
            matches!(unlock_with(&bytes), Err(VaultError::InvalidPassword)),
            "byte {offset}"
        );
    }
    let mut newer = original.clone();
    newer[6] = 9;
    assert!(matches!(unlock_with(&newer), Err(VaultError::UnsupportedFormat(9))));
    assert!(matches!(unlock_with(&original[..20]), Err(VaultError::Corrupted)));
    assert!(unlock_with(&original).is_ok());
}

#[test]
fn new_master_passwords_have_a_minimum_length() {
    let dir = TempDir::new();
    let mut engine = engine(&dir);
    let too_short = |result| {
        matches!(
            result,
            Err(VaultError::MasterPasswordTooShort { min: MIN_MASTER_PASSWORD_LENGTH })
        )
    };
    // Counted in characters, not bytes: "çãoçãoç" is 7 of them in 12 bytes.
    for short in ["", "1234567", "çãoçãoç"] {
        assert!(too_short(engine.create_vault("personal", short)), "{short:?}");
        assert!(engine.is_locked());
    }
    assert!(engine.get_vaults().unwrap().is_empty(), "nothing was written");

    engine.create_vault("personal", "çãoçãoçã").unwrap(); // exactly the minimum
    for short in ["", "1234567"] {
        assert!(too_short(engine.change_password("çãoçãoçã", short)), "{short:?}");
    }
    engine.lock().unwrap();
    engine.unlock("personal", "çãoçãoçã").unwrap();
}

#[test]
fn a_short_password_from_before_the_rule_still_opens_its_vault() {
    // Written by hand, the way create_vault did before the minimum length.
    let dir = TempDir::new();
    let salt = [3; 16];
    let mut crypto = AesGcmCrypto::new();
    crypto.init("pw", &salt, &CHEAP).unwrap();
    let header = format::header(CURRENT_VERSION, &CHEAP, &salt);
    let (cipher, nonce) = crypto
        .encrypt(&format::encode_entries(&BTreeMap::new()), &header)
        .unwrap();
    let file = VaultFile { version: CURRENT_VERSION, kdf: CHEAP, salt, nonce, cipher };
    fs::write(dir.file("old.vault"), file.encode()).unwrap();

    let mut engine = engine(&dir);
    assert_eq!(engine.unlock("old", "pw").unwrap(), Upgrade::None);
    // And the password can be changed for a longer one.
    engine.change_password("pw", "long enough").unwrap();
    engine.lock().unwrap();
    engine.unlock("old", "long enough").unwrap();
}

#[test]
fn the_header_is_authenticated_as_associated_data() {
    let dir = TempDir::new();
    created(&dir, "personal", "password").lock().unwrap();
    let file = VaultFile::decode(&fs::read(dir.file("personal.vault")).unwrap()).unwrap();

    let mut crypto = AesGcmCrypto::new();
    crypto.init("password", &file.salt, &file.kdf).unwrap();
    assert!(crypto.decrypt(&file.cipher, &file.nonce, &file.associated_data()).is_ok());
    assert!(crypto.decrypt(&file.cipher, &file.nonce, &[]).is_err());
}

#[test]
fn kdf_params_reports_the_open_vaults_cost() {
    let dir = TempDir::new();
    assert_eq!(created(&dir, "personal", "password").kdf_params().unwrap(), CHEAP);
    assert!(matches!(engine(&dir).kdf_params(), Err(VaultError::Locked)));
}

#[test]
fn a_vault_over_4_mib_commits_and_reopens() {
    // The old serialisation library wrote it, then refused to read it (B3).
    let dir = TempDir::new();
    let mut engine = created(&dir, "big", "password");
    let big = "x".repeat(5 * 1024 * 1024);
    engine.add("big", "u", &big).unwrap();
    engine.commit().unwrap();
    engine.lock().unwrap();

    engine.unlock("big", "password").unwrap();
    assert_eq!(engine.get("big").unwrap().passwd.len(), big.len());
}

#[test]
fn wrong_password_keeps_the_vault_locked() {
    let dir = TempDir::new();
    created(&dir, "personal", "right-password").lock().unwrap();

    let mut engine = engine(&dir);
    assert!(matches!(engine.unlock("personal", "wrong-password"), Err(VaultError::InvalidPassword)));
    assert!(engine.is_locked());
    assert!(matches!(engine.get_entries(), Err(VaultError::Locked)));

    engine.unlock("personal", "right-password").unwrap();
}

#[test]
fn unlocking_a_missing_vault_fails() {
    let dir = TempDir::new();
    let mut engine = engine(&dir);
    assert!(matches!(engine.unlock("nope", "password"), Err(VaultError::VaultNotFound)));
    assert!(engine.is_locked());
}

#[test]
fn operations_require_an_unlocked_vault() {
    let dir = TempDir::new();
    let mut engine = engine(&dir);
    let csv = dir.file("out.csv");

    assert!(matches!(engine.add("s", "u", "p"), Err(VaultError::Locked)));
    assert!(matches!(engine.get("s"), Err(VaultError::Locked)));
    assert!(matches!(engine.update("s", None, None), Err(VaultError::Locked)));
    assert!(matches!(engine.set_notes("s", "n".into()), Err(VaultError::Locked)));
    assert!(matches!(engine.delete("s"), Err(VaultError::Locked)));
    assert!(matches!(engine.commit(), Err(VaultError::Locked)));
    assert!(matches!(engine.lock(), Err(VaultError::Locked)));
    assert!(matches!(engine.info(), Err(VaultError::Locked)));
    assert!(matches!(engine.rename_vault("x"), Err(VaultError::Locked)));
    assert!(matches!(engine.change_password("a", "b"), Err(VaultError::Locked)));
    assert!(matches!(engine.export(path_str(&csv)), Err(VaultError::Locked)));
    assert!(matches!(engine.import(path_str(&csv)), Err(VaultError::Locked)));
    assert!(!csv.exists());
}

#[test]
fn vault_level_operations_are_refused_while_unlocked() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "password");

    assert!(matches!(engine.create_vault("other", "password"), Err(VaultError::Unlocked)));
    assert!(matches!(engine.unlock("personal", "password"), Err(VaultError::Unlocked)));
    assert!(matches!(engine.delete_vault("personal"), Err(VaultError::Unlocked)));
    assert!(dir.file("personal.vault").exists());
}

#[test]
fn duplicate_and_missing_entries_do_not_change_state() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "password");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();

    assert!(matches!(engine.add("github", "bob", "x"), Err(VaultError::EntryExists)));
    assert!(matches!(engine.get("missing"), Err(VaultError::EntryNotFound)));
    assert!(matches!(engine.delete("missing"), Err(VaultError::EntryNotFound)));
    assert!(matches!(
        engine.update("missing", Some("u".into()), None),
        Err(VaultError::EntryNotFound)
    ));
    assert!(!engine.is_dirty());
    assert_eq!(engine.get("github").unwrap().username, "alice");
}

#[test]
fn update_keeps_the_fields_left_blank() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "password");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();

    engine.update("github", None, Some("new-pass".into())).unwrap();
    assert!(engine.is_dirty());
    let entry = engine.get("github").unwrap();
    assert_eq!((entry.username.as_str(), entry.passwd.as_str()), ("alice", "new-pass"));

    engine.update("github", Some("bob".into()), None).unwrap();
    let entry = engine.get("github").unwrap();
    assert_eq!((entry.username.as_str(), entry.passwd.as_str()), ("bob", "new-pass"));
}

#[test]
fn delete_removes_the_entry() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "password");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();

    let removed = engine.delete("github").unwrap();
    assert_eq!(removed.service, "github");
    assert!(engine.is_dirty());
    assert!(matches!(engine.get("github"), Err(VaultError::EntryNotFound)));
}

#[test]
fn change_password_requires_the_current_one_and_re_encrypts() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "old-password");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();

    assert!(matches!(
        engine.change_password("wrong-password", "new-password"),
        Err(VaultError::InvalidPassword)
    ));
    engine.change_password("old-password", "new-password").unwrap();
    engine.lock().unwrap();

    assert!(matches!(engine.unlock("personal", "old-password"), Err(VaultError::InvalidPassword)));
    engine.unlock("personal", "new-password").unwrap();
    assert_eq!(engine.get("github").unwrap().passwd, "hunter2");
}

#[test]
fn passwd_moves_the_backup_to_the_new_password_too() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "old-password");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();
    engine.change_password("old-password", "new-password").unwrap();
    engine.lock().unwrap();

    // The backup still works, but only with the new password (B8).
    fs::copy(dir.file("personal.bkp"), dir.file("from-backup.vault")).unwrap();
    assert!(matches!(engine.unlock("from-backup", "old-password"), Err(VaultError::InvalidPassword)));
    engine.unlock("from-backup", "new-password").unwrap();
    assert_eq!(engine.get("github").unwrap().passwd, "hunter2");
}

#[test]
fn a_passwd_that_cannot_be_saved_keeps_the_old_password() {
    let dir = TempDir::new();
    let (mut engine, saves_left) = FailingSaves::engine(&dir, usize::MAX);
    engine.create_vault("personal", "old-password").unwrap();
    saves_left.set(0);
    assert!(engine.change_password("old-password", "new-password").is_err());

    // A later commit must not switch to the new password behind the user's back.
    saves_left.set(usize::MAX);
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();
    engine.lock().unwrap();
    assert!(matches!(engine.unlock("personal", "new-password"), Err(VaultError::InvalidPassword)));
    engine.unlock("personal", "old-password").unwrap();
}

#[test]
fn a_passwd_whose_backup_cannot_be_refreshed_says_so() {
    let dir = TempDir::new();
    let (mut engine, saves_left) = FailingSaves::engine(&dir, usize::MAX);
    engine.create_vault("personal", "old-password").unwrap();
    saves_left.set(1); // the password change is saved, the backup refresh isn't
    assert!(matches!(engine.change_password("old-password", "new-password"), Err(VaultError::StaleBackup(_))));

    // The password did change, and committing again fixes the backup.
    saves_left.set(usize::MAX);
    engine.commit().unwrap();
    engine.lock().unwrap();
    engine.unlock("personal", "new-password").unwrap();
    engine.lock().unwrap();
    fs::copy(dir.file("personal.bkp"), dir.file("from-backup.vault")).unwrap();
    assert!(matches!(engine.unlock("from-backup", "old-password"), Err(VaultError::InvalidPassword)));
    engine.unlock("from-backup", "new-password").unwrap();
}

#[test]
fn export_then_import_round_trip() {
    let dir = TempDir::new();
    let csv = dir.file("export.csv");

    let mut source = created(&dir, "source", "password");
    source.add("github", "alice", "hunter2").unwrap();
    source.add("bank", "0042", "0099").unwrap();
    source.set_notes("bank", "agência 0001, conta 12345-6".into()).unwrap();
    source.export(path_str(&csv)).unwrap();
    source.lock().unwrap();

    let mut target = created(&dir, "target", "password");
    target.add("github", "existing", "keep-me").unwrap();
    target.commit().unwrap();

    assert_eq!(target.import(path_str(&csv)).unwrap(), 1); // github already exists
    assert!(target.is_dirty());
    assert_eq!(target.get("github").unwrap().passwd, "keep-me");
    let bank = target.get("bank").unwrap();
    assert_eq!((bank.username.as_str(), bank.passwd.as_str()), ("0042", "0099"));
    assert_eq!(bank.notes, "agência 0001, conta 12345-6");
}

#[test]
fn import_accepts_exports_from_before_notes() {
    let dir = TempDir::new();
    let csv = dir.file("old-export.csv");
    fs::write(&csv, "service,username,password\ngithub,alice,hunter2\n").unwrap();

    let mut engine = created(&dir, "personal", "password");
    assert_eq!(engine.import(path_str(&csv)).unwrap(), 1);
    let entry = engine.get("github").unwrap();
    assert_eq!((entry.passwd.as_str(), entry.notes.as_str()), ("hunter2", ""));
}

/// Imports `csv` into a new vault, returning the engine and the result.
fn import_csv(dir: &TempDir, csv: &str) -> (Engine, Result<usize, VaultError>) {
    let file = dir.file("import.csv");
    fs::write(&file, csv).unwrap();
    let mut engine = created(dir, "personal", "password");
    let result = engine.import(path_str(&file));
    (engine, result)
}

/// The message of an `Import` error, or a panic.
fn import_error(result: Result<usize, VaultError>) -> String {
    match result {
        Err(VaultError::Import(message)) => message,
        other => panic!("expected an import error, got {other:?}"),
    }
}

#[test]
fn import_finds_the_columns_by_name() {
    // Any order, any case; columns it doesn't know are ignored.
    let dir = TempDir::new();
    let (engine, result) = import_csv(
        &dir,
        "Notes, PASSWORD,url,Service,username\n2FA on,hunter2,https://github.com,github,alice\n",
    );
    assert_eq!(result.unwrap(), 1);
    let entry = engine.get("github").unwrap();
    assert_eq!(
        (entry.username.as_str(), entry.passwd.as_str(), entry.notes.as_str()),
        ("alice", "hunter2", "2FA on")
    );
}

#[test]
fn the_csv_example_in_the_readme_imports() {
    let readme = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"));
    let example = readme.split("```csv\n").nth(1).and_then(|s| s.split("```").next());
    let dir = TempDir::new();
    let (engine, result) = import_csv(&dir, example.expect("no csv block in README.md"));
    assert_eq!(result.unwrap(), 2);
    assert_eq!(engine.get("aws").unwrap().passwd, "super,secure!");
}

#[test]
fn import_refuses_a_header_without_the_columns_it_needs() {
    // Before, columns were taken by position: a browser export put the URL
    // in the username and the username in the password (B6).
    let dir = TempDir::new();
    let (engine, result) = import_csv(
        &dir,
        "name,url,username,password,note\ngithub,https://github.com,alice,hunter2,\n",
    );
    assert!(import_error(result).contains("no 'service' column"));
    assert!(engine.get_entries().unwrap().is_empty());

    let (_, result) = import_csv(&TempDir::new(), "service,username,password,Password\na,u,p,q\n");
    assert!(import_error(result).contains("more than one 'password' column"));
}

#[test]
fn a_failed_import_adds_nothing() {
    // Before, the rows above the bad one stayed, and weren't even marked as
    // changes (B6).
    let cases: [(&[u8], &str); 5] = [
        (b"service,username,password\na,u,p\nb,u,p\nbroken-row\n", "line 4: expected 3 fields"),
        // An unquoted comma in a password shifts the fields.
        (
            b"service,username,password\na,u,p\nb,u,pa,ss\n",
            "line 3: expected 3 fields, as in the header, but found 4",
        ),
        (
            b"service,username,password\na,u,p\nMy Bank,u,p\n",
            "line 3: service names can't be empty or contain spaces ('My Bank')",
        ),
        (b"service,username,password\na,u,p\n,u,p\n", "line 3: service names"),
        (b"service,username,password\na,u,p\nb,u,\xff\n", "line 3 isn't valid UTF-8"),
    ];
    for (csv, expected) in cases {
        let dir = TempDir::new();
        let file = dir.file("import.csv");
        fs::write(&file, csv).unwrap();
        let mut engine = created(&dir, "personal", "password");
        let message = import_error(engine.import(path_str(&file)));
        let csv = String::from_utf8_lossy(csv);
        assert!(message.contains(expected), "{message:?} for {csv:?}");
        assert!(engine.get_entries().unwrap().is_empty(), "{csv:?}");
        assert!(!engine.is_dirty(), "{csv:?}");
    }
}

#[test]
fn import_keeps_the_first_row_of_a_repeated_service() {
    let dir = TempDir::new();
    let (engine, result) = import_csv(
        &dir,
        "service,username,password\n github ,alice,first\ngithub,bob,second\n",
    );
    assert_eq!(result.unwrap(), 1);
    // Spaces around a name are trimmed; a password is taken as it is.
    assert_eq!(engine.get("github").unwrap().passwd, "first");
}

#[test]
fn import_reads_files_that_start_with_a_byte_order_mark() {
    // Spreadsheets add one when saving as "CSV UTF-8".
    let dir = TempDir::new();
    let (engine, result) = import_csv(&dir, "\u{feff}service,username,password\nbank,0042,0099\n");
    assert_eq!(result.unwrap(), 1);
    assert_eq!(engine.get("bank").unwrap().username, "0042");
}

#[test]
fn add_refuses_service_names_commands_cannot_reach() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "password");
    for name in ["", "My Bank", "tab\there"] {
        assert!(
            matches!(engine.add(name, "u", "p"), Err(VaultError::InvalidServiceName(_))),
            "{name:?}"
        );
    }
    assert!(engine.get_entries().unwrap().is_empty());
}

/// A committed vault with bank, github and wifi.
fn committed_three(dir: &TempDir) -> Engine {
    let mut engine = created(dir, "personal", "password");
    engine.add("bank", "bob", "0099").unwrap();
    engine.add("github", "alice", "hunter2").unwrap();
    engine.add("wifi", "home", "pass").unwrap();
    engine.commit().unwrap();
    engine
}

#[test]
fn changes_lists_what_differs_from_the_last_commit() {
    let dir = TempDir::new();
    let mut engine = committed_three(&dir);
    assert!(engine.changes().unwrap().is_empty());
    assert!(!engine.is_dirty());

    engine.update("bank", Some("carol".into()), Some("0100".into())).unwrap();
    engine.set_notes("bank", "agência 0001".into()).unwrap();
    engine.rename_entry("github", "gh").unwrap();
    engine.delete("wifi").unwrap();
    engine.add("gitlab", "alice", "tanuki").unwrap();
    assert_eq!(
        engine.changes().unwrap(),
        [
            Change::Changed { service: "bank".into(), fields: vec!["username", "password", "notes"] },
            Change::Renamed { from: "github".into(), to: "gh".into() },
            Change::Removed("wifi".into()),
            Change::Added("gitlab".into()),
        ]
    );
    assert!(engine.is_dirty());
}

#[test]
fn edits_that_undo_each_other_leave_no_change() {
    let dir = TempDir::new();
    let mut engine = committed_three(&dir);
    engine.add("gitlab", "alice", "tanuki").unwrap();
    engine.delete("gitlab").unwrap();
    engine.update("wifi", None, None).unwrap(); // blank answers: nothing changes
    engine.rename_entry("bank", "b").unwrap();
    engine.rename_entry("b", "bank").unwrap();
    assert!(engine.changes().unwrap().is_empty());
    assert!(!engine.is_dirty());

    // A password changed and changed back still leaves a trace: the history.
    engine.update("github", None, Some("other".into())).unwrap();
    engine.update("github", None, Some("hunter2".into())).unwrap();
    assert_eq!(
        engine.changes().unwrap(),
        [Change::Changed { service: "github".into(), fields: vec!["password history"] }]
    );
}

#[test]
fn discard_goes_back_to_the_last_commit() {
    let dir = TempDir::new();
    let mut engine = committed_three(&dir);
    engine.update("github", None, Some("new".into())).unwrap();
    engine.delete("bank").unwrap();
    engine.add("gitlab", "alice", "tanuki").unwrap();

    engine.discard().unwrap();
    assert!(!engine.is_dirty());
    assert_eq!(engine.get_entries().unwrap(), ["bank", "github", "wifi"]);
    let github = engine.get("github").unwrap();
    assert_eq!((github.passwd.as_str(), github.history.len()), ("hunter2", 0));
    assert!(!engine.is_locked(), "discard keeps the vault open");

    engine.lock().unwrap();
    assert!(matches!(engine.discard(), Err(VaultError::Locked)));
    assert!(matches!(engine.changes(), Err(VaultError::Locked)));
}

#[test]
fn lock_drops_every_copy_of_the_entries() {
    // Including the copy of the last commit that status and discard use.
    let dir = TempDir::new();
    let mut engine = committed_three(&dir);
    engine.add("gitlab", "alice", "tanuki").unwrap();
    assert!(engine.holds_entries());
    engine.lock().unwrap();
    assert!(!engine.holds_entries());
}

#[test]
fn a_vault_locked_without_committing_reopens_with_no_changes() {
    let dir = TempDir::new();
    let mut engine = committed_three(&dir);
    engine.add("gitlab", "alice", "tanuki").unwrap();
    engine.lock().unwrap(); // the change is dropped
    engine.unlock("personal", "password").unwrap();
    assert_eq!(engine.get_entries().unwrap(), ["bank", "github", "wifi"]);
    assert!(!engine.is_dirty(), "the prompt would show changes that don't exist");
    assert!(engine.changes().unwrap().is_empty());
}

#[test]
fn lock_if_clean_never_throws_changes_away() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "password");
    engine.add("github", "alice", "hunter2").unwrap();
    assert!(!engine.lock_if_clean().unwrap(), "locked with uncommitted changes");
    assert!(!engine.is_locked());
    assert_eq!(engine.get("github").unwrap().passwd, "hunter2");

    engine.commit().unwrap();
    assert!(engine.lock_if_clean().unwrap());
    assert!(engine.is_locked());
    assert!(matches!(engine.lock_if_clean(), Err(VaultError::Locked)));
}

#[test]
fn mv_renames_an_entry_and_keeps_the_rest() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "password");
    engine.add("github", "alice", "first").unwrap();
    engine.update("github", None, Some("second".into())).unwrap();
    engine.set_notes("github", "2FA on".into()).unwrap();
    let created_at = engine.get("github").unwrap().created_at;
    engine.commit().unwrap();

    engine.rename_entry("github", "gh").unwrap();
    assert!(engine.is_dirty());
    assert!(matches!(engine.get("github"), Err(VaultError::EntryNotFound)));
    let entry = engine.get("gh").unwrap();
    assert_eq!(entry.service, "gh");
    assert_eq!(
        (entry.username.as_str(), entry.passwd.as_str(), entry.notes.as_str()),
        ("alice", "second", "2FA on")
    );
    assert_eq!((entry.history.len(), entry.created_at), (1, created_at));

    engine.commit().unwrap();
    engine.lock().unwrap();
    engine.unlock("personal", "password").unwrap();
    assert_eq!(engine.get_entries().unwrap(), ["gh"]);
    assert_eq!(engine.get("gh").unwrap().service, "gh");
}

#[test]
fn mv_refuses_what_it_cannot_do() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "password");
    engine.add("github", "alice", "p").unwrap();
    engine.add("bank", "bob", "q").unwrap();
    engine.commit().unwrap();

    assert!(matches!(engine.rename_entry("nope", "x"), Err(VaultError::EntryNotFound)));
    assert!(matches!(engine.rename_entry("github", "bank"), Err(VaultError::EntryExists)));
    assert!(matches!(
        engine.rename_entry("github", "My Git"),
        Err(VaultError::InvalidServiceName(_))
    ));
    engine.rename_entry("github", "github").unwrap(); // nothing to do
    assert!(!engine.is_dirty());
    assert_eq!(engine.get_entries().unwrap(), ["bank", "github"]);
    assert_eq!(engine.get("bank").unwrap().username, "bob");

    engine.lock().unwrap();
    assert!(matches!(engine.rename_entry("github", "gh"), Err(VaultError::Locked)));
}

#[test]
fn previous_passwords_are_saved_with_the_entry() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "password");
    engine.add("github", "alice", "first").unwrap();
    engine.update("github", None, Some("second".into())).unwrap();
    engine.update("github", None, Some("third".into())).unwrap();
    engine.commit().unwrap();
    engine.lock().unwrap();

    engine.unlock("personal", "password").unwrap();
    let entry = engine.get("github").unwrap();
    assert_eq!(entry.passwd, "third");
    let history: Vec<&str> = entry.history.iter().map(|old| old.passwd.as_str()).collect();
    assert_eq!(history, ["second", "first"]);
}

#[test]
fn notes_are_saved_with_the_entry() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "password");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();

    engine.set_notes("github", "recovery codes in the safe".into()).unwrap();
    assert!(engine.is_dirty());
    engine.commit().unwrap();
    engine.set_notes("github", "recovery codes in the safe".into()).unwrap();
    assert!(!engine.is_dirty(), "the same notes again change nothing");

    engine.lock().unwrap();
    engine.unlock("personal", "password").unwrap();
    assert_eq!(engine.get("github").unwrap().notes, "recovery codes in the safe");
    assert!(matches!(
        engine.set_notes("missing", "x".into()),
        Err(VaultError::EntryNotFound)
    ));
}

#[test]
fn export_never_replaces_an_existing_file() {
    let dir = TempDir::new();
    let csv = dir.file("precious.csv");
    fs::write(&csv, "precious").unwrap();

    let engine = created(&dir, "personal", "password");
    assert!(matches!(engine.export(path_str(&csv)), Err(VaultError::FileExists(_))));
    assert_eq!(fs::read_to_string(&csv).unwrap(), "precious");
}

#[cfg(unix)]
#[test]
fn exports_are_readable_by_their_owner_only() {
    use super::support::mode;

    let dir = TempDir::new();
    let csv = dir.file("export.csv");
    created(&dir, "personal", "password").export(path_str(&csv)).unwrap();
    assert_eq!(mode(&csv), 0o600);
}

#[test]
fn rename_vault_moves_it_to_the_new_name() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "old", "password");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();

    engine.rename_vault("new").unwrap();
    assert_eq!(engine.current_vault().as_deref(), Some("new"));
    engine.lock().unwrap();

    assert!(matches!(engine.unlock("old", "password"), Err(VaultError::VaultNotFound)));
    engine.unlock("new", "password").unwrap();
    assert_eq!(engine.get("github").unwrap().passwd, "hunter2");
}

#[test]
fn rename_vault_refuses_a_name_already_taken() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "target", "target-password");
    engine.add("bank", "alice", "s3cr3t").unwrap();
    engine.commit().unwrap(); // target.bkp exists from here on
    engine.lock().unwrap();

    engine.create_vault("source", "source-password").unwrap();
    engine.add("github", "bob", "hunter2").unwrap();
    engine.commit().unwrap(); // and so does source.bkp
    assert!(matches!(engine.rename_vault("target"), Err(VaultError::VaultAlreadyExists)));
    assert_eq!(engine.current_vault().as_deref(), Some("source"));
    engine.lock().unwrap();

    // Both vaults and the target's backup are untouched.
    engine.unlock("target", "target-password").unwrap();
    assert_eq!(engine.get("bank").unwrap().passwd, "s3cr3t");
    engine.lock().unwrap();
    engine.unlock("source", "source-password").unwrap();
    assert_eq!(engine.get("github").unwrap().passwd, "hunter2");
    engine.lock().unwrap();
    fs::copy(dir.file("target.bkp"), dir.file("target-backup.vault")).unwrap();
    engine.unlock("target-backup", "target-password").unwrap();
}

#[test]
fn renaming_a_vault_to_its_own_name_changes_nothing() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "password");
    engine.rename_vault("personal").unwrap();
    assert_eq!(engine.current_vault().as_deref(), Some("personal"));
    assert!(dir.file("personal.vault").exists());
}

#[test]
fn gen_password_only_accepts_sensible_lengths() {
    let dir = TempDir::new();
    let engine = engine(&dir);
    for length in [MIN_GENERATED_LENGTH, 20, MAX_GENERATED_LENGTH] {
        assert_eq!(engine.gen_password(length).unwrap().len(), length);
    }
    // A huge length used to abort the whole process (B10).
    for length in [0, MIN_GENERATED_LENGTH - 1, MAX_GENERATED_LENGTH + 1, usize::MAX] {
        assert!(
            matches!(engine.gen_password(length), Err(VaultError::InvalidPasswordLength { .. })),
            "{length}"
        );
    }
}

#[test]
fn delete_vault_removes_it() {
    let dir = TempDir::new();
    let mut engine = created(&dir, "personal", "password");
    engine.add("github", "alice", "hunter2").unwrap();
    engine.commit().unwrap();
    engine.lock().unwrap();

    engine.delete_vault("personal").unwrap();
    assert!(engine.get_vaults().unwrap().is_empty());
    assert!(!dir.file("personal.bkp").exists());
    assert!(matches!(engine.unlock("personal", "password"), Err(VaultError::VaultNotFound)));
    assert!(engine.delete_vault("personal").is_err());
}
