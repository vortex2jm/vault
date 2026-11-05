//! Vault files written by older versions. A failure here means existing
//! vaults may stop opening: change the format only on purpose, with a
//! migration and a new fixture.

use std::fs;

use super::support::{Engine, TempDir, engine, engine_with_kdf};
use crate::{
    application::engine::Upgrade,
    domain::{
        format::{CURRENT_VERSION, VaultFile},
        models::KdfParams,
    },
};

/// Vaults written by older versions of this program, committed to the
/// repository. Never regenerate them: their whole point is to stay old.
const V0_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v0.vault");
const V1_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v1.vault");
const V2_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v2.vault");
const V3_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v3.vault");
const FIXTURE_PASSWORD: &str = "fixture-password";

/// The entries every fixture holds, as far as the format `version` it was
/// written in could carry them: notes from v2 on, previous passwords from v3
/// on (github was created as "hunter0", then changed twice).
fn assert_fixture_entries(engine: &Engine, version: u16) {
    assert_eq!(engine.get_entries().unwrap(), ["bank", "github", "wifi", "ção"]);
    let expected = [
        ("bank", "0042", "0099", "agência 0001"),
        ("github", "alice", "hunter2", "recovery codes in the safe"),
        ("wifi", "home network", "pass with spaces", ""),
        ("ção", "jöão", "pässwörd 🔑", ""),
    ];
    for (service, username, password, notes) in expected {
        let entry = engine.get(service).unwrap();
        let notes = if version >= 2 { notes } else { "" };
        assert_eq!(
            (entry.username.as_str(), entry.passwd.as_str(), entry.notes.as_str()),
            (username, password, notes),
            "{service}"
        );
        let history: Vec<&str> = entry.history.iter().map(|old| old.passwd.as_str()).collect();
        let expected: &[&str] = match service {
            "github" if version >= 3 => &["hunter1", "hunter0"],
            _ => &[],
        };
        assert_eq!(history, expected, "{service}");
    }
}

/// Copies `fixture` into a fresh directory as `fixture.vault`.
fn copy_fixture(fixture: &str) -> (TempDir, Vec<u8>) {
    let dir = TempDir::new();
    let original = fs::read(fixture).unwrap();
    fs::write(dir.file("fixture.vault"), &original).unwrap();
    (dir, original)
}

fn current_file(dir: &TempDir) -> VaultFile {
    VaultFile::decode(&fs::read(dir.file("fixture.vault")).unwrap()).unwrap()
}

#[test]
fn v0_vaults_are_rewritten_in_the_current_format() {
    let (dir, original) = copy_fixture(V0_FIXTURE);
    let mut engine = engine(&dir);
    assert_eq!(engine.unlock("fixture", FIXTURE_PASSWORD).unwrap(), Upgrade::Done);
    assert_fixture_entries(&engine, 0);

    // Current format; the original file is the backup. The test engine's
    // cost (CHEAP) is below the legacy one, and a key is never weakened.
    let upgraded = current_file(&dir);
    assert_eq!((upgraded.version, upgraded.kdf), (CURRENT_VERSION, KdfParams::LEGACY));
    assert_eq!(fs::read(dir.file("fixture.bkp")).unwrap(), original);

    // It opens again, with nothing left to upgrade.
    engine.lock().unwrap();
    assert_eq!(engine.unlock("fixture", FIXTURE_PASSWORD).unwrap(), Upgrade::None);
    assert_fixture_entries(&engine, 0);
}

#[test]
fn v0_vaults_get_a_stronger_key_when_the_current_cost_is_higher() {
    // As in real use, where the cost (128 MiB) is far above the legacy one.
    let stronger = KdfParams { t_cost: 3, ..KdfParams::LEGACY };
    let (dir, original) = copy_fixture(V0_FIXTURE);
    let mut engine = engine_with_kdf(dir.path(), stronger);
    assert_eq!(engine.unlock("fixture", FIXTURE_PASSWORD).unwrap(), Upgrade::Done);
    assert_fixture_entries(&engine, 0);

    let upgraded = current_file(&dir);
    assert_eq!((upgraded.version, upgraded.kdf), (CURRENT_VERSION, stronger));
    assert_ne!(upgraded.salt, VaultFile::decode(&original).unwrap().salt, "a new key gets a new salt");
}

#[test]
fn v1_and_v2_vaults_are_rewritten_in_the_current_format_with_the_same_key() {
    for (fixture, version) in [(V1_FIXTURE, 1), (V2_FIXTURE, 2)] {
        let (dir, original) = copy_fixture(fixture);
        let before = VaultFile::decode(&original).unwrap();
        assert_eq!(before.version, version);

        let mut engine = engine(&dir);
        assert_eq!(engine.unlock("fixture", FIXTURE_PASSWORD).unwrap(), Upgrade::Done, "v{version}");
        assert_fixture_entries(&engine, version);

        // Only the format changed: same salt and cost, so no key was derived again.
        let after = current_file(&dir);
        assert_eq!(after.version, CURRENT_VERSION, "v{version}");
        assert_eq!((after.salt, after.kdf), (before.salt, before.kdf), "v{version}");
        assert_eq!(fs::read(dir.file("fixture.bkp")).unwrap(), original, "v{version}");

        // What it held survives the rewrite.
        engine.lock().unwrap();
        assert_eq!(engine.unlock("fixture", FIXTURE_PASSWORD).unwrap(), Upgrade::None, "v{version}");
        assert_fixture_entries(&engine, version);
    }
}

#[test]
fn v3_vaults_open_as_they_are() {
    let (dir, original) = copy_fixture(V3_FIXTURE);
    assert_eq!(VaultFile::decode(&original).unwrap().version, 3);

    let mut engine = engine(&dir);
    assert_eq!(engine.unlock("fixture", FIXTURE_PASSWORD).unwrap(), Upgrade::None);
    assert_fixture_entries(&engine, 3);
    assert_eq!(fs::read(dir.file("fixture.vault")).unwrap(), original, "opening rewrote it");
}
