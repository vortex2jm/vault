//! Vault files written by older versions. A failure here means existing
//! vaults may stop opening: change the format only on purpose, with a
//! migration and a new fixture.

use std::fs;

use super::support::{CHEAP, Engine, TempDir, engine};
use crate::{
    application::engine::Upgrade,
    domain::format::{CURRENT_VERSION, VaultFile},
};

/// Vaults written by older versions of this program, committed to the
/// repository. Never regenerate them: their whole point is to stay old.
const V0_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v0.vault");
const V1_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v1.vault");
const FIXTURE_PASSWORD: &str = "fixture-password";

fn assert_fixture_entries(engine: &Engine) {
    assert_eq!(engine.get_entries().unwrap(), ["bank", "github", "wifi", "ção"]);
    let expected = [
        ("bank", "0042", "0099"),
        ("github", "alice", "hunter2"),
        ("wifi", "home network", "pass with spaces"),
        ("ção", "jöão", "pässwörd 🔑"),
    ];
    for (service, username, password) in expected {
        let entry = engine.get(service).unwrap();
        assert_eq!((entry.username.as_str(), entry.passwd.as_str()), (username, password));
    }
}

#[test]
fn v0_vaults_open_and_are_upgraded_in_place() {
    let dir = TempDir::new();
    let original = fs::read(V0_FIXTURE).unwrap();
    fs::write(dir.file("fixture.vault"), &original).unwrap();

    let mut engine = engine(&dir);
    assert_eq!(engine.unlock("fixture", FIXTURE_PASSWORD).unwrap(), Upgrade::Done);
    assert_fixture_entries(&engine);

    // Rewritten in the current format; the original file is the backup.
    let upgraded = VaultFile::decode(&fs::read(dir.file("fixture.vault")).unwrap()).unwrap();
    assert_eq!((upgraded.version, upgraded.kdf), (CURRENT_VERSION, CHEAP));
    assert_eq!(fs::read(dir.file("fixture.bkp")).unwrap(), original);

    // It opens again, with nothing left to upgrade.
    engine.lock().unwrap();
    assert_eq!(engine.unlock("fixture", FIXTURE_PASSWORD).unwrap(), Upgrade::None);
    assert_fixture_entries(&engine);
}

#[test]
fn v1_vaults_open_as_they_are() {
    let dir = TempDir::new();
    let original = fs::read(V1_FIXTURE).unwrap();
    assert_eq!(VaultFile::decode(&original).unwrap().version, 1);
    fs::write(dir.file("fixture.vault"), &original).unwrap();

    let mut engine = engine(&dir);
    assert_eq!(engine.unlock("fixture", FIXTURE_PASSWORD).unwrap(), Upgrade::None);
    assert_fixture_entries(&engine);
    assert_eq!(fs::read(dir.file("fixture.vault")).unwrap(), original, "opening rewrote it");
}
