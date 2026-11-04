//! On-disk format. A failure here means existing vaults may stop opening:
//! change the format only on purpose, together with a migration (E1).

use std::fs;

use super::support::{TempDir, engine};
use crate::domain::models::VaultState;

/// A vault written by the current (v0) format, committed to the repository.
/// Never regenerate it: its whole point is to stay old.
const V0_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v0.vault");
const V0_PASSWORD: &str = "fixture-password";

#[test]
fn v0_layout_is_salt_nonce_then_length_prefixed_ciphertext() {
    let state = VaultState {
        salt: [1; 16],
        nonce: [2; 12],
        cipher: vec![3, 4, 5],
    };
    let mut bytes = Vec::new();
    wincode::serialize_into(&mut bytes, &state).unwrap();

    let mut expected = vec![1; 16];
    expected.extend([2; 12]);
    expected.extend(3u64.to_le_bytes());
    expected.extend([3, 4, 5]);
    assert_eq!(bytes, expected);
}

#[test]
fn v0_vaults_still_open() {
    let dir = TempDir::new();
    fs::copy(V0_FIXTURE, dir.file("fixture.vault")).unwrap();

    let mut engine = engine(&dir);
    engine.unlock("fixture", V0_PASSWORD).unwrap();

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
