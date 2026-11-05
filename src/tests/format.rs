//! The vault file format (`domain::format`): both versions' layouts and the
//! plaintext codec. A change here is a change to every vault on disk.

use std::collections::BTreeMap;

use crate::domain::{
    format::{self, CURRENT_VERSION, FormatError, VaultFile},
    models::{Entry, KdfParams},
};

const KDF: KdfParams = KdfParams {
    m_cost: 65536,
    t_cost: 3,
    p_cost: 1,
};

fn sample_file() -> VaultFile {
    VaultFile {
        version: CURRENT_VERSION,
        kdf: KDF,
        salt: [7; 16],
        nonce: [9; 12],
        cipher: vec![1, 2, 3, 4],
    }
}

/// A version-0 file holding the ciphertext `[1, 2, 3, 4]`.
fn v0_bytes() -> Vec<u8> {
    let mut bytes = vec![7; 16]; // salt
    bytes.extend([9; 12]); // nonce
    bytes.extend(4u64.to_le_bytes()); // ciphertext length
    bytes.extend([1, 2, 3, 4]);
    bytes
}

fn sample_entries() -> BTreeMap<String, Entry> {
    [
        ("bank", "0042", "0099", "agência 0001"),
        ("ção", "jöão", "pässwörd 🔑", ""),
        ("empty", "", "", ""),
    ]
    .into_iter()
    .map(|(service, user, pass, notes)| {
        let mut entry = Entry::new(service.into(), user.into(), pass.into());
        entry.notes = notes.into();
        (service.to_string(), entry)
    })
    .collect()
}

/// The plaintext of one entry "ab" (user "c", empty password, notes "n",
/// created 1, updated 2), with or without the notes field.
fn one_entry_bytes(with_notes: bool) -> Vec<u8> {
    let mut bytes = 1u64.to_le_bytes().to_vec(); // one entry
    let texts: &[&str] = if with_notes {
        &["ab", "ab", "c", "", "n"] // key, service, username, password, notes
    } else {
        &["ab", "ab", "c", ""]
    };
    for text in texts {
        bytes.extend((text.len() as u64).to_le_bytes());
        bytes.extend(text.as_bytes());
    }
    bytes.extend(1i64.to_le_bytes()); // created_at
    bytes.extend(2i64.to_le_bytes()); // updated_at
    bytes
}

#[test]
fn the_current_layout_is_header_nonce_then_ciphertext() {
    let mut expected = b"VAULT\0".to_vec();
    expected.extend(CURRENT_VERSION.to_le_bytes()); // format version
    expected.push(1); // Argon2id
    expected.extend(65536u32.to_le_bytes()); // memory, KiB
    expected.extend(3u32.to_le_bytes()); // passes
    expected.extend(1u32.to_le_bytes()); // lanes
    expected.extend([7; 16]); // salt
    let header_len = expected.len();
    expected.extend([9; 12]); // nonce
    expected.extend([1, 2, 3, 4]); // ciphertext

    let file = sample_file();
    assert_eq!(file.encode(), expected);
    assert_eq!(file.associated_data(), expected[..header_len]);
    assert_eq!(VaultFile::decode(&expected).unwrap(), file);
}

#[test]
fn version_0_files_decode_with_the_legacy_cost_and_no_associated_data() {
    let file = VaultFile::decode(&v0_bytes()).unwrap();
    assert_eq!(
        file,
        VaultFile {
            version: 0,
            kdf: KdfParams::LEGACY,
            salt: [7; 16],
            nonce: [9; 12],
            cipher: vec![1, 2, 3, 4],
        }
    );
    assert!(file.associated_data().is_empty());
}

#[test]
fn a_header_cut_short_is_rejected() {
    let bytes = sample_file().encode();
    let before_ciphertext = bytes.len() - 4;
    for len in 0..before_ciphertext {
        assert!(VaultFile::decode(&bytes[..len]).is_err(), "{len} bytes");
    }
}

#[test]
fn a_version_0_file_must_be_exactly_as_long_as_it_says() {
    let mut bytes = v0_bytes();
    for len in 0..bytes.len() {
        assert!(VaultFile::decode(&bytes[..len]).is_err(), "{len} bytes");
    }
    bytes.push(0);
    assert_eq!(VaultFile::decode(&bytes), Err(FormatError::TrailingBytes));
}

#[test]
fn newer_versions_are_refused_with_their_number() {
    let mut bytes = sample_file().encode();
    bytes[6..8].copy_from_slice(&7u16.to_le_bytes());
    assert_eq!(VaultFile::decode(&bytes), Err(FormatError::UnsupportedVersion(7)));
}

#[test]
fn unreasonable_kdf_costs_are_refused_before_deriving_anything() {
    // The header is authenticated only after the key is derived: a damaged
    // or hostile one must not get to ask for gigabytes of memory.
    for kdf in [
        KdfParams { m_cost: 4 * 1024 * 1024, ..KDF }, // 4 GiB
        KdfParams { m_cost: 4, ..KDF },               // below Argon2's minimum
        KdfParams { t_cost: 0, ..KDF },
        KdfParams { t_cost: 1000, ..KDF },
        KdfParams { p_cost: 0, ..KDF },
    ] {
        let bytes = VaultFile { kdf, ..sample_file() }.encode();
        assert_eq!(VaultFile::decode(&bytes), Err(FormatError::BadKdf), "{kdf:?}");
    }

    let mut bytes = sample_file().encode();
    bytes[8] = 2; // an unknown key derivation function
    assert_eq!(VaultFile::decode(&bytes), Err(FormatError::BadKdf));
}

fn decode(bytes: &[u8]) -> Result<BTreeMap<String, Entry>, FormatError> {
    format::decode_entries(bytes, CURRENT_VERSION)
}

#[test]
fn entries_round_trip() {
    let entries = sample_entries();
    assert_eq!(decode(&format::encode_entries(&entries)).unwrap(), entries);

    let none = BTreeMap::new();
    assert_eq!(decode(&format::encode_entries(&none)).unwrap(), none);
}

#[test]
fn the_current_plaintext_has_notes_after_the_password() {
    let mut entry = Entry::new("ab".into(), "c".into(), "".into());
    entry.notes = "n".into();
    entry.created_at = 1;
    entry.updated_at = 2;
    let entries = BTreeMap::from([("ab".to_string(), entry)]);
    assert_eq!(format::encode_entries(&entries), one_entry_bytes(true));
}

#[test]
fn plaintext_from_before_notes_decodes_with_empty_notes() {
    // Versions 0 and 1 had no notes field.
    for version in [0, 1] {
        let entries = format::decode_entries(&one_entry_bytes(false), version).unwrap();
        let entry = &entries["ab"];
        assert_eq!((entry.username.as_str(), entry.notes.as_str()), ("c", ""));
        assert_eq!((entry.created_at, entry.updated_at), (1, 2));
    }
    // Read with the wrong version, the same bytes don't line up.
    assert!(decode(&one_entry_bytes(false)).is_err());
}

#[test]
fn entries_have_no_size_limit() {
    // The old serialisation library refused to read anything over 4 MiB (B3).
    let big = "x".repeat(5 * 1024 * 1024);
    let entries = BTreeMap::from([(
        "big".to_string(),
        Entry::new("big".into(), "u".into(), big.clone()),
    )]);
    let decoded = decode(&format::encode_entries(&entries)).unwrap();
    assert_eq!(decoded["big"].passwd, big);
}

#[test]
fn lying_lengths_fail_without_allocating() {
    // Claims u64::MAX entries, or a key of u64::MAX bytes, with nothing behind it.
    let huge_count = u64::MAX.to_le_bytes().to_vec();
    assert_eq!(decode(&huge_count), Err(FormatError::Truncated));

    let mut huge_key = 1u64.to_le_bytes().to_vec();
    huge_key.extend(u64::MAX.to_le_bytes());
    assert_eq!(decode(&huge_key), Err(FormatError::Truncated));
}

#[test]
fn damaged_plaintext_is_rejected() {
    let bytes = format::encode_entries(&sample_entries());
    for len in 0..bytes.len() {
        assert!(decode(&bytes[..len]).is_err(), "{len} bytes");
    }

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(decode(&trailing), Err(FormatError::TrailingBytes));

    let mut not_utf8 = bytes.clone();
    not_utf8[16] = 0xFF; // first byte of the first key
    assert_eq!(decode(&not_utf8), Err(FormatError::InvalidText));
}
