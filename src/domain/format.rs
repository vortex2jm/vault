//! The vault file format, byte by byte. Pure functions, no I/O.
//!
//! Version 1, written by this version:
//!
//! | bytes | field                                         |
//! |-------|-----------------------------------------------|
//! | 6     | magic `VAULT\0`                               |
//! | 2     | format version, u16 LE                        |
//! | 1     | key derivation: 1 = Argon2id                  |
//! | 4     | Argon2 memory in KiB, u32 LE                  |
//! | 4     | Argon2 passes, u32 LE                         |
//! | 4     | Argon2 lanes, u32 LE                          |
//! | 16    | salt                                          |
//! | 12    | AES-GCM nonce                                 |
//! | rest  | AES-256-GCM ciphertext, ending in its 16-byte tag |
//!
//! Everything before the nonce is the header. AES-GCM authenticates it as
//! associated data, so changing any header byte makes decryption fail.
//!
//! Version 0, before the format had a version: salt (16) | nonce (12) |
//! ciphertext length (u64 LE) | ciphertext. Its key was derived with
//! [`KdfParams::LEGACY`], and there is no associated data.
//!
//! The plaintext is the same in both versions: the entry count (u64 LE),
//! then for each entry its service name once more as the map key, followed
//! by service, username, password, created_at (i64 LE) and updated_at
//! (i64 LE). A string is its byte length (u64 LE) followed by UTF-8. Every
//! length is checked against the bytes actually present, so there is no
//! arbitrary size limit and nothing is allocated for a length that lies.

use std::collections::BTreeMap;

use crate::domain::models::{Entry, KdfParams};

pub const MAGIC: [u8; 6] = *b"VAULT\0";
pub const CURRENT_VERSION: u16 = 1;

const ARGON2ID: u8 = 1;

/// Largest Argon2 costs accepted from a file. The header is only
/// authenticated after the key has been derived, so a damaged or hostile
/// file must not be able to demand gigabytes of memory first.
const MAX_M_COST: u32 = 1024 * 1024; // 1 GiB
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    /// The data ends before a field it announces.
    Truncated,
    /// Bytes are left over after the last field.
    TrailingBytes,
    /// Written by a newer version of this program.
    UnsupportedVersion(u16),
    /// Unknown key derivation, or costs outside the accepted range.
    BadKdf,
    /// A string isn't valid UTF-8.
    InvalidText,
}

/// A vault file, split into its fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultFile {
    pub version: u16,
    pub kdf: KdfParams,
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub cipher: Vec<u8>,
}

impl VaultFile {
    /// Parses a file in any supported version.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.starts_with(&MAGIC) {
            decode_versioned(bytes)
        } else {
            decode_v0(bytes)
        }
    }

    /// The file's bytes. Only the current version is ever written.
    pub fn encode(&self) -> Vec<u8> {
        assert_eq!(self.version, CURRENT_VERSION, "only the current version is written");
        let mut out = header(self.version, &self.kdf, &self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.cipher);
        out
    }

    /// What AES-GCM authenticates along with the ciphertext.
    pub fn associated_data(&self) -> Vec<u8> {
        match self.version {
            0 => Vec::new(),
            version => header(version, &self.kdf, &self.salt),
        }
    }
}

/// The header of a versioned file, which is also its associated data.
pub fn header(version: u16, kdf: &KdfParams, salt: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAGIC.len() + 2 + 1 + 3 * 4 + salt.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&version.to_le_bytes());
    out.push(ARGON2ID);
    out.extend_from_slice(&kdf.m_cost.to_le_bytes());
    out.extend_from_slice(&kdf.t_cost.to_le_bytes());
    out.extend_from_slice(&kdf.p_cost.to_le_bytes());
    out.extend_from_slice(salt);
    out
}

/// The plaintext for `entries`, built in a single allocation: growing a
/// buffer would leave partial copies of the secrets in freed memory.
pub fn encode_entries(entries: &BTreeMap<String, Entry>) -> Vec<u8> {
    let size = 8 + entries
        .iter()
        .map(|(key, e)| {
            4 * 8 + key.len() + e.service.len() + e.username.len() + e.passwd.len() + 2 * 8
        })
        .sum::<usize>();
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for (key, entry) in entries {
        for text in [key, &entry.service, &entry.username, &entry.passwd] {
            out.extend_from_slice(&(text.len() as u64).to_le_bytes());
            out.extend_from_slice(text.as_bytes());
        }
        out.extend_from_slice(&entry.created_at.to_le_bytes());
        out.extend_from_slice(&entry.updated_at.to_le_bytes());
    }
    debug_assert_eq!(out.len(), size);
    out
}

/// Parses the plaintext written by [`encode_entries`] (or by version 0).
pub fn decode_entries(bytes: &[u8]) -> Result<BTreeMap<String, Entry>, FormatError> {
    let mut reader = Reader { bytes };
    let count = reader.u64()?;
    let mut entries = BTreeMap::new();
    // No preallocation from `count`: a bad count just runs out of bytes.
    for _ in 0..count {
        let key = reader.string()?;
        let entry = Entry {
            service: reader.string()?,
            username: reader.string()?,
            passwd: reader.string()?,
            created_at: reader.i64()?,
            updated_at: reader.i64()?,
        };
        entries.insert(key, entry);
    }
    reader.finish()?;
    Ok(entries)
}

fn decode_v0(bytes: &[u8]) -> Result<VaultFile, FormatError> {
    let mut reader = Reader { bytes };
    let salt = reader.array()?;
    let nonce = reader.array()?;
    let len = reader.len()?;
    let cipher = reader.take(len)?.to_vec();
    reader.finish()?;
    Ok(VaultFile {
        version: 0,
        kdf: KdfParams::LEGACY,
        salt,
        nonce,
        cipher,
    })
}

fn decode_versioned(bytes: &[u8]) -> Result<VaultFile, FormatError> {
    let mut reader = Reader { bytes };
    reader.take(MAGIC.len())?;
    let version = reader.u16()?;
    if version == 0 || version > CURRENT_VERSION {
        return Err(FormatError::UnsupportedVersion(version));
    }
    if reader.array::<1>()? != [ARGON2ID] {
        return Err(FormatError::BadKdf);
    }
    let kdf = KdfParams {
        m_cost: reader.u32()?,
        t_cost: reader.u32()?,
        p_cost: reader.u32()?,
    };
    if !acceptable(&kdf) {
        return Err(FormatError::BadKdf);
    }
    let salt = reader.array()?;
    let nonce = reader.array()?;
    Ok(VaultFile {
        version,
        kdf,
        salt,
        nonce,
        cipher: reader.bytes.to_vec(),
    })
}

/// Costs Argon2 accepts, within the limits a file may ask for.
fn acceptable(kdf: &KdfParams) -> bool {
    (1..=MAX_P_COST).contains(&kdf.p_cost)
        && (1..=MAX_T_COST).contains(&kdf.t_cost)
        && (8 * kdf.p_cost..=MAX_M_COST).contains(&kdf.m_cost)
}

/// Reads fields front to back; reading past the end is `Truncated`.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], FormatError> {
        if self.bytes.len() < n {
            return Err(FormatError::Truncated);
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FormatError> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, FormatError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, FormatError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, FormatError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn i64(&mut self) -> Result<i64, FormatError> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    /// A length prefix, which can't be more than the bytes left.
    fn len(&mut self) -> Result<usize, FormatError> {
        let len = self.u64()?;
        usize::try_from(len)
            .ok()
            .filter(|&len| len <= self.bytes.len())
            .ok_or(FormatError::Truncated)
    }

    fn string(&mut self) -> Result<String, FormatError> {
        let len = self.len()?;
        String::from_utf8(self.take(len)?.to_vec()).map_err(|_| FormatError::InvalidText)
    }

    fn finish(self) -> Result<(), FormatError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(FormatError::TrailingBytes)
        }
    }
}
