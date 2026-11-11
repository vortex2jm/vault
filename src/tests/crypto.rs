//! `AesGcmCrypto`: key derivation, AES-256-GCM and the password generator.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::ZeroizeOnDrop;

use super::support::CHEAP;
use crate::{
    adapters::aes_crypto::AesGcmCrypto,
    domain::{errors::CryptoError, models::KdfParams, ports::CryptoPort},
};

const SALT: [u8; 16] = [7; 16];
const AAD: &[u8] = b"header";

fn ready(password: &str) -> AesGcmCrypto {
    let mut crypto = AesGcmCrypto::new();
    crypto.init(password, &SALT, &CHEAP).unwrap();
    crypto
}

/// Argon2id(password, SALT) at cost `kdf`, computed independently of the adapter.
fn derived_key(password: &str, kdf: &KdfParams) -> [u8; 32] {
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32)).unwrap();
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &SALT, &mut key)
        .unwrap();
    key
}

/// The struct's bytes, as a memory dump would show them.
fn memory_of(crypto: &AesGcmCrypto) -> &[u8] {
    // Only sound while every byte is initialised: 32 key bytes and a bool,
    // no padding. Revisit this helper if the layout changes.
    assert_eq!(size_of::<AesGcmCrypto>(), 33, "AesGcmCrypto layout changed");
    // SAFETY: the struct is plain initialised bytes (checked above).
    unsafe {
        std::slice::from_raw_parts(
            (crypto as *const AesGcmCrypto).cast::<u8>(),
            size_of::<AesGcmCrypto>(),
        )
    }
}

/// Compiles only for types that wipe themselves when dropped.
fn wiped_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn the_cipher_wipes_its_keys_when_dropped() {
    // A cipher lives only for one encrypt or decrypt. Its AES round keys
    // contain the key itself, and the aes crate wipes them only with its
    // `zeroize` feature on.
    wiped_on_drop::<aes::Aes256>();
}

#[test]
fn argon2s_working_memory_is_wiped_after_deriving() {
    let mut memory = Vec::new();
    let mut key = [0u8; 32];
    AesGcmCrypto::derive_with_memory("pw", &SALT, &CHEAP, &mut key, &mut memory).unwrap();
    assert_eq!(memory.len(), 64, "one 1 KiB block per KiB of memory cost");
    assert!(memory.iter().all(|block| block.as_ref().iter().all(|&word| word == 0)));
    assert_eq!(key, derived_key("pw", &CHEAP), "the key itself is unchanged");
}

#[test]
fn reset_wipes_the_key_from_memory() {
    let key = derived_key("pw", &CHEAP);
    let holds_key = |crypto: &AesGcmCrypto| memory_of(crypto).windows(32).any(|w| w == key);

    let mut crypto = ready("pw");
    assert!(holds_key(&crypto));
    crypto.reset();
    assert!(!holds_key(&crypto));

    // It can be initialised again afterwards.
    crypto.init("pw", &SALT, &CHEAP).unwrap();
    assert!(holds_key(&crypto));
}

#[test]
fn the_legacy_cost_reproduces_the_key_of_old_vaults() {
    // Version-0 vaults were keyed with the argon2 crate's defaults.
    let mut old = [0u8; 32];
    Argon2::default().hash_password_into(b"pw", &SALT, &mut old).unwrap();
    assert_eq!(derived_key("pw", &KdfParams::LEGACY), old);
}

#[test]
fn the_key_depends_on_the_kdf_cost() {
    let costlier = KdfParams { t_cost: 2, ..CHEAP };
    assert_ne!(derived_key("pw", &CHEAP), derived_key("pw", &costlier));

    let (cipher, nonce) = ready("pw").encrypt(b"secret", AAD).unwrap();
    let mut other = AesGcmCrypto::new();
    other.init("pw", &SALT, &costlier).unwrap();
    assert!(other.decrypt(&cipher, &nonce, AAD).is_err());
}

#[test]
fn invalid_kdf_costs_are_rejected() {
    let mut crypto = AesGcmCrypto::new();
    let no_passes = KdfParams { t_cost: 0, ..CHEAP };
    assert!(matches!(
        crypto.init("pw", &SALT, &no_passes),
        Err(CryptoError::KeyDerivationError)
    ));
    assert!(matches!(crypto.encrypt(b"x", AAD), Err(CryptoError::NotInitialized)));
}

#[test]
fn encrypt_decrypt_round_trip() {
    let crypto = ready("pw");
    let (cipher, nonce) = crypto.encrypt(b"secret data", AAD).unwrap();
    assert_ne!(&cipher[..], b"secret data");
    assert_eq!(crypto.decrypt(&cipher, &nonce, AAD).unwrap(), b"secret data");
}

#[test]
fn the_associated_data_must_match() {
    let crypto = ready("pw");
    let (cipher, nonce) = crypto.encrypt(b"secret", b"header v1").unwrap();
    assert_eq!(crypto.decrypt(&cipher, &nonce, b"header v1").unwrap(), b"secret");
    assert!(crypto.decrypt(&cipher, &nonce, b"header v2").is_err());
    assert!(crypto.decrypt(&cipher, &nonce, b"").is_err());
}

#[test]
fn every_encryption_uses_a_fresh_nonce() {
    let crypto = ready("pw");
    let (cipher1, nonce1) = crypto.encrypt(b"same", AAD).unwrap();
    let (cipher2, nonce2) = crypto.encrypt(b"same", AAD).unwrap();
    assert_ne!(nonce1, nonce2);
    assert_ne!(cipher1, cipher2);
}

#[test]
fn tampering_is_detected() {
    let crypto = ready("pw");
    let (mut cipher, mut nonce) = crypto.encrypt(b"secret", AAD).unwrap();

    cipher[0] ^= 1;
    assert!(crypto.decrypt(&cipher, &nonce, AAD).is_err());
    cipher[0] ^= 1;

    nonce[0] ^= 1;
    assert!(crypto.decrypt(&cipher, &nonce, AAD).is_err());
}

#[test]
fn wrong_password_cannot_decrypt() {
    let (cipher, nonce) = ready("right").encrypt(b"secret", AAD).unwrap();
    assert!(ready("wrong").decrypt(&cipher, &nonce, AAD).is_err());
}

#[test]
fn uninitialized_or_reset_crypto_refuses_to_work() {
    let mut crypto = AesGcmCrypto::new();
    assert!(matches!(crypto.encrypt(b"x", AAD), Err(CryptoError::NotInitialized)));

    crypto.init("pw", &SALT, &CHEAP).unwrap();
    crypto.reset();
    assert!(matches!(crypto.encrypt(b"x", AAD), Err(CryptoError::NotInitialized)));
    assert!(matches!(
        crypto.decrypt(b"x", &[0; 12], AAD),
        Err(CryptoError::NotInitialized)
    ));
}

#[test]
fn invalid_nonce_length_is_rejected() {
    let crypto = ready("pw");
    assert!(matches!(
        crypto.decrypt(b"whatever", &[0; 5], AAD),
        Err(CryptoError::InvalidNonce)
    ));
}

#[test]
fn verify_password_matches_only_the_current_key() {
    let crypto = ready("pw");
    assert!(crypto.verify_password("pw", &SALT, &CHEAP));
    assert!(!crypto.verify_password("other", &SALT, &CHEAP));
    assert!(!crypto.verify_password("pw", &[8; 16], &CHEAP));
    assert!(!crypto.verify_password("pw", &SALT, &KdfParams { t_cost: 2, ..CHEAP }));
    assert!(!AesGcmCrypto::new().verify_password("pw", &SALT, &CHEAP));
}

#[test]
fn salts_are_random() {
    let crypto = AesGcmCrypto::new();
    assert_ne!(crypto.salt_gen(), crypto.salt_gen());
}

#[test]
fn random_below_covers_the_range_evenly() {
    let crypto = AesGcmCrypto::new();
    let mut counts = [0usize; 7];
    for _ in 0..7000 {
        counts[crypto.random_below(7)] += 1;
    }
    // About 1000 each; this far off would take a broken draw.
    assert!(counts.iter().all(|&c| (700..1300).contains(&c)), "{counts:?}");
    assert_eq!(crypto.random_below(1), 0);
}
