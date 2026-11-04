//! `AesGcmCrypto`: key derivation, AES-256-GCM and the password generator.

use argon2::Argon2;

use crate::{
    adapters::aes_crypto::AesGcmCrypto,
    domain::{errors::CryptoError, ports::CryptoPort},
};

const SALT: [u8; 16] = [7; 16];

fn ready(password: &str) -> AesGcmCrypto {
    let mut crypto = AesGcmCrypto::new();
    crypto.init(password, &SALT).unwrap();
    crypto
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

#[test]
fn reset_wipes_the_key_from_memory() {
    let mut key = [0u8; 32];
    Argon2::default().hash_password_into(b"pw", &SALT, &mut key).unwrap();
    let holds_key = |crypto: &AesGcmCrypto| memory_of(crypto).windows(32).any(|w| w == key);

    let mut crypto = ready("pw");
    assert!(holds_key(&crypto));
    crypto.reset();
    assert!(!holds_key(&crypto));

    // It can be initialised again afterwards.
    crypto.init("pw", &SALT).unwrap();
    assert!(holds_key(&crypto));
}

#[test]
fn encrypt_decrypt_round_trip() {
    let crypto = ready("pw");
    let (cipher, nonce) = crypto.encrypt(b"secret data").unwrap();
    assert_ne!(&cipher[..], b"secret data");
    assert_eq!(crypto.decrypt(&cipher, &nonce).unwrap(), b"secret data");
}

#[test]
fn every_encryption_uses_a_fresh_nonce() {
    let crypto = ready("pw");
    let (cipher1, nonce1) = crypto.encrypt(b"same").unwrap();
    let (cipher2, nonce2) = crypto.encrypt(b"same").unwrap();
    assert_ne!(nonce1, nonce2);
    assert_ne!(cipher1, cipher2);
}

#[test]
fn tampering_is_detected() {
    let crypto = ready("pw");
    let (mut cipher, mut nonce) = crypto.encrypt(b"secret").unwrap();

    cipher[0] ^= 1;
    assert!(crypto.decrypt(&cipher, &nonce).is_err());
    cipher[0] ^= 1;

    nonce[0] ^= 1;
    assert!(crypto.decrypt(&cipher, &nonce).is_err());
}

#[test]
fn wrong_password_cannot_decrypt() {
    let (cipher, nonce) = ready("right").encrypt(b"secret").unwrap();
    assert!(ready("wrong").decrypt(&cipher, &nonce).is_err());
}

#[test]
fn uninitialized_or_reset_crypto_refuses_to_work() {
    let mut crypto = AesGcmCrypto::new();
    assert!(matches!(crypto.encrypt(b"x"), Err(CryptoError::NotInitialized)));

    crypto.init("pw", &SALT).unwrap();
    crypto.reset();
    assert!(matches!(crypto.encrypt(b"x"), Err(CryptoError::NotInitialized)));
    assert!(matches!(crypto.decrypt(b"x", &[0; 12]), Err(CryptoError::NotInitialized)));
}

#[test]
fn invalid_nonce_length_is_rejected() {
    let crypto = ready("pw");
    assert!(matches!(crypto.decrypt(b"whatever", &[0; 5]), Err(CryptoError::InvalidNonce)));
}

#[test]
fn verify_password_matches_only_the_current_key() {
    let crypto = ready("pw");
    assert!(crypto.verify_password("pw", &SALT));
    assert!(!crypto.verify_password("other", &SALT));
    assert!(!crypto.verify_password("pw", &[8; 16]));
    assert!(!AesGcmCrypto::new().verify_password("pw", &SALT));
}

#[test]
fn salts_are_random() {
    let crypto = AesGcmCrypto::new();
    assert_ne!(crypto.salt_gen(), crypto.salt_gen());
}

#[test]
fn generated_passwords_have_the_requested_length_and_charset() {
    let crypto = AesGcmCrypto::new();
    for len in [1, 20, 64] {
        let password = crypto.gen_password(len);
        assert_eq!(password.len(), len);
        assert!(
            password
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!@#$%^&*".contains(&b)),
            "{password}"
        );
    }
    assert_ne!(crypto.gen_password(20), crypto.gen_password(20));
}
