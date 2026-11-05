use aes_gcm::{
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, OsRng, Payload, rand_core::RngCore},
};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::domain::{errors::CryptoError, models::KdfParams, ports::CryptoPort};

/// AES-256-GCM with a key derived by Argon2id.
///
/// The key lives in a fixed array that is wiped in place; `has_key` says
/// whether it currently holds one. An `Option<[u8; 32]>` would not do:
/// `take()` copies the bytes out and leaves the original ones behind.
#[derive(ZeroizeOnDrop)]
pub struct AesGcmCrypto {
    key: [u8; 32],
    has_key: bool,
}

impl AesGcmCrypto {
    pub fn new() -> Self {
        Self {
            key: [0; 32],
            has_key: false,
        }
    }

    /// The current key. A reference, so the key bytes are never copied.
    fn key(&self) -> Result<&[u8; 32], CryptoError> {
        if self.has_key {
            Ok(&self.key)
        } else {
            Err(CryptoError::NotInitialized)
        }
    }

    /// Derives the key for `password` and `salt` with Argon2id at cost `kdf`
    /// into `out`, wiping `out` if the derivation fails.
    fn derive_into(
        password: &str,
        salt: &[u8],
        kdf: &KdfParams,
        out: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(out.len()))
            .map_err(|_| CryptoError::KeyDerivationError)?;
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password.as_bytes(), salt, out)
            .map_err(|_| {
                out.zeroize();
                CryptoError::KeyDerivationError
            })
    }
}

impl CryptoPort for AesGcmCrypto {
    fn init(&mut self, password: &str, salt: &[u8], kdf: &KdfParams) -> Result<(), CryptoError> {
        self.reset();
        // Derived straight into the struct, so the key never sits in a temporary.
        Self::derive_into(password, salt, kdf, &mut self.key)?;
        self.has_key = true;
        Ok(())
    }

    fn reset(&mut self) {
        self.key.zeroize();
        self.has_key = false;
    }

    fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 12]), CryptoError> {
        let key = Key::<Aes256Gcm>::from_slice(self.key()?);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let payload = Payload {
            msg: plaintext,
            aad: associated_data,
        };
        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| CryptoError::Aead(e.to_string()))?;
        Ok((ciphertext, nonce.into()))
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key = Key::<Aes256Gcm>::from_slice(self.key()?);
        let cipher = Aes256Gcm::new(key);
        let nonce_array: [u8; 12] = nonce.try_into().map_err(|_| CryptoError::InvalidNonce)?;
        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };
        let plaintext = cipher
            .decrypt(&Nonce::from(nonce_array), payload)
            .map_err(|e| CryptoError::Aead(e.to_string()))?;
        Ok(plaintext)
    }

    fn salt_gen(&self) -> [u8; 16] {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    fn gen_password(&self, length: usize) -> String {
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        let n = CHARSET.len();
        let limit = (256 / n) * n;
        let mut password = String::with_capacity(length);
        let mut buf = [0u8; 1];
        while password.len() < length {
            OsRng.fill_bytes(&mut buf);
            let b = buf[0] as usize;
            if b < limit {
                password.push(CHARSET[b % n] as char);
            }
        }
        password
    }

    fn verify_password(&self, password: &str, salt: &[u8], kdf: &KdfParams) -> bool {
        let Ok(current) = self.key() else {
            return false;
        };
        let mut derived = [0u8; 32];
        let matches =
            Self::derive_into(password, salt, kdf, &mut derived).is_ok() && &derived == current;
        derived.zeroize();
        matches
    }
}
