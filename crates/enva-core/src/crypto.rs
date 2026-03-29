//! AES-256-GCM encryption engine with HKDF-SHA256 per-secret key derivation.
//!
//! Every `encrypt` call generates a fresh random salt and nonce, ensuring
//! that repeated encryptions of the same plaintext produce distinct
//! ciphertexts. The encrypted output format is `nonce || ciphertext_with_tag`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;

/// Byte-length of the AES-256 key.
pub const KEY_SIZE: usize = 32;
/// Byte-length of the AES-GCM nonce (96-bit).
pub const NONCE_SIZE: usize = 12;
/// Byte-length of the per-secret HKDF salt.
pub const SALT_SIZE: usize = 32;

const HKDF_INFO: &[u8] = b"final-agent-secrets-v1";

/// Errors produced by the cryptographic engine.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("master key must be at least {KEY_SIZE} bytes, got {actual}")]
    KeyTooShort { actual: usize },
    #[error("HKDF key derivation failed")]
    DerivationFailed,
    #[error("AES-GCM encryption failed")]
    EncryptionFailed,
    #[error("AES-GCM decryption failed — wrong key, salt, or corrupted data")]
    DecryptionFailed,
    #[error("encrypted payload too short to contain nonce ({NONCE_SIZE} bytes required)")]
    PayloadTooShort,
}

/// AES-256-GCM encryption engine backed by a master key.
///
/// Each call to [`encrypt`](SecretsCrypto::encrypt) derives a unique
/// per-secret key via HKDF-SHA256 using a fresh random salt.
pub struct SecretsCrypto {
    master_key: SecretString,
}

impl SecretsCrypto {
    /// Creates a new crypto engine.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyTooShort`] if `master_key` is shorter than
    /// [`KEY_SIZE`] bytes.
    pub fn new(master_key: SecretString) -> Result<Self, CryptoError> {
        if master_key.expose_secret().len() < KEY_SIZE {
            return Err(CryptoError::KeyTooShort {
                actual: master_key.expose_secret().len(),
            });
        }
        Ok(Self { master_key })
    }

    /// Encrypts `plaintext`, returning `(nonce || ciphertext_with_tag, salt)`.
    ///
    /// A fresh random salt and nonce are generated for every call.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] on key derivation or encryption failure.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let salt = generate_salt();
        let derived = self.derive_key(&salt)?;
        let cipher =
            Aes256Gcm::new_from_slice(&derived).map_err(|_| CryptoError::EncryptionFailed)?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok((output, salt))
    }

    /// Decrypts a payload previously produced by [`encrypt`](SecretsCrypto::encrypt).
    ///
    /// `encrypted` must be in `nonce || ciphertext_with_tag` format.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] on derivation failure, truncated payload,
    /// or authentication / decryption failure.
    pub fn decrypt(&self, encrypted: &[u8], salt: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if encrypted.len() < NONCE_SIZE {
            return Err(CryptoError::PayloadTooShort);
        }

        let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
        let derived = self.derive_key(salt)?;
        let cipher =
            Aes256Gcm::new_from_slice(&derived).map_err(|_| CryptoError::DecryptionFailed)?;
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    /// Derives a per-secret AES-256 key from the master key and the given salt
    /// via HKDF-SHA256.
    fn derive_key(&self, salt: &[u8]) -> Result<[u8; KEY_SIZE], CryptoError> {
        let hk = Hkdf::<Sha256>::new(Some(salt), self.master_key.expose_secret().as_bytes());
        let mut okm = [0u8; KEY_SIZE];
        hk.expand(HKDF_INFO, &mut okm)
            .map_err(|_| CryptoError::DerivationFailed)?;
        Ok(okm)
    }
}

/// Generates a cryptographically random salt of [`SALT_SIZE`] bytes.
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SecretString {
        SecretString::from("a]32-byte-test-master-key-value!".to_owned())
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let crypto = SecretsCrypto::new(test_key()).unwrap();
        let plaintext = b"hello, secret world!";
        let (encrypted, salt) = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted, &salt).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let crypto1 = SecretsCrypto::new(test_key()).unwrap();
        let crypto2 = SecretsCrypto::new(SecretString::from(
            "another-32-byte-key-that-differs".to_owned(),
        ))
        .unwrap();

        let (encrypted, salt) = crypto1.encrypt(b"secret data").unwrap();
        let result = crypto2.decrypt(&encrypted, &salt);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_salt_fails_decryption() {
        let crypto = SecretsCrypto::new(test_key()).unwrap();
        let (encrypted, _salt) = crypto.encrypt(b"secret data").unwrap();
        let wrong_salt = generate_salt();
        let result = crypto.decrypt(&encrypted, &wrong_salt);
        assert!(result.is_err());
    }

    #[test]
    fn different_salts_produce_different_ciphertexts() {
        let crypto = SecretsCrypto::new(test_key()).unwrap();
        let plaintext = b"same plaintext";
        let (enc1, salt1) = crypto.encrypt(plaintext).unwrap();
        let (enc2, salt2) = crypto.encrypt(plaintext).unwrap();

        assert_ne!(salt1, salt2, "salts should differ across calls");
        assert_ne!(enc1, enc2, "ciphertexts should differ across calls");

        assert_eq!(crypto.decrypt(&enc1, &salt1).unwrap(), plaintext);
        assert_eq!(crypto.decrypt(&enc2, &salt2).unwrap(), plaintext);
    }

    #[test]
    fn key_too_short_is_rejected() {
        let result = SecretsCrypto::new(SecretString::from("short".to_owned()));
        assert!(result.is_err());
    }

    #[test]
    fn payload_too_short_is_rejected() {
        let crypto = SecretsCrypto::new(test_key()).unwrap();
        let result = crypto.decrypt(&[0u8; 5], &[0u8; SALT_SIZE]);
        assert!(result.is_err());
    }

    #[test]
    fn generate_salt_returns_correct_length() {
        let salt = generate_salt();
        assert_eq!(salt.len(), SALT_SIZE);
    }
}
