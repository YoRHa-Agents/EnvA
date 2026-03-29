//! Vault encryption engine for password-based secrets management.
//!
//! Uses Argon2id (RFC 9106) for password-based key derivation and
//! AES-256-GCM for per-value authenticated encryption. HMAC-SHA256
//! provides file-level integrity verification.
//!
//! This module provides the core vault cryptographic operations and serves
//! a fundamentally different purpose than [`crate::crypto`]: this module
//! derives keys from user passwords (memory-hard), while `crypto` derives
//! keys from existing key material via HKDF.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::Mac;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

pub const ENC_KEY_SIZE: usize = 32;
pub const HMAC_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const SALT_SIZE: usize = 32;
const TAG_SIZE: usize = 16;

type HmacSha256 = hmac::Hmac<Sha256>;

#[derive(Debug, thiserror::Error)]
pub enum VaultCryptoError {
    #[error("Argon2id key derivation failed: {0}")]
    KdfFailed(String),
    #[error("AES-GCM encryption failed")]
    EncryptionFailed,
    #[error("AES-GCM decryption failed — wrong password or corrupted data")]
    DecryptionFailed,
    #[error("invalid ENC format: {0}")]
    InvalidEncFormat(String),
    #[error("HMAC verification failed — vault data has been tampered with")]
    HmacMismatch,
    #[error("base64 decode error: {0}")]
    Base64Error(String),
}

/// Derives a 64-byte key from a password and salt using Argon2id,
/// then splits into (encryption_key[32], hmac_key[32]).
pub fn derive_key(
    password: &str,
    salt: &[u8],
    memory_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<([u8; ENC_KEY_SIZE], [u8; HMAC_KEY_SIZE]), VaultCryptoError> {
    let params = argon2::Params::new(memory_cost_kib, time_cost, parallelism, Some(64))
        .map_err(|e| VaultCryptoError::KdfFailed(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut output = [0u8; 64];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| VaultCryptoError::KdfFailed(e.to_string()))?;

    let mut enc_key = [0u8; ENC_KEY_SIZE];
    let mut hmac_key = [0u8; HMAC_KEY_SIZE];
    enc_key.copy_from_slice(&output[..32]);
    hmac_key.copy_from_slice(&output[32..]);
    output.zeroize();

    Ok((enc_key, hmac_key))
}

/// Encrypts a plaintext value using AES-256-GCM with the alias as AAD.
///
/// Returns the SOPS-inspired encoding:
/// `ENC[AES256_GCM,data:<b64>,iv:<b64>,tag:<b64>,type:str]`
pub fn encrypt_value(
    key: &[u8; ENC_KEY_SIZE],
    plaintext: &str,
    alias: &str,
) -> Result<String, VaultCryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultCryptoError::EncryptionFailed)?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = format!("secrets:{alias}");
    let payload = Payload {
        msg: plaintext.as_bytes(),
        aad: aad.as_bytes(),
    };

    let ciphertext_with_tag = cipher
        .encrypt(nonce, payload)
        .map_err(|_| VaultCryptoError::EncryptionFailed)?;

    let ct_len = ciphertext_with_tag.len() - TAG_SIZE;
    let data_b64 = B64.encode(&ciphertext_with_tag[..ct_len]);
    let iv_b64 = B64.encode(nonce_bytes);
    let tag_b64 = B64.encode(&ciphertext_with_tag[ct_len..]);

    Ok(format!(
        "ENC[AES256_GCM,data:{data_b64},iv:{iv_b64},tag:{tag_b64},type:str]"
    ))
}

/// Decrypts a value previously encrypted by [`encrypt_value`].
pub fn decrypt_value(
    key: &[u8; ENC_KEY_SIZE],
    ciphertext: &str,
    alias: &str,
) -> Result<String, VaultCryptoError> {
    let (data_b64, iv_b64, tag_b64) = parse_enc_format(ciphertext)?;

    let data = B64
        .decode(data_b64)
        .map_err(|e| VaultCryptoError::Base64Error(e.to_string()))?;
    let iv = B64
        .decode(iv_b64)
        .map_err(|e| VaultCryptoError::Base64Error(e.to_string()))?;
    let tag = B64
        .decode(tag_b64)
        .map_err(|e| VaultCryptoError::Base64Error(e.to_string()))?;

    if iv.len() != NONCE_SIZE {
        return Err(VaultCryptoError::InvalidEncFormat(format!(
            "IV must be {NONCE_SIZE} bytes, got {}",
            iv.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultCryptoError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(&iv);

    let mut ciphertext_with_tag = Vec::with_capacity(data.len() + tag.len());
    ciphertext_with_tag.extend_from_slice(&data);
    ciphertext_with_tag.extend_from_slice(&tag);

    let aad = format!("secrets:{alias}");
    let payload = Payload {
        msg: &ciphertext_with_tag,
        aad: aad.as_bytes(),
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| VaultCryptoError::DecryptionFailed)?;

    String::from_utf8(plaintext).map_err(|_| VaultCryptoError::DecryptionFailed)
}

/// Generates a cryptographically random salt of [`SALT_SIZE`] bytes.
pub fn gen_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Computes HMAC-SHA256 over `data` using `hmac_key`.
pub fn compute_hmac(
    hmac_key: &[u8; HMAC_KEY_SIZE],
    data: &[u8],
) -> Result<Vec<u8>, VaultCryptoError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
        .map_err(|_| VaultCryptoError::KdfFailed("invalid HMAC key length".into()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verifies HMAC-SHA256 in constant time.
pub fn verify_hmac(
    hmac_key: &[u8; HMAC_KEY_SIZE],
    data: &[u8],
    expected: &[u8],
) -> Result<bool, VaultCryptoError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
        .map_err(|_| VaultCryptoError::KdfFailed("invalid HMAC key length".into()))?;
    mac.update(data);
    Ok(mac.verify_slice(expected).is_ok())
}

fn parse_enc_format(s: &str) -> Result<(&str, &str, &str), VaultCryptoError> {
    let s = s.trim();
    let inner = s
        .strip_prefix("ENC[AES256_GCM,")
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| {
            VaultCryptoError::InvalidEncFormat(
                "must start with ENC[AES256_GCM, and end with ]".into(),
            )
        })?;

    let mut data = None;
    let mut iv = None;
    let mut tag = None;

    for part in inner.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("data:") {
            data = Some(v);
        } else if let Some(v) = part.strip_prefix("iv:") {
            iv = Some(v);
        } else if let Some(v) = part.strip_prefix("tag:") {
            tag = Some(v);
        }
    }

    match (data, iv, tag) {
        (Some(d), Some(i), Some(t)) => Ok((d, i, t)),
        _ => Err(VaultCryptoError::InvalidEncFormat(
            "missing data, iv, or tag field".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASSWORD: &str = "test-vault-password-2026";
    const TEST_ALIAS: &str = "test-secret";

    fn test_salt() -> Vec<u8> {
        vec![42u8; SALT_SIZE]
    }

    fn fast_derive() -> ([u8; ENC_KEY_SIZE], [u8; HMAC_KEY_SIZE]) {
        derive_key(TEST_PASSWORD, &test_salt(), 1024, 1, 1).unwrap()
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (enc_key, _) = fast_derive();
        let plaintext = "postgres://user:pass@db:5432/myapp";
        let encrypted = encrypt_value(&enc_key, plaintext, TEST_ALIAS).unwrap();

        assert!(encrypted.starts_with("ENC[AES256_GCM,"));
        assert!(encrypted.ends_with(",type:str]"));

        let decrypted = decrypt_value(&enc_key, &encrypted, TEST_ALIAS).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_password_fails() {
        let (enc_key, _) = fast_derive();
        let encrypted = encrypt_value(&enc_key, "secret", TEST_ALIAS).unwrap();

        let (wrong_key, _) = derive_key("wrong-password", &test_salt(), 1024, 1, 1).unwrap();
        let result = decrypt_value(&wrong_key, &encrypted, TEST_ALIAS);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_alias_fails_aad() {
        let (enc_key, _) = fast_derive();
        let encrypted = encrypt_value(&enc_key, "secret", TEST_ALIAS).unwrap();

        let result = decrypt_value(&enc_key, &encrypted, "different-alias");
        assert!(result.is_err());
    }

    #[test]
    fn hmac_roundtrip() {
        let (_, hmac_key) = fast_derive();
        let data = b"canonical vault data";
        let mac = compute_hmac(&hmac_key, data).unwrap();
        assert!(verify_hmac(&hmac_key, data, &mac).unwrap());
    }

    #[test]
    fn hmac_tamper_detected() {
        let (_, hmac_key) = fast_derive();
        let data = b"original data";
        let mac = compute_hmac(&hmac_key, data).unwrap();
        assert!(!verify_hmac(&hmac_key, b"tampered data", &mac).unwrap());
    }

    #[test]
    fn invalid_enc_format_rejected() {
        let (enc_key, _) = fast_derive();
        assert!(decrypt_value(&enc_key, "not-encrypted", TEST_ALIAS).is_err());
        assert!(decrypt_value(&enc_key, "ENC[AES256_GCM,data:abc]", TEST_ALIAS).is_err());
    }

    #[test]
    fn salt_generation_uniqueness() {
        let s1 = gen_salt();
        let s2 = gen_salt();
        assert_eq!(s1.len(), SALT_SIZE);
        assert_ne!(s1, s2);
    }

    #[test]
    fn derive_key_produces_different_keys_for_different_passwords() {
        let (ek1, hk1) = derive_key("password1", &test_salt(), 1024, 1, 1).unwrap();
        let (ek2, hk2) = derive_key("password2", &test_salt(), 1024, 1, 1).unwrap();
        assert_ne!(ek1, ek2);
        assert_ne!(hk1, hk2);
    }

    #[test]
    fn derive_key_produces_different_keys_for_different_salts() {
        let salt1 = vec![1u8; SALT_SIZE];
        let salt2 = vec![2u8; SALT_SIZE];
        let (ek1, _) = derive_key(TEST_PASSWORD, &salt1, 1024, 1, 1).unwrap();
        let (ek2, _) = derive_key(TEST_PASSWORD, &salt2, 1024, 1, 1).unwrap();
        assert_ne!(ek1, ek2);
    }

    #[test]
    fn encrypt_empty_string_roundtrips() {
        let (enc_key, _) = fast_derive();
        let encrypted = encrypt_value(&enc_key, "", TEST_ALIAS).unwrap();

        assert!(encrypted.starts_with("ENC[AES256_GCM,"));
        assert!(encrypted.ends_with(",type:str]"));

        let decrypted = decrypt_value(&enc_key, &encrypted, TEST_ALIAS).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn decrypt_garbage_input_errors() {
        let (enc_key, _) = fast_derive();
        let result = decrypt_value(&enc_key, "totally-not-encrypted-garbage", TEST_ALIAS);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), VaultCryptoError::InvalidEncFormat(_)),
            "expected InvalidEncFormat for garbage input"
        );
    }

    #[test]
    fn derive_key_rejects_zero_time_cost() {
        let result = derive_key(TEST_PASSWORD, &test_salt(), 1024, 0, 1);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), VaultCryptoError::KdfFailed(_)),
            "expected KdfFailed for time_cost=0"
        );
    }
}
