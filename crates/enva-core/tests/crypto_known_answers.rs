//! Known-answer vectors for the vault's on-disk cryptography.
//!
//! These vectors were produced by enva-core 1.4.3 (RustCrypto `digest` 0.10
//! generation, `rand` 0.8). Every value here is reachable from a real vault
//! file, so a change in any of them means previously written vaults can no
//! longer be read. Dependency upgrades across the crypto stack must keep
//! these passing; if one fails, the upgrade is format-breaking and needs a
//! vault migration rather than a version bump.

use enva_core::crypto::SecretsCrypto;
use enva_core::vault_crypto;
use secrecy::SecretString;

const KAT_PASSWORD: &str = "kat-password-2026";
const KAT_ALIAS: &str = "kat-alias";
const KAT_MASTER_KEY: &str = "a]32-byte-test-master-key-value!";

const ARGON2_ENC_KEY: &str = "90018db7945dbe3e6b43d3de135b8d724b8263c573d336ac8c1663eec0b3af04";
const ARGON2_HMAC_KEY: &str = "bee9706f43f55c40ab6233636c9144f0effae731571e8ac2030899dcd77094ef";

const VAULT_CIPHERTEXT: &str = "ENC[AES256_GCM,data:939B6/PF2skUBAntbmXMUNrS1LfQcYAyY4o=,iv:8JkU6HmU7fhkCNPG,tag:iKJ20Tntu9zMy9IfOS5Wdw==,type:str]";
const VAULT_PLAINTEXT: &str = "postgres://u:p@db:5432/app";

const HMAC_DATA: &[u8] = b"canonical vault bytes";
const HMAC_EXPECTED: &str = "b866685495cb8a49bc777f32c1143a05a725c2ae5c188daf4cd9e55491e44944";

const HKDF_PAYLOAD: &str = "91454c996b3ead0ea609a11f691c2989a626838719f3fa8055606e7d59fcaf4de0854537f4f859f50c8da2bdb81b831fc481c816e6";
const HKDF_SALT: &str = "17c79769758ed57356003fe13de1b4035d7834bdd7cba8be2749e848572bae79";
const HKDF_PLAINTEXT: &[u8] = b"hkdf known answer payload";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn kat_salt() -> Vec<u8> {
    vec![42u8; vault_crypto::SALT_SIZE]
}

/// Argon2id must keep deriving the same encryption and HMAC keys, otherwise
/// no existing vault password unlocks its vault.
#[test]
fn argon2id_derivation_is_stable() {
    let (enc_key, hmac_key) =
        vault_crypto::derive_key(KAT_PASSWORD, &kat_salt(), 1024, 2, 1).unwrap();
    assert_eq!(hex(&enc_key), ARGON2_ENC_KEY);
    assert_eq!(hex(&hmac_key), ARGON2_HMAC_KEY);
}

/// A ciphertext written by an older release must still decrypt, including the
/// alias-bound AAD.
#[test]
fn vault_value_from_previous_release_decrypts() {
    let (enc_key, _) = vault_crypto::derive_key(KAT_PASSWORD, &kat_salt(), 1024, 2, 1).unwrap();
    let plaintext = vault_crypto::decrypt_value(&enc_key, VAULT_CIPHERTEXT, KAT_ALIAS).unwrap();
    assert_eq!(plaintext, VAULT_PLAINTEXT);
}

#[test]
fn vault_value_still_rejects_a_mismatched_alias() {
    let (enc_key, _) = vault_crypto::derive_key(KAT_PASSWORD, &kat_salt(), 1024, 2, 1).unwrap();
    assert!(vault_crypto::decrypt_value(&enc_key, VAULT_CIPHERTEXT, "other-alias").is_err());
}

/// File-level integrity tags stored in existing vaults must keep verifying.
#[test]
fn hmac_sha256_is_stable() {
    let (_, hmac_key) = vault_crypto::derive_key(KAT_PASSWORD, &kat_salt(), 1024, 2, 1).unwrap();
    let mac = vault_crypto::compute_hmac(&hmac_key, HMAC_DATA).unwrap();
    assert_eq!(hex(&mac), HMAC_EXPECTED);
    assert!(vault_crypto::verify_hmac(&hmac_key, HMAC_DATA, &unhex(HMAC_EXPECTED)).unwrap());
}

/// The HKDF-SHA256 engine used for key-material-derived secrets must keep
/// reading payloads written by earlier releases.
#[test]
fn hkdf_payload_from_previous_release_decrypts() {
    let crypto = SecretsCrypto::new(SecretString::from(KAT_MASTER_KEY.to_owned())).unwrap();
    let decrypted = crypto
        .decrypt(&unhex(HKDF_PAYLOAD), &unhex(HKDF_SALT))
        .unwrap();
    assert_eq!(decrypted, HKDF_PLAINTEXT);
}

#[test]
fn hkdf_payload_still_rejects_a_mismatched_salt() {
    let crypto = SecretsCrypto::new(SecretString::from(KAT_MASTER_KEY.to_owned())).unwrap();
    let wrong_salt = vec![7u8; vault_crypto::SALT_SIZE];
    assert!(crypto.decrypt(&unhex(HKDF_PAYLOAD), &wrong_salt).is_err());
}
