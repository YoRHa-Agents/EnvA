#![no_main]

use libfuzzer_sys::fuzz_target;
use secrecy::SecretString;

fuzz_target!(|data: &[u8]| {
    let mut material = String::from_utf8_lossy(data).into_owned();
    if material.len() < enva_core::crypto::KEY_SIZE {
        material.push_str(&"0".repeat(enva_core::crypto::KEY_SIZE - material.len()));
    }
    let Ok(crypto) = enva_core::crypto::SecretsCrypto::new(SecretString::from(material)) else {
        return;
    };
    let salt = enva_core::crypto::generate_salt();
    let _ = crypto.decrypt(data, &salt);
});
