use criterion::{black_box, criterion_group, criterion_main, Criterion};
use enva_core::crypto::{generate_salt, SecretsCrypto};
use enva_core::vault_crypto;
use secrecy::SecretString;

fn bench_master_key() -> SecretString {
    SecretString::from("a]32-byte-bench-master-key-value!".to_owned())
}

fn bench_hkdf_encrypt_decrypt(c: &mut Criterion) {
    let crypto = SecretsCrypto::new(bench_master_key()).unwrap();
    let plaintext = b"postgres://user:password@host:5432/db";

    c.bench_function("hkdf_encrypt", |b| {
        b.iter(|| crypto.encrypt(black_box(plaintext)).unwrap())
    });

    let (encrypted, salt) = crypto.encrypt(plaintext).unwrap();
    c.bench_function("hkdf_decrypt", |b| {
        b.iter(|| {
            crypto
                .decrypt(black_box(&encrypted), black_box(&salt))
                .unwrap()
        })
    });
}

fn bench_argon2_derive_key(c: &mut Criterion) {
    let salt = vec![42u8; vault_crypto::SALT_SIZE];

    c.bench_function("argon2id_derive_key_fast", |b| {
        b.iter(|| {
            vault_crypto::derive_key(
                black_box("bench-password-2026"),
                black_box(&salt),
                1024,
                1,
                1,
            )
            .unwrap()
        })
    });
}

fn bench_vault_encrypt_decrypt(c: &mut Criterion) {
    let salt = vec![42u8; vault_crypto::SALT_SIZE];
    let (enc_key, _) = vault_crypto::derive_key("bench-password", &salt, 1024, 1, 1).unwrap();
    let alias = "bench-secret";
    let plaintext = "super-secret-api-key-value-12345";

    c.bench_function("vault_encrypt_value", |b| {
        b.iter(|| {
            vault_crypto::encrypt_value(black_box(&enc_key), black_box(plaintext), black_box(alias))
                .unwrap()
        })
    });

    let encrypted = vault_crypto::encrypt_value(&enc_key, plaintext, alias).unwrap();
    c.bench_function("vault_decrypt_value", |b| {
        b.iter(|| {
            vault_crypto::decrypt_value(
                black_box(&enc_key),
                black_box(&encrypted),
                black_box(alias),
            )
            .unwrap()
        })
    });
}

fn bench_hmac(c: &mut Criterion) {
    let salt = vec![42u8; vault_crypto::SALT_SIZE];
    let (_, hmac_key) = vault_crypto::derive_key("bench-password", &salt, 1024, 1, 1).unwrap();
    let data = b"canonical-vault-json-payload-for-integrity-check-benchmarking";

    c.bench_function("hmac_sha256_compute", |b| {
        b.iter(|| vault_crypto::compute_hmac(black_box(&hmac_key), black_box(data)))
    });

    let mac = vault_crypto::compute_hmac(&hmac_key, data).unwrap();
    c.bench_function("hmac_sha256_verify", |b| {
        b.iter(|| {
            vault_crypto::verify_hmac(black_box(&hmac_key), black_box(data), black_box(&mac))
                .unwrap()
        })
    });
}

fn bench_salt_generation(c: &mut Criterion) {
    c.bench_function("generate_salt", |b| b.iter(|| generate_salt()));

    c.bench_function("vault_gen_salt", |b| b.iter(|| vault_crypto::gen_salt()));
}

criterion_group!(
    benches,
    bench_hkdf_encrypt_decrypt,
    bench_argon2_derive_key,
    bench_vault_encrypt_decrypt,
    bench_hmac,
    bench_salt_generation,
);
criterion_main!(benches);
