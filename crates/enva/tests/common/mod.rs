use assert_cmd::Command;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use enva_core::vault_crypto;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub fn enva_cmd() -> Command {
    Command::cargo_bin("enva").unwrap()
}

pub fn create_test_vault(dir: &Path, password: &str) -> PathBuf {
    let vault_path = dir.join("test.vault.json");
    enva_cmd()
        .args(["vault", "init", "--vault", vault_path.to_str().unwrap()])
        .arg("--password-stdin")
        .write_stdin(format!("{password}\n"))
        .assert()
        .success();
    vault_path
}

pub fn vault_set(vps: &str, pw: &str, alias: &str, key: &str, value: &str) {
    enva_cmd()
        .args(["vault", "set", alias, "-k", key, "-V", value])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin(format!("{pw}\n"))
        .assert()
        .success();
}

pub fn vault_assign(vps: &str, pw: &str, alias: &str, app: &str) {
    enva_cmd()
        .args(["vault", "assign", alias, "--app", app])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin(format!("{pw}\n"))
        .assert()
        .success();
}

pub fn vault_assign_with_override(vps: &str, pw: &str, alias: &str, app: &str, override_key: &str) {
    enva_cmd()
        .args(["vault", "assign", alias, "--app", app, "--as", override_key])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin(format!("{pw}\n"))
        .assert()
        .success();
}

fn canonical_data(raw: &serde_json::Value) -> Vec<u8> {
    let mut parts = Vec::new();
    let meta = &raw["_meta"];
    parts.push(format!(
        "_meta:format_version={}",
        meta["format_version"].as_str().unwrap_or_default()
    ));
    parts.push(format!(
        "_meta:kdf.algorithm={}",
        meta["kdf"]["algorithm"].as_str().unwrap_or_default()
    ));
    parts.push(format!(
        "_meta:kdf.memory_cost={}",
        meta["kdf"]["memory_cost"].as_u64().unwrap_or_default()
    ));
    parts.push(format!(
        "_meta:kdf.time_cost={}",
        meta["kdf"]["time_cost"].as_u64().unwrap_or_default()
    ));
    parts.push(format!(
        "_meta:kdf.parallelism={}",
        meta["kdf"]["parallelism"].as_u64().unwrap_or_default()
    ));

    if let Some(secrets) = raw["secrets"].as_object() {
        for (alias, secret) in secrets {
            if let Some(id) = secret.get("id").and_then(|value| value.as_str()) {
                if !id.is_empty() {
                    parts.push(format!("secrets:{alias}:id={id}"));
                }
            }
            parts.push(format!(
                "secrets:{alias}:key={}",
                secret["key"].as_str().unwrap_or_default()
            ));
            parts.push(format!(
                "secrets:{alias}:value={}",
                secret["value"].as_str().unwrap_or_default()
            ));
            parts.push(format!(
                "secrets:{alias}:description={}",
                secret["description"].as_str().unwrap_or_default()
            ));
            let mut tags: Vec<String> = secret["tags"]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            tags.sort();
            parts.push(format!("secrets:{alias}:tags={}", tags.join(",")));
        }
    }

    if let Some(apps) = raw["apps"].as_object() {
        for (app_name, app) in apps {
            if let Some(id) = app.get("id").and_then(|value| value.as_str()) {
                if !id.is_empty() {
                    parts.push(format!("apps:{app_name}:id={id}"));
                }
            }
            let mut secret_refs: Vec<String> = app["secrets"]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            secret_refs.sort();
            parts.push(format!("apps:{app_name}:secrets={}", secret_refs.join(",")));
            parts.push(format!(
                "apps:{app_name}:description={}",
                app["description"].as_str().unwrap_or_default()
            ));
            parts.push(format!(
                "apps:{app_name}:app_path={}",
                app["app_path"].as_str().unwrap_or_default()
            ));
            let overrides: BTreeMap<String, String> = app["overrides"]
                .as_object()
                .map(|map| {
                    map.iter()
                        .map(|(key, value)| {
                            (key.clone(), value.as_str().unwrap_or_default().to_string())
                        })
                        .collect()
                })
                .unwrap_or_default();
            let override_parts: Vec<String> = overrides
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect();
            parts.push(format!(
                "apps:{app_name}:overrides={}",
                override_parts.join(",")
            ));
        }
    }

    parts.sort();
    parts.join("\n").into_bytes()
}

fn rewrite_vault_with_hmac(vps: &str, pw: &str, raw: &serde_json::Value) {
    let salt = B64.decode(raw["_meta"]["salt"].as_str().unwrap()).unwrap();
    let memory_cost = raw["_meta"]["kdf"]["memory_cost"].as_u64().unwrap() as u32;
    let time_cost = raw["_meta"]["kdf"]["time_cost"].as_u64().unwrap() as u32;
    let parallelism = raw["_meta"]["kdf"]["parallelism"].as_u64().unwrap() as u32;
    let (enc_key, hmac_key) =
        vault_crypto::derive_key(pw, &salt, memory_cost, time_cost, parallelism).unwrap();
    let _enc_key = Zeroizing::new(enc_key);
    let hmac_key = Zeroizing::new(hmac_key);
    let canonical = canonical_data(raw);
    let hmac = vault_crypto::compute_hmac(&hmac_key, &canonical).unwrap();
    let mut updated = raw.clone();
    updated["_meta"]["hmac"] = serde_json::Value::String(B64.encode(hmac));
    std::fs::write(vps, serde_json::to_string_pretty(&updated).unwrap()).unwrap();
}

pub fn rename_secret_in_vault(vps: &str, pw: &str, old_alias: &str, new_alias: &str) {
    let mut raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(vps).unwrap()).unwrap();
    let salt = B64.decode(raw["_meta"]["salt"].as_str().unwrap()).unwrap();
    let memory_cost = raw["_meta"]["kdf"]["memory_cost"].as_u64().unwrap() as u32;
    let time_cost = raw["_meta"]["kdf"]["time_cost"].as_u64().unwrap() as u32;
    let parallelism = raw["_meta"]["kdf"]["parallelism"].as_u64().unwrap() as u32;
    let (enc_key, _) =
        vault_crypto::derive_key(pw, &salt, memory_cost, time_cost, parallelism).unwrap();
    let enc_key = Zeroizing::new(enc_key);
    let secrets = raw["secrets"].as_object_mut().unwrap();
    let mut secret = secrets.remove(old_alias).unwrap();
    let plaintext =
        vault_crypto::decrypt_value(&enc_key, secret["value"].as_str().unwrap(), old_alias)
            .unwrap();
    let reencrypted = vault_crypto::encrypt_value(&enc_key, &plaintext, new_alias).unwrap();
    secret["value"] = serde_json::Value::String(reencrypted);
    let secret_id = secret["id"].as_str().unwrap_or_default().to_string();
    secrets.insert(new_alias.to_string(), secret);

    if let Some(apps) = raw["apps"].as_object_mut() {
        for app in apps.values_mut() {
            if let Some(secret_refs) = app["secrets"].as_array_mut() {
                for secret_ref in secret_refs {
                    if secret_ref.as_str() == Some(old_alias) {
                        *secret_ref = serde_json::Value::String(if secret_id.is_empty() {
                            new_alias.to_string()
                        } else {
                            secret_id.clone()
                        });
                    }
                }
            }
            if let Some(overrides) = app["overrides"].as_object_mut() {
                if let Some(value) = overrides.remove(old_alias) {
                    let key = if secret_id.is_empty() {
                        new_alias.to_string()
                    } else {
                        secret_id.clone()
                    };
                    overrides.insert(key, value);
                }
            }
        }
    }

    rewrite_vault_with_hmac(vps, pw, &raw);
}

pub fn rename_app_in_vault(vps: &str, pw: &str, old_name: &str, new_name: &str) {
    let mut raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(vps).unwrap()).unwrap();
    let apps = raw["apps"].as_object_mut().unwrap();
    let app = apps.remove(old_name).unwrap();
    apps.insert(new_name.to_string(), app);
    rewrite_vault_with_hmac(vps, pw, &raw);
}
