//! Alias-based encrypted vault store with JSON persistence.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use enva_core::vault_crypto;
use rand::RngCore;
use regex::Regex;
use serde::{Deserialize, Serialize};

const FORMAT_VERSION: &str = "2.1";
const SECRET_ID_PREFIX: &str = "sec_";
const APP_ID_PREFIX: &str = "app_";

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("vault corrupted: {0}")]
    Corrupted(String),
    #[error("alias not found: {0}")]
    AliasNotFound(String),
    #[error("alias '{0}' already exists")]
    AliasExists(String),
    #[error("app not found: {0}")]
    AppNotFound(String),
    #[error("app '{0}' already exists")]
    AppExists(String),
    #[error("invalid alias '{0}': must match ^[a-z0-9][a-z0-9_-]{{0,62}}$")]
    InvalidAlias(String),
    #[error("{0}")]
    Crypto(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: "argon2id".into(),
            memory_cost: 65536,
            time_cost: 3,
            parallelism: 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMeta {
    pub format_version: String,
    pub kdf: KdfParams,
    pub salt: String,
    pub hmac: String,
    pub created_at: String,
    pub updated_at: String,
    pub created_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    #[serde(default)]
    pub id: String,
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppEntry {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub app_path: String,
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(default)]
    pub overrides: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultFile {
    _meta: VaultMeta,
    #[serde(default)]
    secrets: BTreeMap<String, SecretEntry>,
    #[serde(default)]
    apps: BTreeMap<String, AppEntry>,
}

pub struct SecretInfo {
    pub id: String,
    pub alias: String,
    pub key: String,
    pub description: String,
    pub tags: Vec<String>,
    pub apps: Vec<String>,
    pub updated_at: String,
}

pub struct AppInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub app_path: String,
    pub secret_count: usize,
}

pub struct AppSecretBinding {
    pub secret_id: String,
    pub alias: String,
    pub key: String,
    pub injected_as: String,
}

pub struct VaultStore {
    path: String,
    data: VaultFile,
    enc_key: zeroize::Zeroizing<[u8; 32]>,
    hmac_key: zeroize::Zeroizing<[u8; 32]>,
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

fn generate_prefixed_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut encoded = String::with_capacity(prefix.len() + bytes.len() * 2);
    encoded.push_str(prefix);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn creator() -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    let host = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".into());
    format!("{user}@{host}")
}

fn validate_alias(alias: &str) -> Result<(), VaultError> {
    use std::sync::OnceLock;
    static ALIAS_RE: OnceLock<Regex> = OnceLock::new();
    let re = ALIAS_RE.get_or_init(|| Regex::new(r"^[a-z0-9][a-z0-9_-]{0,62}$").unwrap());
    if !re.is_match(alias) {
        return Err(VaultError::InvalidAlias(alias.into()));
    }
    Ok(())
}

fn validate_app_name(name: &str) -> Result<(), VaultError> {
    use std::sync::OnceLock;
    static APP_RE: OnceLock<Regex> = OnceLock::new();
    let re = APP_RE.get_or_init(|| Regex::new(r"^[a-z][a-z0-9_-]{0,63}$").unwrap());
    if !re.is_match(name) {
        return Err(VaultError::AppNotFound(format!(
            "invalid app name '{}': must match ^[a-z][a-z0-9_-]{{0,63}}$",
            name
        )));
    }
    Ok(())
}

impl VaultStore {
    fn next_unique_id(prefix: &str, used: &mut HashSet<String>) -> String {
        loop {
            let candidate = generate_prefixed_id(prefix);
            if used.insert(candidate.clone()) {
                return candidate;
            }
        }
    }

    fn next_secret_id(&self) -> String {
        let mut used: HashSet<String> = self
            .data
            .secrets
            .values()
            .filter_map(|entry| {
                if entry.id.is_empty() {
                    None
                } else {
                    Some(entry.id.clone())
                }
            })
            .collect();
        Self::next_unique_id(SECRET_ID_PREFIX, &mut used)
    }

    fn next_app_id(&self) -> String {
        let mut used: HashSet<String> = self
            .data
            .apps
            .values()
            .filter_map(|entry| {
                if entry.id.is_empty() {
                    None
                } else {
                    Some(entry.id.clone())
                }
            })
            .collect();
        Self::next_unique_id(APP_ID_PREFIX, &mut used)
    }

    fn find_secret_by_ref(&self, secret_ref: &str) -> Option<(&str, &SecretEntry)> {
        if let Some((alias, entry)) = self.data.secrets.get_key_value(secret_ref) {
            return Some((alias.as_str(), entry));
        }

        self.data
            .secrets
            .iter()
            .find(|(_, entry)| entry.id == secret_ref)
            .map(|(alias, entry)| (alias.as_str(), entry))
    }

    fn app_references_secret(app: &AppEntry, alias: &str, secret_id: &str) -> bool {
        app.secrets
            .iter()
            .any(|secret_ref| secret_ref == alias || secret_ref == secret_id)
    }

    fn app_override_for_secret<'a>(
        app: &'a AppEntry,
        alias: &str,
        secret_id: &str,
    ) -> Option<&'a String> {
        app.overrides
            .get(secret_id)
            .or_else(|| app.overrides.get(alias))
    }

    fn migrate_in_place(&mut self) -> Result<(), VaultError> {
        let mut used_secret_ids = HashSet::new();
        for entry in self.data.secrets.values_mut() {
            if entry.id.is_empty() {
                entry.id = Self::next_unique_id(SECRET_ID_PREFIX, &mut used_secret_ids);
            } else if !used_secret_ids.insert(entry.id.clone()) {
                return Err(VaultError::Corrupted(format!(
                    "duplicate secret id '{}'",
                    entry.id
                )));
            }
        }

        let alias_to_id: BTreeMap<String, String> = self
            .data
            .secrets
            .iter()
            .map(|(alias, entry)| (alias.clone(), entry.id.clone()))
            .collect();

        let mut used_app_ids = HashSet::new();
        for app in self.data.apps.values_mut() {
            if app.id.is_empty() {
                app.id = Self::next_unique_id(APP_ID_PREFIX, &mut used_app_ids);
            } else if !used_app_ids.insert(app.id.clone()) {
                return Err(VaultError::Corrupted(format!(
                    "duplicate app id '{}'",
                    app.id
                )));
            }

            let mut seen_refs = HashSet::new();
            let mut normalized_refs = Vec::with_capacity(app.secrets.len());
            for secret_ref in &app.secrets {
                let normalized = alias_to_id
                    .get(secret_ref)
                    .cloned()
                    .unwrap_or_else(|| secret_ref.clone());
                if seen_refs.insert(normalized.clone()) {
                    normalized_refs.push(normalized);
                }
            }
            app.secrets = normalized_refs;

            let mut normalized_overrides = BTreeMap::new();
            for (secret_ref, env_name) in &app.overrides {
                let normalized = alias_to_id
                    .get(secret_ref)
                    .cloned()
                    .unwrap_or_else(|| secret_ref.clone());
                if let Some(existing) = normalized_overrides.get(&normalized) {
                    if existing != env_name {
                        return Err(VaultError::Corrupted(format!(
                            "conflicting override values for secret reference '{}'",
                            normalized
                        )));
                    }
                    continue;
                }
                normalized_overrides.insert(normalized, env_name.clone());
            }
            app.overrides = normalized_overrides;
        }

        self.data._meta.format_version = FORMAT_VERSION.into();
        Ok(())
    }

    pub fn create(
        path: &str,
        password: &str,
        kdf_params: Option<KdfParams>,
    ) -> Result<Self, VaultError> {
        if password.is_empty() {
            return Err(VaultError::Auth("password must not be empty".into()));
        }
        let kdf = kdf_params.unwrap_or_default();
        let salt = vault_crypto::gen_salt();
        let (enc_key, hmac_key) = vault_crypto::derive_key(
            password,
            &salt,
            kdf.memory_cost,
            kdf.time_cost,
            kdf.parallelism,
        )
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

        let now = now_iso();
        let data = VaultFile {
            _meta: VaultMeta {
                format_version: FORMAT_VERSION.into(),
                kdf,
                salt: B64.encode(&salt),
                hmac: String::new(),
                created_at: now.clone(),
                updated_at: now,
                created_by: creator(),
            },
            secrets: BTreeMap::new(),
            apps: BTreeMap::new(),
        };

        let mut store = Self {
            path: path.into(),
            data,
            enc_key: zeroize::Zeroizing::new(enc_key),
            hmac_key: zeroize::Zeroizing::new(hmac_key),
        };
        store.save()?;
        Ok(store)
    }

    pub fn load(path: &str, password: &str) -> Result<Self, VaultError> {
        let raw = fs::read_to_string(path)?;
        let data: VaultFile = serde_json::from_str(&raw)
            .map_err(|e| VaultError::Corrupted(format!("invalid JSON: {e}")))?;

        if !data._meta.format_version.starts_with('2') {
            return Err(VaultError::Corrupted(format!(
                "unsupported format version: {}",
                data._meta.format_version
            )));
        }

        if data._meta.kdf.memory_cost < 8192 {
            return Err(VaultError::Corrupted(format!(
                "kdf.memory_cost {} is below minimum 8192",
                data._meta.kdf.memory_cost
            )));
        }

        let salt = B64
            .decode(&data._meta.salt)
            .map_err(|e| VaultError::Corrupted(format!("bad salt: {e}")))?;

        let (enc_key, hmac_key) = vault_crypto::derive_key(
            password,
            &salt,
            data._meta.kdf.memory_cost,
            data._meta.kdf.time_cost,
            data._meta.kdf.parallelism,
        )
        .map_err(|e| VaultError::Auth(e.to_string()))?;

        let mut store = Self {
            path: path.into(),
            data,
            enc_key: zeroize::Zeroizing::new(enc_key),
            hmac_key: zeroize::Zeroizing::new(hmac_key),
        };

        if store.data._meta.hmac.is_empty() {
            return Err(VaultError::Corrupted(
                "missing HMAC — vault integrity cannot be verified".into(),
            ));
        }
        let stored = B64
            .decode(&store.data._meta.hmac)
            .map_err(|e| VaultError::Corrupted(format!("bad hmac: {e}")))?;
        let canonical = store.canonical_data();
        if !vault_crypto::verify_hmac(&store.hmac_key, &canonical, &stored)
            .map_err(|e| VaultError::Crypto(e.to_string()))?
        {
            return Err(VaultError::Corrupted("HMAC verification failed".into()));
        }

        store.migrate_in_place()?;
        Ok(store)
    }

    pub fn save(&mut self) -> Result<(), VaultError> {
        self.migrate_in_place()?;
        let canonical = self.canonical_data();
        let mac = vault_crypto::compute_hmac(&self.hmac_key, &canonical)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        self.data._meta.hmac = B64.encode(&mac);
        self.data._meta.updated_at = now_iso();

        let content = serde_json::to_string_pretty(&self.data)?;
        let dir = Path::new(&self.path).parent().unwrap_or(Path::new("."));
        fs::create_dir_all(dir)?;
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        tmp.write_all(content.as_bytes())?;
        tmp.persist(&self.path)
            .map_err(|e| VaultError::Io(e.error))?;
        Ok(())
    }

    pub fn set(
        &mut self,
        alias: &str,
        key: &str,
        value: &str,
        description: &str,
        tags: &[String],
    ) -> Result<(), VaultError> {
        validate_alias(alias)?;
        let encrypted = vault_crypto::encrypt_value(&self.enc_key, value, alias)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        let now = now_iso();
        let existing = self.data.secrets.get(alias).cloned();
        let created = existing
            .as_ref()
            .map(|s| s.created_at.clone())
            .unwrap_or_else(|| now.clone());
        let id = existing
            .as_ref()
            .filter(|entry| !entry.id.is_empty())
            .map(|entry| entry.id.clone())
            .unwrap_or_else(|| self.next_secret_id());
        self.data.secrets.insert(
            alias.into(),
            SecretEntry {
                id,
                key: key.into(),
                value: encrypted,
                description: description.into(),
                tags: tags.to_vec(),
                created_at: created,
                updated_at: now,
            },
        );
        Ok(())
    }

    pub fn edit(
        &mut self,
        alias: &str,
        new_key: Option<&str>,
        new_value: Option<&str>,
        new_description: Option<&str>,
        new_tags: Option<&[String]>,
    ) -> Result<(), VaultError> {
        let entry = self
            .data
            .secrets
            .get(alias)
            .ok_or_else(|| VaultError::AliasNotFound(alias.into()))?
            .clone();

        let key = new_key.unwrap_or(&entry.key);
        let description = new_description.unwrap_or(&entry.description);
        let tags = new_tags.unwrap_or(&entry.tags);
        let encrypted = if let Some(v) = new_value {
            vault_crypto::encrypt_value(&self.enc_key, v, alias)
                .map_err(|e| VaultError::Crypto(e.to_string()))?
        } else {
            entry.value.clone()
        };

        self.data.secrets.insert(
            alias.into(),
            SecretEntry {
                id: entry.id,
                key: key.into(),
                value: encrypted,
                description: description.into(),
                tags: tags.to_vec(),
                created_at: entry.created_at,
                updated_at: now_iso(),
            },
        );
        Ok(())
    }

    pub fn get(&self, alias: &str) -> Result<String, VaultError> {
        let entry = self
            .data
            .secrets
            .get(alias)
            .ok_or_else(|| VaultError::AliasNotFound(alias.into()))?;
        vault_crypto::decrypt_value(&self.enc_key, &entry.value, alias)
            .map_err(|e| VaultError::Crypto(e.to_string()))
    }

    pub fn delete(&mut self, alias: &str) -> Result<(), VaultError> {
        let removed = self
            .data
            .secrets
            .remove(alias)
            .ok_or_else(|| VaultError::AliasNotFound(alias.into()))?;
        for app in self.data.apps.values_mut() {
            app.secrets
                .retain(|secret_ref| secret_ref != alias && secret_ref != &removed.id);
            app.overrides.remove(alias);
            if !removed.id.is_empty() {
                app.overrides.remove(&removed.id);
            }
        }
        Ok(())
    }

    pub fn list(&self, app: Option<&str>) -> Result<Vec<SecretInfo>, VaultError> {
        let filter_aliases: Option<HashSet<String>> = match app {
            Some(name) => {
                let ad = self
                    .data
                    .apps
                    .get(name)
                    .ok_or_else(|| VaultError::AppNotFound(name.into()))?;
                Some(
                    ad.secrets
                        .iter()
                        .filter_map(|secret_ref| {
                            self.find_secret_by_ref(secret_ref)
                                .map(|(alias, _)| alias.to_owned())
                        })
                        .collect(),
                )
            }
            None => None,
        };
        let mut result = Vec::new();
        for (alias, entry) in &self.data.secrets {
            if let Some(ref filter) = filter_aliases {
                if !filter.contains(alias) {
                    continue;
                }
            }
            let apps_using: Vec<String> = self
                .data
                .apps
                .iter()
                .filter(|(_, ad)| Self::app_references_secret(ad, alias, &entry.id))
                .map(|(name, _)| name.clone())
                .collect();
            result.push(SecretInfo {
                id: entry.id.clone(),
                alias: alias.clone(),
                key: entry.key.clone(),
                description: entry.description.clone(),
                tags: entry.tags.clone(),
                apps: apps_using,
                updated_at: entry.updated_at.clone(),
            });
        }
        Ok(result)
    }

    pub fn assign(
        &mut self,
        app: &str,
        alias: &str,
        override_key: Option<&str>,
    ) -> Result<(), VaultError> {
        validate_app_name(app)?;
        let secret_id = self
            .data
            .secrets
            .get(alias)
            .map(|entry| entry.id.clone())
            .ok_or_else(|| VaultError::AliasNotFound(alias.into()))?;
        if !self.data.apps.contains_key(app) {
            self.create_app(app, "", "")?;
        }
        let ad = self
            .data
            .apps
            .get_mut(app)
            .ok_or_else(|| VaultError::AppNotFound(app.into()))?;
        let mut normalized_refs = Vec::with_capacity(ad.secrets.len() + 1);
        let mut seen = false;
        for secret_ref in &ad.secrets {
            if secret_ref == alias || secret_ref == &secret_id {
                if !seen {
                    normalized_refs.push(secret_id.clone());
                    seen = true;
                }
            } else {
                normalized_refs.push(secret_ref.clone());
            }
        }
        if !seen {
            normalized_refs.push(secret_id.clone());
        }
        ad.secrets = normalized_refs;
        ad.overrides.remove(alias);
        ad.overrides.remove(&secret_id);
        if let Some(k) = override_key {
            ad.overrides.insert(secret_id, k.into());
        }
        Ok(())
    }

    pub fn unassign(&mut self, app: &str, alias: &str) -> Result<(), VaultError> {
        let secret_id = self.data.secrets.get(alias).map(|entry| entry.id.clone());
        let ad = self
            .data
            .apps
            .get_mut(app)
            .ok_or_else(|| VaultError::AppNotFound(app.into()))?;
        ad.secrets.retain(|secret_ref| {
            if secret_ref == alias {
                return false;
            }
            if let Some(secret_id) = &secret_id {
                return secret_ref != secret_id;
            }
            true
        });
        ad.overrides.remove(alias);
        if let Some(secret_id) = secret_id {
            ad.overrides.remove(&secret_id);
        }
        Ok(())
    }

    pub fn get_app_secret_bindings(&self, app: &str) -> Result<Vec<AppSecretBinding>, VaultError> {
        let ad = self
            .data
            .apps
            .get(app)
            .ok_or_else(|| VaultError::AppNotFound(app.into()))?;
        let mut bindings = Vec::new();
        for secret_ref in &ad.secrets {
            if let Some((alias, entry)) = self.find_secret_by_ref(secret_ref) {
                let injected_as = Self::app_override_for_secret(ad, alias, &entry.id)
                    .cloned()
                    .unwrap_or_else(|| entry.key.clone());
                bindings.push(AppSecretBinding {
                    secret_id: entry.id.clone(),
                    alias: alias.to_owned(),
                    key: entry.key.clone(),
                    injected_as,
                });
            }
        }
        Ok(bindings)
    }

    pub fn get_app_secrets(&self, app: &str) -> Result<BTreeMap<String, String>, VaultError> {
        let ad = self
            .data
            .apps
            .get(app)
            .ok_or_else(|| VaultError::AppNotFound(app.into()))?;
        let mut result = BTreeMap::new();
        for secret_ref in &ad.secrets {
            if let Some((alias, entry)) = self.find_secret_by_ref(secret_ref) {
                let env_name =
                    Self::app_override_for_secret(ad, alias, &entry.id).unwrap_or(&entry.key);
                let plaintext = vault_crypto::decrypt_value(&self.enc_key, &entry.value, alias)
                    .map_err(|e| VaultError::Crypto(e.to_string()))?;
                result.insert(env_name.clone(), plaintext);
            }
        }
        Ok(result)
    }

    pub fn create_app(
        &mut self,
        app: &str,
        description: &str,
        app_path: &str,
    ) -> Result<(), VaultError> {
        validate_app_name(app)?;
        if self.data.apps.contains_key(app) {
            return Err(VaultError::AppExists(app.into()));
        }
        self.data.apps.insert(
            app.into(),
            AppEntry {
                id: self.next_app_id(),
                description: description.into(),
                app_path: app_path.into(),
                secrets: Vec::new(),
                overrides: BTreeMap::new(),
            },
        );
        Ok(())
    }

    pub fn rename_secret(&mut self, alias: &str, new_alias: &str) -> Result<(), VaultError> {
        validate_alias(new_alias)?;
        if alias == new_alias {
            return Ok(());
        }
        if self.data.secrets.contains_key(new_alias) {
            return Err(VaultError::AliasExists(new_alias.into()));
        }

        let mut entry = self
            .data
            .secrets
            .remove(alias)
            .ok_or_else(|| VaultError::AliasNotFound(alias.into()))?;
        let plaintext = vault_crypto::decrypt_value(&self.enc_key, &entry.value, alias)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        entry.value = vault_crypto::encrypt_value(&self.enc_key, &plaintext, new_alias)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        entry.updated_at = now_iso();
        let secret_id = entry.id.clone();
        self.data.secrets.insert(new_alias.into(), entry);

        for app in self.data.apps.values_mut() {
            let mut normalized_refs = Vec::with_capacity(app.secrets.len());
            let mut seen = HashSet::new();
            for secret_ref in &app.secrets {
                let normalized = if secret_ref == alias {
                    secret_id.clone()
                } else {
                    secret_ref.clone()
                };
                if seen.insert(normalized.clone()) {
                    normalized_refs.push(normalized);
                }
            }
            app.secrets = normalized_refs;

            if let Some(override_key) = app.overrides.remove(alias) {
                app.overrides
                    .entry(secret_id.clone())
                    .or_insert(override_key);
            }
        }

        Ok(())
    }

    pub fn rename_app(&mut self, app: &str, new_name: &str) -> Result<(), VaultError> {
        validate_app_name(new_name)?;
        if app == new_name {
            return Ok(());
        }
        if self.data.apps.contains_key(new_name) {
            return Err(VaultError::AppExists(new_name.into()));
        }
        let entry = self
            .data
            .apps
            .remove(app)
            .ok_or_else(|| VaultError::AppNotFound(app.into()))?;
        self.data.apps.insert(new_name.into(), entry);
        Ok(())
    }

    #[allow(dead_code)] // Exercised in unit tests; reserved for future CLI
    pub fn delete_app(&mut self, app: &str) -> Result<(), VaultError> {
        if self.data.apps.remove(app).is_none() {
            return Err(VaultError::AppNotFound(app.into()));
        }
        Ok(())
    }

    pub fn get_app_entry_mut(&mut self, app: &str) -> Result<&mut AppEntry, VaultError> {
        self.data
            .apps
            .get_mut(app)
            .ok_or_else(|| VaultError::AppNotFound(app.into()))
    }

    pub fn get_app_path(&self, app: &str) -> Result<String, VaultError> {
        let ad = self
            .data
            .apps
            .get(app)
            .ok_or_else(|| VaultError::AppNotFound(app.into()))?;
        Ok(ad.app_path.clone())
    }

    pub fn list_apps(&self) -> Vec<AppInfo> {
        self.data
            .apps
            .iter()
            .map(|(name, ad)| AppInfo {
                id: ad.id.clone(),
                name: name.clone(),
                description: ad.description.clone(),
                app_path: ad.app_path.clone(),
                secret_count: ad.secrets.len(),
            })
            .collect()
    }

    fn canonical_data(&self) -> Vec<u8> {
        let mut parts = Vec::new();
        parts.push(format!(
            "_meta:format_version={}",
            self.data._meta.format_version
        ));
        parts.push(format!(
            "_meta:kdf.algorithm={}",
            self.data._meta.kdf.algorithm
        ));
        parts.push(format!(
            "_meta:kdf.memory_cost={}",
            self.data._meta.kdf.memory_cost
        ));
        parts.push(format!(
            "_meta:kdf.time_cost={}",
            self.data._meta.kdf.time_cost
        ));
        parts.push(format!(
            "_meta:kdf.parallelism={}",
            self.data._meta.kdf.parallelism
        ));
        for (alias, s) in &self.data.secrets {
            if !s.id.is_empty() {
                parts.push(format!("secrets:{alias}:id={}", s.id));
            }
            parts.push(format!("secrets:{alias}:key={}", s.key));
            parts.push(format!("secrets:{alias}:value={}", s.value));
            parts.push(format!("secrets:{alias}:description={}", s.description));
            let mut sorted_tags = s.tags.clone();
            sorted_tags.sort();
            parts.push(format!("secrets:{alias}:tags={}", sorted_tags.join(",")));
        }
        for (app_name, ad) in &self.data.apps {
            if !ad.id.is_empty() {
                parts.push(format!("apps:{app_name}:id={}", ad.id));
            }
            let mut sorted_secret_refs = ad.secrets.clone();
            sorted_secret_refs.sort();
            parts.push(format!(
                "apps:{app_name}:secrets={}",
                sorted_secret_refs.join(",")
            ));
            parts.push(format!("apps:{app_name}:description={}", ad.description));
            parts.push(format!("apps:{app_name}:app_path={}", ad.app_path));
            let mut sorted_ovr: Vec<_> = ad.overrides.iter().collect();
            sorted_ovr.sort_by_key(|(k, _)| (*k).clone());
            let ovr_str: Vec<String> = sorted_ovr.iter().map(|(k, v)| format!("{k}={v}")).collect();
            parts.push(format!("apps:{app_name}:overrides={}", ovr_str.join(",")));
        }
        parts.sort();
        parts.join("\n").into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn fast_kdf() -> KdfParams {
        KdfParams {
            algorithm: "argon2id".into(),
            memory_cost: 8192,
            time_cost: 1,
            parallelism: 1,
        }
    }

    fn rewrite_vault_with_valid_hmac(path: &str, password: &str, raw: serde_json::Value) {
        let mut data: VaultFile = serde_json::from_value(raw).unwrap();
        let salt = B64.decode(&data._meta.salt).unwrap();
        let (enc_key, hmac_key) = vault_crypto::derive_key(
            password,
            &salt,
            data._meta.kdf.memory_cost,
            data._meta.kdf.time_cost,
            data._meta.kdf.parallelism,
        )
        .unwrap();
        let store = VaultStore {
            path: path.into(),
            data: data.clone(),
            enc_key: Zeroizing::new(enc_key),
            hmac_key: Zeroizing::new(hmac_key),
        };
        let mac = vault_crypto::compute_hmac(&store.hmac_key, &store.canonical_data()).unwrap();
        data._meta.hmac = B64.encode(&mac);
        std::fs::write(path, serde_json::to_string_pretty(&data).unwrap()).unwrap();
    }

    #[test]
    fn create_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.vault.json");
        let ps = path.to_str().unwrap();
        VaultStore::create(ps, "pw", Some(fast_kdf())).unwrap();
        let store = VaultStore::load(ps, "pw").unwrap();
        assert!(store.list(None).unwrap().is_empty());
    }

    #[test]
    fn load_migrates_legacy_alias_references_and_persists_ids() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir
            .path()
            .join("legacy.vault.json")
            .to_str()
            .unwrap()
            .to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store
            .set("db", "DATABASE_URL", "postgres://x", "", &[])
            .unwrap();
        store.create_app("backend", "backend", "./run.sh").unwrap();
        store.assign("backend", "db", Some("BACKEND_DB")).unwrap();
        store.save().unwrap();
        drop(store);

        let mut raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&ps).unwrap()).unwrap();
        let secret_id = raw["secrets"]["db"]["id"].as_str().unwrap().to_string();
        let app_id = raw["apps"]["backend"]["id"].as_str().unwrap().to_string();
        raw["_meta"]["format_version"] = serde_json::Value::String("2.0".into());
        raw["secrets"]["db"].as_object_mut().unwrap().remove("id");
        raw["apps"]["backend"].as_object_mut().unwrap().remove("id");
        raw["apps"]["backend"]["secrets"] = serde_json::json!(["db"]);
        raw["apps"]["backend"]["overrides"] = serde_json::json!({"db": "BACKEND_DB"});
        rewrite_vault_with_valid_hmac(&ps, "pw", raw);

        let mut loaded = VaultStore::load(&ps, "pw").unwrap();
        let secrets = loaded.list(None).unwrap();
        let apps = loaded.list_apps();
        let bindings = loaded.get_app_secret_bindings("backend").unwrap();

        assert_eq!(secrets.len(), 1);
        assert_eq!(apps.len(), 1);
        assert_eq!(bindings.len(), 1);
        assert!(!secrets[0].id.is_empty());
        assert!(!apps[0].id.is_empty());
        assert_eq!(bindings[0].alias, "db");
        assert_eq!(bindings[0].injected_as, "BACKEND_DB");
        assert_ne!(secrets[0].id, secret_id);
        assert_ne!(apps[0].id, app_id);

        loaded.save().unwrap();
        let upgraded: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&ps).unwrap()).unwrap();
        let upgraded_secret_id = upgraded["secrets"]["db"]["id"].as_str().unwrap();
        let upgraded_app_id = upgraded["apps"]["backend"]["id"].as_str().unwrap();
        assert_eq!(
            upgraded["apps"]["backend"]["secrets"][0],
            upgraded_secret_id
        );
        assert_eq!(
            upgraded["apps"]["backend"]["overrides"][upgraded_secret_id],
            "BACKEND_DB"
        );
        assert!(upgraded_secret_id.starts_with(SECRET_ID_PREFIX));
        assert!(upgraded_app_id.starts_with(APP_ID_PREFIX));
    }

    #[test]
    fn set_get_delete() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store
            .set("my-key", "MY_VAR", "secret-value", "", &[])
            .unwrap();
        store.save().unwrap();
        let store = VaultStore::load(&ps, "pw").unwrap();
        assert_eq!(store.get("my-key").unwrap(), "secret-value");
    }

    #[test]
    fn wrong_password_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.set("k", "K", "v", "", &[]).unwrap();
        store.save().unwrap();
        assert!(VaultStore::load(&ps, "wrong").is_err());
    }

    #[test]
    fn app_assign_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.create_app("be", "backend", "").unwrap();
        store
            .set("db", "DATABASE_URL", "postgres://x", "", &[])
            .unwrap();
        store.assign("be", "db", None).unwrap();
        let resolved = store.get_app_secrets("be").unwrap();
        assert_eq!(resolved["DATABASE_URL"], "postgres://x");
    }

    #[test]
    fn override_key() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.create_app("fe", "frontend", "").unwrap();
        store
            .set("sentry", "SENTRY_DSN", "https://s", "", &[])
            .unwrap();
        store
            .assign("fe", "sentry", Some("NEXT_PUBLIC_SENTRY"))
            .unwrap();
        let resolved = store.get_app_secrets("fe").unwrap();
        assert!(resolved.contains_key("NEXT_PUBLIC_SENTRY"));
        assert!(!resolved.contains_key("SENTRY_DSN"));
    }

    #[test]
    fn delete_app_removes_app() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.create_app("tmp", "", "").unwrap();
        store.delete_app("tmp").unwrap();
        assert!(store.list_apps().is_empty());
        assert!(store.delete_app("missing").is_err());
    }

    #[test]
    fn list_with_app_filter() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.set("s1", "K1", "v1", "", &[]).unwrap();
        store.set("s2", "K2", "v2", "", &[]).unwrap();
        store.create_app("myapp", "", "").unwrap();
        store.assign("myapp", "s1", None).unwrap();
        let filtered = store.list(Some("myapp")).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].alias, "s1");
    }

    #[test]
    fn list_with_nonexistent_app_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        assert!(store.list(Some("ghost")).is_err());
    }

    #[test]
    fn unassign_removes_secret_from_app() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.set("s1", "K1", "v1", "", &[]).unwrap();
        store.create_app("a", "", "").unwrap();
        store.assign("a", "s1", None).unwrap();
        assert_eq!(store.get_app_secrets("a").unwrap().len(), 1);
        store.unassign("a", "s1").unwrap();
        assert!(store.get_app_secrets("a").unwrap().is_empty());
    }

    #[test]
    fn unassign_from_nonexistent_app_errors() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        assert!(store.unassign("no-app", "s1").is_err());
    }

    #[test]
    fn set_invalid_alias_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        assert!(store.set("UPPER_CASE", "K", "v", "", &[]).is_err());
        assert!(store.set("has space", "K", "v", "", &[]).is_err());
        assert!(store.set("", "K", "v", "", &[]).is_err());
    }

    #[test]
    fn save_produces_valid_hmac() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.set("k1", "K1", "v1", "", &[]).unwrap();
        store.save().unwrap();
        let content = std::fs::read_to_string(&ps).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        let hmac = parsed["_meta"]["hmac"].as_str().unwrap();
        assert!(!hmac.is_empty());
    }

    #[test]
    fn get_nonexistent_alias_errors() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        assert!(store.get("no-such-alias").is_err());
    }

    #[test]
    fn assign_auto_creates_app() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.set("s1", "K1", "v1", "", &[]).unwrap();
        store.assign("new-app", "s1", None).unwrap();
        let apps = store.list_apps();
        assert!(apps.iter().any(|a| a.name == "new-app"));
    }

    #[test]
    fn create_rejects_empty_password() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        assert!(VaultStore::create(&ps, "", Some(fast_kdf())).is_err());
    }

    #[test]
    fn invalid_app_name_uppercase_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.set("s1", "K1", "v1", "", &[]).unwrap();
        assert!(store.assign("UPPERCASE", "s1", None).is_err());
    }

    #[test]
    fn invalid_app_name_with_spaces_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        assert!(store.create_app("has space", "", "").is_err());
    }

    #[test]
    fn valid_app_name_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        assert!(store
            .create_app("my-valid-app", "desc", "/usr/bin/app")
            .is_ok());
        assert!(store.create_app("app123", "", "").is_ok());
    }

    #[test]
    fn load_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.vault.json");
        std::fs::write(&path, b"not json at all!!! {{{").unwrap();
        let result = VaultStore::load(path.to_str().unwrap(), "pw");
        assert!(result.is_err());
        let err_msg = result.err().expect("expected Err").to_string();
        assert!(err_msg.contains("invalid JSON"), "got: {err_msg}");
    }

    #[test]
    fn load_wrong_format_version() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        drop(store);
        let mut raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&ps).unwrap()).unwrap();
        raw["_meta"]["format_version"] = serde_json::Value::String("1.0".into());
        std::fs::write(&ps, serde_json::to_string_pretty(&raw).unwrap()).unwrap();
        let result = VaultStore::load(&ps, "pw");
        assert!(result.is_err());
        let err_msg = result.err().expect("expected Err").to_string();
        assert!(
            err_msg.contains("unsupported format version"),
            "got: {err_msg}"
        );
    }

    #[test]
    fn load_low_memory_cost() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        drop(store);
        let mut raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&ps).unwrap()).unwrap();
        raw["_meta"]["kdf"]["memory_cost"] = serde_json::json!(1024);
        std::fs::write(&ps, serde_json::to_string_pretty(&raw).unwrap()).unwrap();
        let result = VaultStore::load(&ps, "pw");
        assert!(result.is_err());
        let err_msg = result.err().expect("expected Err").to_string();
        assert!(err_msg.contains("below minimum"), "got: {err_msg}");
    }

    #[test]
    fn load_empty_hmac() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        drop(store);
        let mut raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&ps).unwrap()).unwrap();
        raw["_meta"]["hmac"] = serde_json::Value::String("".into());
        std::fs::write(&ps, serde_json::to_string_pretty(&raw).unwrap()).unwrap();
        let result = VaultStore::load(&ps, "pw");
        assert!(result.is_err());
        let err_msg = result.err().expect("expected Err").to_string();
        assert!(err_msg.contains("missing HMAC"), "got: {err_msg}");
    }

    #[test]
    fn load_tampered_data() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.set("s1", "ORIGINAL_KEY", "value", "", &[]).unwrap();
        store.save().unwrap();
        drop(store);
        let mut raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&ps).unwrap()).unwrap();
        raw["secrets"]["s1"]["key"] = serde_json::Value::String("TAMPERED_KEY".into());
        std::fs::write(&ps, serde_json::to_string_pretty(&raw).unwrap()).unwrap();
        let result = VaultStore::load(&ps, "pw");
        assert!(result.is_err());
        let err_msg = result.err().expect("expected Err").to_string();
        assert!(
            err_msg.contains("HMAC verification failed"),
            "got: {err_msg}"
        );
    }

    #[test]
    fn load_bad_salt_base64() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        drop(store);
        let mut raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&ps).unwrap()).unwrap();
        raw["_meta"]["salt"] = serde_json::Value::String("not-valid-base64!!!".into());
        std::fs::write(&ps, serde_json::to_string_pretty(&raw).unwrap()).unwrap();
        let result = VaultStore::load(&ps, "pw");
        assert!(result.is_err());
        let err_msg = result.err().expect("expected Err").to_string();
        assert!(err_msg.contains("bad salt"), "got: {err_msg}");
    }

    #[test]
    fn edit_updates_key_only() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store
            .set("db", "OLD_KEY", "secret", "original desc", &["tag1".into()])
            .unwrap();
        store.edit("db", Some("NEW_KEY"), None, None, None).unwrap();
        store.save().unwrap();
        let store = VaultStore::load(&ps, "pw").unwrap();
        let info = store.list(None).unwrap();
        assert_eq!(info[0].key, "NEW_KEY");
        assert_eq!(info[0].description, "original desc");
        assert_eq!(info[0].tags, vec!["tag1".to_string()]);
        assert_eq!(store.get("db").unwrap(), "secret");
    }

    #[test]
    fn edit_updates_value_only() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.set("db", "DB_URL", "old-val", "desc", &[]).unwrap();
        store.edit("db", None, Some("new-val"), None, None).unwrap();
        store.save().unwrap();
        let store = VaultStore::load(&ps, "pw").unwrap();
        assert_eq!(store.get("db").unwrap(), "new-val");
        let info = store.list(None).unwrap();
        assert_eq!(info[0].key, "DB_URL");
        assert_eq!(info[0].description, "desc");
    }

    #[test]
    fn edit_updates_description_and_tags() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.set("s1", "K", "v", "old desc", &[]).unwrap();
        store
            .edit(
                "s1",
                None,
                None,
                Some("new desc"),
                Some(&["prod".into(), "db".into()]),
            )
            .unwrap();
        store.save().unwrap();
        let store = VaultStore::load(&ps, "pw").unwrap();
        let info = store.list(None).unwrap();
        assert_eq!(info[0].description, "new desc");
        assert_eq!(info[0].tags, vec!["prod".to_string(), "db".to_string()]);
        assert_eq!(store.get("s1").unwrap(), "v");
    }

    #[test]
    fn edit_nonexistent_alias_errors() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        let result = store.edit("missing", Some("K"), None, None, None);
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(err_msg.contains("alias not found"), "got: {err_msg}");
    }

    #[test]
    fn edit_preserves_created_at() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.set("s1", "K", "v", "", &[]).unwrap();
        store.save().unwrap();
        let store_r = VaultStore::load(&ps, "pw").unwrap();
        let before = store_r.list(None).unwrap();
        let created_before = before[0].updated_at.clone();
        drop(store_r);

        std::thread::sleep(std::time::Duration::from_millis(10));

        let mut store = VaultStore::load(&ps, "pw").unwrap();
        store.edit("s1", None, Some("new-val"), None, None).unwrap();
        store.save().unwrap();
        let store = VaultStore::load(&ps, "pw").unwrap();
        let after = store.list(None).unwrap();
        assert_ne!(after[0].updated_at, created_before);
    }

    #[test]
    fn edit_all_fields_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.set("s1", "K", "v", "d", &["old".into()]).unwrap();
        store
            .edit(
                "s1",
                Some("NEW_K"),
                Some("new-v"),
                Some("new-d"),
                Some(&["new-tag".into()]),
            )
            .unwrap();
        store.save().unwrap();
        let store = VaultStore::load(&ps, "pw").unwrap();
        let info = store.list(None).unwrap();
        assert_eq!(info[0].key, "NEW_K");
        assert_eq!(info[0].description, "new-d");
        assert_eq!(info[0].tags, vec!["new-tag".to_string()]);
        assert_eq!(store.get("s1").unwrap(), "new-v");
    }

    #[test]
    fn rename_secret_preserves_assignments_and_override_bindings() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir
            .path()
            .join("rename-secret.vault.json")
            .to_str()
            .unwrap()
            .to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store
            .set("db", "DATABASE_URL", "postgres://x", "desc", &[])
            .unwrap();
        store.create_app("backend", "backend", "./run.sh").unwrap();
        store.assign("backend", "db", Some("BACKEND_DB")).unwrap();
        let original_id = store.list(None).unwrap()[0].id.clone();

        store.rename_secret("db", "primary-db").unwrap();
        store.save().unwrap();

        let store = VaultStore::load(&ps, "pw").unwrap();
        let secrets = store.list(None).unwrap();
        let bindings = store.get_app_secret_bindings("backend").unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].alias, "primary-db");
        assert_eq!(secrets[0].id, original_id);
        assert_eq!(store.get("primary-db").unwrap(), "postgres://x");
        assert!(matches!(store.get("db"), Err(VaultError::AliasNotFound(_))));
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].alias, "primary-db");
        assert_eq!(bindings[0].secret_id, original_id);
        assert_eq!(bindings[0].injected_as, "BACKEND_DB");
        assert_eq!(
            store.get_app_secrets("backend").unwrap()["BACKEND_DB"],
            "postgres://x"
        );
    }

    #[test]
    fn rename_app_preserves_id_path_and_secret_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir
            .path()
            .join("rename-app.vault.json")
            .to_str()
            .unwrap()
            .to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.set("api", "API_KEY", "secret", "", &[]).unwrap();
        store
            .create_app("backend", "backend", "./bin/run-backend")
            .unwrap();
        store.assign("backend", "api", Some("RENAMED_KEY")).unwrap();
        let original_app_id = store.list_apps()[0].id.clone();

        store.rename_app("backend", "api-service").unwrap();
        store.save().unwrap();

        let store = VaultStore::load(&ps, "pw").unwrap();
        let apps = store.list_apps();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].name, "api-service");
        assert_eq!(apps[0].id, original_app_id);
        assert_eq!(
            store.get_app_path("api-service").unwrap(),
            "./bin/run-backend"
        );
        assert!(matches!(
            store.get_app_path("backend"),
            Err(VaultError::AppNotFound(_))
        ));
        assert_eq!(
            store.get_app_secrets("api-service").unwrap()["RENAMED_KEY"],
            "secret"
        );
    }

    #[test]
    fn create_app_rejects_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir.path().join("v.json").to_str().unwrap().to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.create_app("myapp", "desc", "").unwrap();
        let result = store.create_app("myapp", "other", "");
        assert!(result.is_err());
        let err_msg = result.err().expect("expected Err").to_string();
        assert!(err_msg.contains("already exists"), "got: {err_msg}");
    }

    #[test]
    fn rename_secret_rejects_existing_alias() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir
            .path()
            .join("rename-conflict.vault.json")
            .to_str()
            .unwrap()
            .to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.set("db", "DATABASE_URL", "a", "", &[]).unwrap();
        store.set("redis", "REDIS_URL", "b", "", &[]).unwrap();
        let result = store.rename_secret("db", "redis");
        assert!(matches!(result, Err(VaultError::AliasExists(_))));
    }

    #[test]
    fn rename_app_rejects_existing_name() {
        let dir = tempfile::tempdir().unwrap();
        let ps = dir
            .path()
            .join("rename-app-conflict.vault.json")
            .to_str()
            .unwrap()
            .to_string();
        let mut store = VaultStore::create(&ps, "pw", Some(fast_kdf())).unwrap();
        store.create_app("backend", "", "").unwrap();
        store.create_app("worker", "", "").unwrap();
        let result = store.rename_app("backend", "worker");
        assert!(matches!(result, Err(VaultError::AppExists(_))));
    }
}
