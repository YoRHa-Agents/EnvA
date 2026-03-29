//! File-based encrypted storage backend.
//!
//! Secrets are persisted as JSON Lines in a single file
//! (default `~/.enva/secrets.enc`). Each line is a serialised
//! [`SecretRecord`] whose `encrypted_value` and `salt` fields are
//! base64-encoded.
//!
//! Records are loaded into memory on construction and written back
//! atomically on every mutation.

use std::fs;
use std::path::PathBuf;

use crate::crypto::SecretsCrypto;
use crate::store::{SecretsStore, StoreError};
use crate::types::{SecretKind, SecretRecord};

/// File-backed implementation of [`SecretsStore`].
///
/// Holds an in-memory copy of all records and flushes to disk on
/// every `put` or `delete`.
pub struct FileSecretsStore {
    path: PathBuf,
    records: Vec<SecretRecord>,
    crypto: SecretsCrypto,
}

impl FileSecretsStore {
    /// Opens (or creates) a file-backed secrets store at `path`.
    ///
    /// Existing records are loaded on construction. The `crypto` engine
    /// is retained for future encryption operations during `put`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the file exists but cannot be read or
    /// contains malformed JSON Lines.
    pub fn new(path: PathBuf, crypto: SecretsCrypto) -> Result<Self, StoreError> {
        let records = if path.exists() {
            load_records(&path)?
        } else {
            Vec::new()
        };
        Ok(Self {
            path,
            records,
            crypto,
        })
    }

    /// Returns a reference to the underlying crypto engine, useful for
    /// decrypting individual records retrieved via [`get`](SecretsStore::get).
    pub fn crypto(&self) -> &SecretsCrypto {
        &self.crypto
    }

    fn flush(&self) -> Result<(), StoreError> {
        let dir = self.path.parent().unwrap_or(std::path::Path::new("."));
        fs::create_dir_all(dir)?;
        let mut buf = String::new();
        for record in &self.records {
            let line = serde_json::to_string(record)?;
            buf.push_str(&line);
            buf.push('\n');
        }
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        tmp.write_all(buf.as_bytes())?;
        tmp.persist(&self.path)
            .map_err(|e| StoreError::Io(e.error))?;
        Ok(())
    }

    fn find_index(&self, provider_id: &str, profile_id: &str, kind: &SecretKind) -> Option<usize> {
        self.records.iter().position(|r| {
            r.provider_id == provider_id && r.profile_id == profile_id && r.secret_kind == *kind
        })
    }
}

impl SecretsStore for FileSecretsStore {
    fn put(&mut self, record: &SecretRecord) -> Result<(), StoreError> {
        if let Some(idx) =
            self.find_index(&record.provider_id, &record.profile_id, &record.secret_kind)
        {
            self.records[idx] = record.clone();
        } else {
            self.records.push(record.clone());
        }
        self.flush()
    }

    fn get(
        &self,
        provider_id: &str,
        profile_id: &str,
        kind: &SecretKind,
    ) -> Result<Option<SecretRecord>, StoreError> {
        Ok(self
            .find_index(provider_id, profile_id, kind)
            .map(|idx| self.records[idx].clone()))
    }

    fn list(&self, provider_id: Option<&str>) -> Result<Vec<SecretRecord>, StoreError> {
        let filtered = match provider_id {
            Some(pid) => self
                .records
                .iter()
                .filter(|r| r.provider_id == pid)
                .cloned()
                .collect(),
            None => self.records.clone(),
        };
        Ok(filtered)
    }

    fn delete(&mut self, provider_id: &str, profile_id: &str) -> Result<bool, StoreError> {
        let before = self.records.len();
        self.records
            .retain(|r| !(r.provider_id == provider_id && r.profile_id == profile_id));
        let removed = self.records.len() < before;
        if removed {
            self.flush()?;
        }
        Ok(removed)
    }
}

fn load_records(path: &PathBuf) -> Result<Vec<SecretRecord>, StoreError> {
    let content = fs::read_to_string(path)?;
    let mut records = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let record: SecretRecord = serde_json::from_str(line)?;
        records.push(record);
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use secrecy::SecretString;
    use tempfile::TempDir;

    use super::*;

    fn make_crypto() -> SecretsCrypto {
        SecretsCrypto::new(SecretString::from(
            "a]32-byte-test-master-key-value!".to_owned(),
        ))
        .unwrap()
    }

    fn make_record(provider: &str, profile: &str, kind: SecretKind) -> SecretRecord {
        let crypto = make_crypto();
        let (encrypted, salt) = crypto.encrypt(b"test-secret-value").unwrap();
        SecretRecord {
            schema_version: 1,
            provider_id: provider.to_owned(),
            profile_id: profile.to_owned(),
            secret_kind: kind,
            encrypted_value: encrypted,
            salt,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: None,
        }
    }

    #[test]
    fn put_get_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.enc");
        let crypto = make_crypto();
        let mut store = FileSecretsStore::new(path, crypto).unwrap();

        let record = make_record("openai", "default", SecretKind::ApiKey);
        store.put(&record).unwrap();

        let fetched = store.get("openai", "default", &SecretKind::ApiKey).unwrap();
        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.provider_id, "openai");
        assert_eq!(fetched.profile_id, "default");
    }

    #[test]
    fn put_updates_existing_record() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.enc");
        let crypto = make_crypto();
        let mut store = FileSecretsStore::new(path, crypto).unwrap();

        let r1 = make_record("openai", "default", SecretKind::ApiKey);
        store.put(&r1).unwrap();

        let mut r2 = make_record("openai", "default", SecretKind::ApiKey);
        r2.schema_version = 2;
        store.put(&r2).unwrap();

        let all = store.list(None).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].schema_version, 2);
    }

    #[test]
    fn list_filters_by_provider() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.enc");
        let crypto = make_crypto();
        let mut store = FileSecretsStore::new(path, crypto).unwrap();

        store
            .put(&make_record("openai", "a", SecretKind::ApiKey))
            .unwrap();
        store
            .put(&make_record("anthropic", "b", SecretKind::Bearer))
            .unwrap();

        let all = store.list(None).unwrap();
        assert_eq!(all.len(), 2);

        let openai_only = store.list(Some("openai")).unwrap();
        assert_eq!(openai_only.len(), 1);
        assert_eq!(openai_only[0].provider_id, "openai");
    }

    #[test]
    fn delete_removes_matching_records() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.enc");
        let crypto = make_crypto();
        let mut store = FileSecretsStore::new(path, crypto).unwrap();

        store
            .put(&make_record("openai", "default", SecretKind::ApiKey))
            .unwrap();
        store
            .put(&make_record("openai", "default", SecretKind::Bearer))
            .unwrap();

        let removed = store.delete("openai", "default").unwrap();
        assert!(removed);
        assert_eq!(store.list(None).unwrap().len(), 0);
    }

    #[test]
    fn delete_returns_false_when_no_match() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.enc");
        let crypto = make_crypto();
        let mut store = FileSecretsStore::new(path, crypto).unwrap();

        let removed = store.delete("nonexistent", "nope").unwrap();
        assert!(!removed);
    }

    #[test]
    fn persistence_across_reloads() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.enc");

        {
            let crypto = make_crypto();
            let mut store = FileSecretsStore::new(path.clone(), crypto).unwrap();
            store
                .put(&make_record("openai", "work", SecretKind::ApiKey))
                .unwrap();
        }

        let crypto = make_crypto();
        let store = FileSecretsStore::new(path, crypto).unwrap();
        let records = store.list(None).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].provider_id, "openai");
    }

    #[test]
    fn new_with_invalid_json_errors() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.enc");
        fs::write(&path, "this is not valid json\n").unwrap();

        let crypto = make_crypto();
        let result = FileSecretsStore::new(path, crypto);
        match result {
            Err(StoreError::Serialization(_)) => {}
            Err(other) => panic!("expected StoreError::Serialization, got: {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn new_with_empty_file_succeeds() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.enc");
        fs::write(&path, "").unwrap();

        let crypto = make_crypto();
        let store = FileSecretsStore::new(path, crypto).unwrap();
        let records = store.list(None).unwrap();
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn new_with_truncated_json_errors() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("secrets.enc");
        fs::write(&path, "{\"schema_version\":1,\"provider_id\":\"op\n").unwrap();

        let crypto = make_crypto();
        let result = FileSecretsStore::new(path, crypto);
        match result {
            Err(StoreError::Serialization(_)) => {}
            Err(other) => panic!("expected StoreError::Serialization, got: {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }
}
