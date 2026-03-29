//! Storage backend trait for encrypted secret records.
//!
//! Implementations persist [`SecretRecord`] instances and retrieve them
//! by `(provider_id, profile_id, secret_kind)` composite key.

use crate::types::{SecretKind, SecretRecord};

/// Errors produced by storage backend operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("encryption error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
}

/// Trait for secret storage backends.
///
/// Implementations must be `Send + Sync` to support concurrent access
/// from async runtimes.
pub trait SecretsStore: Send + Sync {
    /// Persists a secret record, inserting or updating the existing entry
    /// matching `(provider_id, profile_id, secret_kind)`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] on I/O, serialization, or encryption failure.
    fn put(&mut self, record: &SecretRecord) -> Result<(), StoreError>;

    /// Retrieves a secret record by its composite key.
    ///
    /// Returns `Ok(None)` when no matching record exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] on I/O or deserialization failure.
    fn get(
        &self,
        provider_id: &str,
        profile_id: &str,
        kind: &SecretKind,
    ) -> Result<Option<SecretRecord>, StoreError>;

    /// Lists all stored records, optionally filtered by `provider_id`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] on I/O failure.
    fn list(&self, provider_id: Option<&str>) -> Result<Vec<SecretRecord>, StoreError>;

    /// Deletes all records matching `(provider_id, profile_id)`.
    ///
    /// Returns `true` if any records were removed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] on I/O failure.
    fn delete(&mut self, provider_id: &str, profile_id: &str) -> Result<bool, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_error_io_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let err = StoreError::Io(io_err);
        let msg = format!("{err}");
        assert!(msg.contains("I/O error"));
        assert!(msg.contains("file gone"));
    }

    #[test]
    fn store_error_serialization_display() {
        let bad_json: Result<serde_json::Value, _> = serde_json::from_str("{invalid");
        let serde_err = bad_json.unwrap_err();
        let err = StoreError::Serialization(serde_err);
        let msg = format!("{err}");
        assert!(msg.contains("serialization error"));
    }

    #[test]
    fn store_error_debug_contains_type() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err = StoreError::Io(io_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Io"));
    }
}
