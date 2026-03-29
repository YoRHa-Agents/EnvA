//! Secret type definitions for the Enva core library.
//!
//! Provides [`SecretKind`], [`SecretRecord`], [`DecryptedSecret`], and
//! [`ResolvedCredential`] — the core domain types used across the
//! encryption engine, storage backend, and resolution pipeline.

use std::fmt;

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

/// Discriminator for the type of credential stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiKey,
    Bearer,
    OAuthRefresh,
    Custom(String),
}

/// Persisted record that wraps an encrypted secret with its metadata.
///
/// The `encrypted_value` field holds `nonce || ciphertext_with_tag` and `salt`
/// is the per-secret HKDF salt used during key derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    pub schema_version: u32,
    pub provider_id: String,
    pub profile_id: String,
    pub secret_kind: SecretKind,
    #[serde(with = "base64_bytes")]
    pub encrypted_value: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub salt: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Wrapper around a decrypted secret that only exposes the plaintext
/// through an explicit [`expose`](DecryptedSecret::expose) call.
///
/// Internally backed by [`SecretString`] which zeroises memory on drop.
pub struct DecryptedSecret {
    inner: SecretString,
}

impl DecryptedSecret {
    /// Creates a new decrypted secret from a raw string value.
    pub fn new(value: String) -> Self {
        Self {
            inner: SecretString::from(value),
        }
    }

    /// Temporarily exposes the plaintext secret for use.
    pub fn expose(&self) -> &str {
        self.inner.expose_secret()
    }
}

impl fmt::Debug for DecryptedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Resolved credential ready for injection into HTTP requests.
///
/// Adapters map this to wire-level headers / query parameters.
/// The `Debug` impl never prints plaintext values.
pub enum ResolvedCredential {
    ApiKey(SecretString),
    Bearer(SecretString),
    OAuth {
        access: SecretString,
        expires_at: Option<DateTime<Utc>>,
    },
    None,
}

impl fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.write_str("ResolvedCredential::ApiKey([REDACTED])"),
            Self::Bearer(_) => f.write_str("ResolvedCredential::Bearer([REDACTED])"),
            Self::OAuth { expires_at, .. } => f
                .debug_struct("ResolvedCredential::OAuth")
                .field("access", &"[REDACTED]")
                .field("expires_at", expires_at)
                .finish(),
            Self::None => f.write_str("ResolvedCredential::None"),
        }
    }
}

/// Serde helper for `Vec<u8>` ↔ base64 encoding in JSON Lines storage.
mod base64_bytes {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypted_secret_debug_is_redacted() {
        let secret = DecryptedSecret::new("super-secret-key".to_owned());
        let debug_output = format!("{secret:?}");
        assert_eq!(debug_output, "[REDACTED]");
        assert!(!debug_output.contains("super-secret-key"));
    }

    #[test]
    fn decrypted_secret_expose_returns_value() {
        let secret = DecryptedSecret::new("my-api-key".to_owned());
        assert_eq!(secret.expose(), "my-api-key");
    }

    #[test]
    fn resolved_credential_debug_hides_plaintext() {
        let api = ResolvedCredential::ApiKey(SecretString::from("sk-1234".to_owned()));
        let bearer = ResolvedCredential::Bearer(SecretString::from("tok-abc".to_owned()));
        let oauth = ResolvedCredential::OAuth {
            access: SecretString::from("access-xyz".to_owned()),
            expires_at: None,
        };
        let none = ResolvedCredential::None;

        let api_dbg = format!("{api:?}");
        let bearer_dbg = format!("{bearer:?}");
        let oauth_dbg = format!("{oauth:?}");
        let none_dbg = format!("{none:?}");

        assert!(!api_dbg.contains("sk-1234"));
        assert!(api_dbg.contains("REDACTED"));
        assert!(!bearer_dbg.contains("tok-abc"));
        assert!(bearer_dbg.contains("REDACTED"));
        assert!(!oauth_dbg.contains("access-xyz"));
        assert!(oauth_dbg.contains("REDACTED"));
        assert_eq!(none_dbg, "ResolvedCredential::None");
    }

    #[test]
    fn secret_kind_serialization_roundtrip() {
        let kinds = vec![
            SecretKind::ApiKey,
            SecretKind::Bearer,
            SecretKind::OAuthRefresh,
            SecretKind::Custom("x-custom".to_owned()),
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).expect("serialize");
            let back: SecretKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&back, kind);
        }
    }

    #[test]
    fn secret_record_serde_roundtrip() {
        use chrono::Utc;
        let record = SecretRecord {
            schema_version: 1,
            provider_id: "openai".to_owned(),
            profile_id: "default".to_owned(),
            secret_kind: SecretKind::ApiKey,
            encrypted_value: vec![1, 2, 3, 4, 5],
            salt: vec![10, 20, 30],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: None,
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: SecretRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.provider_id, "openai");
        assert_eq!(back.profile_id, "default");
        assert_eq!(back.encrypted_value, vec![1, 2, 3, 4, 5]);
        assert_eq!(back.salt, vec![10, 20, 30]);
        assert_eq!(back.schema_version, 1);
        assert!(back.expires_at.is_none());
    }

    #[test]
    fn secret_record_with_expires_at_roundtrip() {
        use chrono::Utc;
        let now = Utc::now();
        let record = SecretRecord {
            schema_version: 2,
            provider_id: "anthropic".to_owned(),
            profile_id: "work".to_owned(),
            secret_kind: SecretKind::Bearer,
            encrypted_value: vec![],
            salt: vec![],
            created_at: now,
            updated_at: now,
            expires_at: Some(now),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("expires_at"));
        let back: SecretRecord = serde_json::from_str(&json).unwrap();
        assert!(back.expires_at.is_some());
    }

    #[test]
    fn decrypted_secret_empty_string() {
        let secret = DecryptedSecret::new(String::new());
        assert_eq!(secret.expose(), "");
    }

    #[test]
    fn decrypted_secret_unicode() {
        let secret = DecryptedSecret::new("密钥🔑résumé".to_owned());
        assert_eq!(secret.expose(), "密钥🔑résumé");
    }

    #[test]
    fn secret_kind_custom_variant_preserves_value() {
        let kind = SecretKind::Custom("my-special-type".to_owned());
        let json = serde_json::to_string(&kind).unwrap();
        assert!(json.contains("my-special-type"));
        let back: SecretKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SecretKind::Custom("my-special-type".to_owned()));
    }
}
