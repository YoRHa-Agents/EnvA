//! Audit log interface for secret access events.
//!
//! Entries never contain plaintext secret values — only non-sensitive
//! metadata (provider, profile, source). See architecture doc §6.6.

use serde::Serialize;

/// A single audit log entry recording a secret access event.
///
/// The `source` field indicates where the credential was resolved from
/// (e.g. `"encrypted"` or `"env"`) and **must never** contain the
/// secret value itself.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub action: String,
    pub provider_id: String,
    pub profile_id: String,
    pub source: String,
}

/// Emits a structured audit log entry via `tracing::info`.
///
/// All fields are recorded as structured tracing fields for
/// machine-parseable consumption by log aggregators.
pub fn log_access(entry: &AuditEntry) {
    tracing::info!(
        timestamp = %entry.timestamp,
        action = %entry.action,
        provider_id = %entry.provider_id,
        profile_id = %entry.profile_id,
        source = %entry.source,
        "secret_access"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_entry_serializes_without_secret_value() {
        let entry = AuditEntry {
            timestamp: "2026-03-22T00:00:00Z".to_owned(),
            action: "get".to_owned(),
            provider_id: "openai".to_owned(),
            profile_id: "default".to_owned(),
            source: "encrypted".to_owned(),
        };
        let json = serde_json::to_string(&entry).expect("serialization");
        assert!(json.contains("openai"));
        assert!(json.contains("encrypted"));
        assert!(!json.contains("sk-"));
    }

    #[test]
    fn log_access_does_not_panic() {
        let entry = AuditEntry {
            timestamp: "2026-03-22T00:00:00Z".to_owned(),
            action: "resolve".to_owned(),
            provider_id: "anthropic".to_owned(),
            profile_id: "work".to_owned(),
            source: "env".to_owned(),
        };
        log_access(&entry);
    }

    #[test]
    fn audit_entry_all_fields_present_in_json() {
        let entry = AuditEntry {
            timestamp: "2026-01-01T00:00:00Z".to_owned(),
            action: "delete".to_owned(),
            provider_id: "provider-x".to_owned(),
            profile_id: "profile-y".to_owned(),
            source: "encrypted".to_owned(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("timestamp"));
        assert!(json.contains("action"));
        assert!(json.contains("provider_id"));
        assert!(json.contains("profile_id"));
        assert!(json.contains("source"));
        assert!(json.contains("delete"));
        assert!(json.contains("provider-x"));
    }

    #[test]
    fn log_access_various_actions() {
        for action in &["get", "set", "delete", "resolve", "list", "export"] {
            let entry = AuditEntry {
                timestamp: "2026-03-28T12:00:00Z".to_owned(),
                action: action.to_string(),
                provider_id: "test".to_owned(),
                profile_id: "default".to_owned(),
                source: "env".to_owned(),
            };
            log_access(&entry);
        }
    }
}
