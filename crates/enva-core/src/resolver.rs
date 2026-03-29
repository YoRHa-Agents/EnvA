//! Secret resolution pipeline (architecture doc §6.2).
//!
//! Resolves a [`ResolvedCredential`] for a given provider/profile by
//! walking a configurable precedence chain: session override → profile
//! list (cooldown-aware) → encrypted store → environment variable
//! fallback.

use std::env;

use chrono::Utc;
use secrecy::SecretString;

use crate::audit::{log_access, AuditEntry};
use crate::profile::{is_cooled_down, sort_profiles, AuthProfile};
use crate::store::SecretsStore;
use crate::types::{ResolvedCredential, SecretKind};

/// Controls whether the encrypted store or environment variables are
/// checked first when resolving credentials.
///
/// Configurable via `ENVA_SECRET_PRECEDENCE`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Precedence {
    /// Check encrypted store before environment variables (default).
    #[default]
    StoreFirst,
    /// Check environment variables before the encrypted store.
    EnvFirst,
}

impl Precedence {
    /// Reads precedence from the `ENVA_SECRET_PRECEDENCE` env var.
    ///
    /// Returns [`StoreFirst`](Precedence::StoreFirst) unless the env var
    /// is explicitly set to `"env_first"`.
    pub fn from_env() -> Self {
        match env::var("ENVA_SECRET_PRECEDENCE")
            .unwrap_or_default()
            .as_str()
        {
            "env_first" => Self::EnvFirst,
            _ => Self::StoreFirst,
        }
    }
}

/// Errors produced during credential resolution.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("store lookup failed: {0}")]
    Store(#[from] crate::store::StoreError),
    #[error("decryption failed: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
}

/// Resolves a credential for `provider_id` by walking the precedence chain.
///
/// 1. Iterate `profiles` (already sorted, cooldown-aware) for the
///    given provider.
/// 2. For each non-cooled profile, attempt resolution in the order
///    dictated by `precedence`.
/// 3. If `profile_id` is `Some`, only that specific profile is tried.
///
/// # Errors
///
/// Returns [`ResolveError`] on store or decryption failures.
pub fn resolve(
    provider_id: &str,
    profile_id: Option<&str>,
    profiles: &[AuthProfile],
    store: &dyn SecretsStore,
    crypto: &crate::crypto::SecretsCrypto,
    precedence: Precedence,
) -> Result<ResolvedCredential, ResolveError> {
    let mut candidates: Vec<AuthProfile> = profiles
        .iter()
        .filter(|p| p.provider_id == provider_id)
        .filter(|p| profile_id.is_none_or(|pid| p.profile_id == pid))
        .cloned()
        .collect();

    sort_profiles(&mut candidates);

    for profile in &candidates {
        if is_cooled_down(profile) {
            continue;
        }

        let result = match precedence {
            Precedence::StoreFirst => try_store_then_env(
                provider_id,
                &profile.profile_id,
                profile.api_key_env.as_deref(),
                store,
                crypto,
            )?,
            Precedence::EnvFirst => try_env_then_store(
                provider_id,
                &profile.profile_id,
                profile.api_key_env.as_deref(),
                store,
                crypto,
            )?,
        };

        if !matches!(result, ResolvedCredential::None) {
            return Ok(result);
        }
    }

    Ok(ResolvedCredential::None)
}

fn try_store_then_env(
    provider_id: &str,
    profile_id: &str,
    api_key_env: Option<&str>,
    store: &dyn SecretsStore,
    crypto: &crate::crypto::SecretsCrypto,
) -> Result<ResolvedCredential, ResolveError> {
    if let Some(cred) = try_store(provider_id, profile_id, store, crypto)? {
        return Ok(cred);
    }
    Ok(try_env(provider_id, profile_id, api_key_env))
}

fn try_env_then_store(
    provider_id: &str,
    profile_id: &str,
    api_key_env: Option<&str>,
    store: &dyn SecretsStore,
    crypto: &crate::crypto::SecretsCrypto,
) -> Result<ResolvedCredential, ResolveError> {
    let env_result = try_env(provider_id, profile_id, api_key_env);
    if !matches!(env_result, ResolvedCredential::None) {
        return Ok(env_result);
    }
    if let Some(cred) = try_store(provider_id, profile_id, store, crypto)? {
        return Ok(cred);
    }
    Ok(ResolvedCredential::None)
}

fn try_store(
    provider_id: &str,
    profile_id: &str,
    store: &dyn SecretsStore,
    crypto: &crate::crypto::SecretsCrypto,
) -> Result<Option<ResolvedCredential>, ResolveError> {
    if let Some(record) = store.get(provider_id, profile_id, &SecretKind::ApiKey)? {
        let plaintext = crypto.decrypt(&record.encrypted_value, &record.salt)?;
        let secret_str = String::from_utf8(plaintext)
            .map_err(|_| ResolveError::Crypto(crate::crypto::CryptoError::DecryptionFailed))?;
        log_access(&AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            action: "resolve".to_owned(),
            provider_id: provider_id.to_owned(),
            profile_id: profile_id.to_owned(),
            source: "encrypted".to_owned(),
        });
        return Ok(Some(ResolvedCredential::ApiKey(SecretString::from(
            secret_str,
        ))));
    }
    Ok(None)
}

fn try_env(provider_id: &str, profile_id: &str, api_key_env: Option<&str>) -> ResolvedCredential {
    let env_name = match api_key_env {
        Some(name) => name,
        None => return ResolvedCredential::None,
    };
    match env::var(env_name) {
        Ok(val) if !val.is_empty() => {
            log_access(&AuditEntry {
                timestamp: Utc::now().to_rfc3339(),
                action: "resolve".to_owned(),
                provider_id: provider_id.to_owned(),
                profile_id: profile_id.to_owned(),
                source: "env".to_owned(),
            });
            ResolvedCredential::ApiKey(SecretString::from(val))
        }
        _ => ResolvedCredential::None,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use secrecy::{ExposeSecret, SecretString};
    use tempfile::TempDir;

    use super::*;
    use crate::crypto::SecretsCrypto;
    use crate::file_backend::FileSecretsStore;
    use crate::store::SecretsStore;
    use crate::types::SecretRecord;

    fn make_crypto() -> SecretsCrypto {
        SecretsCrypto::new(SecretString::from(
            "a]32-byte-test-master-key-value!".to_owned(),
        ))
        .unwrap()
    }

    fn make_store(tmp: &TempDir) -> FileSecretsStore {
        let path = tmp.path().join("test-secrets.enc");
        FileSecretsStore::new(path, make_crypto()).unwrap()
    }

    fn make_profile(id: &str, env_name: Option<&str>, preferred: bool) -> AuthProfile {
        AuthProfile {
            profile_id: id.to_owned(),
            provider_id: "test-provider".to_owned(),
            api_key_env: env_name.map(|s| s.to_owned()),
            priority: 0,
            cooldown_until: None,
            preferred,
        }
    }

    fn store_secret(store: &mut FileSecretsStore, provider: &str, profile: &str, value: &str) {
        let crypto = make_crypto();
        let (encrypted, salt) = crypto.encrypt(value.as_bytes()).unwrap();
        let record = SecretRecord {
            schema_version: 1,
            provider_id: provider.to_owned(),
            profile_id: profile.to_owned(),
            secret_kind: SecretKind::ApiKey,
            encrypted_value: encrypted,
            salt,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: None,
        };
        store.put(&record).unwrap();
    }

    #[test]
    fn resolve_from_store_first() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(&tmp);
        store_secret(&mut store, "test-provider", "default", "sk-from-store");

        let profiles = vec![make_profile("default", None, true)];
        let crypto = make_crypto();
        let result = resolve(
            "test-provider",
            None,
            &profiles,
            &store,
            &crypto,
            Precedence::StoreFirst,
        )
        .unwrap();

        match result {
            ResolvedCredential::ApiKey(s) => assert_eq!(s.expose_secret(), "sk-from-store"),
            _ => panic!("expected ApiKey"),
        }
    }

    #[test]
    fn resolve_env_fallback() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp);

        let env_key = "FA_TEST_RESOLVE_ENV_FALLBACK_KEY";
        env::set_var(env_key, "sk-from-env");

        let profiles = vec![make_profile("default", Some(env_key), true)];
        let crypto = make_crypto();
        let result = resolve(
            "test-provider",
            None,
            &profiles,
            &store,
            &crypto,
            Precedence::StoreFirst,
        )
        .unwrap();

        match result {
            ResolvedCredential::ApiKey(s) => assert_eq!(s.expose_secret(), "sk-from-env"),
            _ => panic!("expected ApiKey from env"),
        }

        env::remove_var(env_key);
    }

    #[test]
    fn resolve_env_first_precedence() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(&tmp);
        store_secret(&mut store, "test-provider", "default", "sk-from-store");

        let env_key = "FA_TEST_RESOLVE_ENV_FIRST_KEY";
        env::set_var(env_key, "sk-env-wins");

        let profiles = vec![make_profile("default", Some(env_key), true)];
        let crypto = make_crypto();
        let result = resolve(
            "test-provider",
            None,
            &profiles,
            &store,
            &crypto,
            Precedence::EnvFirst,
        )
        .unwrap();

        match result {
            ResolvedCredential::ApiKey(s) => assert_eq!(s.expose_secret(), "sk-env-wins"),
            _ => panic!("expected ApiKey from env"),
        }

        env::remove_var(env_key);
    }

    #[test]
    fn resolve_skips_cooled_profiles() {
        let tmp = TempDir::new().unwrap();
        let mut store = make_store(&tmp);
        store_secret(&mut store, "test-provider", "cooled", "sk-cooled");
        store_secret(&mut store, "test-provider", "ok", "sk-ok");

        let mut cooled_prof = make_profile("cooled", None, true);
        crate::profile::report_rate_limit(&mut cooled_prof, std::time::Duration::from_secs(60));
        let ok_prof = make_profile("ok", None, false);

        let profiles = vec![cooled_prof, ok_prof];
        let crypto = make_crypto();
        let result = resolve(
            "test-provider",
            None,
            &profiles,
            &store,
            &crypto,
            Precedence::StoreFirst,
        )
        .unwrap();

        match result {
            ResolvedCredential::ApiKey(s) => assert_eq!(s.expose_secret(), "sk-ok"),
            _ => panic!("expected ApiKey from non-cooled profile"),
        }
    }

    #[test]
    fn resolve_returns_none_when_no_credentials() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp);
        let profiles = vec![make_profile("empty", None, false)];
        let crypto = make_crypto();
        let result = resolve(
            "test-provider",
            None,
            &profiles,
            &store,
            &crypto,
            Precedence::StoreFirst,
        )
        .unwrap();
        assert!(matches!(result, ResolvedCredential::None));
    }

    #[test]
    fn precedence_from_env_defaults_store_first() {
        env::remove_var("ENVA_SECRET_PRECEDENCE");
        assert_eq!(Precedence::from_env(), Precedence::StoreFirst);
    }

    #[test]
    fn precedence_from_env_invalid_value_falls_back_to_store_first() {
        env::set_var("ENVA_SECRET_PRECEDENCE", "bogus_invalid");
        let p = Precedence::from_env();
        env::remove_var("ENVA_SECRET_PRECEDENCE");
        assert_eq!(p, Precedence::StoreFirst);
    }

    #[test]
    fn precedence_from_env_recognizes_env_first() {
        env::set_var("ENVA_SECRET_PRECEDENCE", "env_first");
        let p = Precedence::from_env();
        env::remove_var("ENVA_SECRET_PRECEDENCE");
        assert_eq!(p, Precedence::EnvFirst);
    }
}
