//! JWT authentication and rate limiting.

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_EXPIRY_SECS: u64 = 1800;
const MAX_ATTEMPTS: usize = 5;
const LOCKOUT_SECS: u64 = 300;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub vault_path: String,
    pub exp: u64,
    pub iat: u64,
}

pub struct AuthManager {
    secret: Vec<u8>,
    expiry: Duration,
    failures: Mutex<HashMap<String, Vec<Instant>>>,
}

impl AuthManager {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            expiry: Duration::from_secs(DEFAULT_EXPIRY_SECS),
            failures: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_rate_limit(&self, client: &str) -> Result<(), String> {
        let mut failures = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(LOCKOUT_SECS);
        let attempts = failures.entry(client.into()).or_default();
        attempts.retain(|t| *t > cutoff);
        if attempts.len() >= MAX_ATTEMPTS {
            return Err(format!("Rate limited. Try again in {LOCKOUT_SECS}s."));
        }
        Ok(())
    }

    pub fn record_failure(&self, client: &str) {
        let mut failures = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        failures
            .entry(client.into())
            .or_default()
            .push(Instant::now());
    }

    pub fn create_token(&self, vault_path: &str) -> Result<String, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let claims = Claims {
            vault_path: vault_path.into(),
            iat: now,
            exp: now + self.expiry.as_secs(),
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(&self.secret),
        )
        .map_err(|e| e.to_string())
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, String> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(&self.secret),
            &Validation::default(),
        )
        .map(|data| data.claims)
        .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_verify_token_roundtrip() {
        let am = AuthManager::new(b"test-secret-key");
        let token = am.create_token("/tmp/vault.json").unwrap();
        let claims = am.verify_token(&token).unwrap();
        assert_eq!(claims.vault_path, "/tmp/vault.json");
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn verify_rejects_tampered_token() {
        let am = AuthManager::new(b"test-secret-key");
        let token = am.create_token("/tmp/vault.json").unwrap();
        let tampered = format!("{token}tampered");
        assert!(am.verify_token(&tampered).is_err());
    }

    #[test]
    fn verify_rejects_garbage_token() {
        let am = AuthManager::new(b"test-secret-key");
        assert!(am.verify_token("not.a.valid.jwt").is_err());
        assert!(am.verify_token("").is_err());
    }

    #[test]
    fn check_rate_limit_ok_initially() {
        let am = AuthManager::new(b"secret");
        assert!(am.check_rate_limit("client1").is_ok());
    }

    #[test]
    fn rate_limit_blocks_after_max_failures() {
        let am = AuthManager::new(b"secret");
        for _ in 0..MAX_ATTEMPTS {
            am.record_failure("abuser");
        }
        assert!(am.check_rate_limit("abuser").is_err());
        assert!(am.check_rate_limit("innocent").is_ok());
    }
}
