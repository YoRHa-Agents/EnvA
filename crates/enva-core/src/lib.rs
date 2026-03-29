//! Enva core library — encrypted secret storage and cryptographic primitives.
//!
//! Provides AES-256-GCM encrypted secret storage with HKDF-SHA256
//! per-secret key derivation, a file-based backend, multi-profile
//! credential resolution, and audit logging.

pub mod audit;
pub mod crypto;
pub mod file_backend;
pub mod profile;
pub mod resolver;
pub mod store;
pub mod types;
pub mod vault_crypto;
