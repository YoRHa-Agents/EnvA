use std::fs;
use std::io::Write;
use std::path::Path;

use thiserror::Error;

use crate::{paths, ssh_config::SshHostConfig};

pub const DEFAULT_MANAGED_SSH_HOSTS_PATH: &str = "~/.enva/ssh_hosts.json";

#[derive(Debug, Error)]
pub enum ManagedSshHostsError {
    #[error("managed ssh hosts path cannot be empty")]
    EmptyPath,
    #[error("failed to resolve managed ssh hosts path '{raw}': {source}")]
    Resolve {
        raw: String,
        #[source]
        source: paths::PathResolutionError,
    },
    #[error("failed to read managed ssh hosts '{path}': {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse managed ssh hosts '{path}': {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("managed ssh hosts contains duplicate alias '{alias}'")]
    DuplicateAlias { alias: String },
    #[error("failed to serialize managed ssh hosts: {source}")]
    Serialize {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to write managed ssh hosts '{path}': {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

pub fn load_managed_hosts(raw_path: &str) -> Result<Vec<SshHostConfig>, ManagedSshHostsError> {
    let resolved_path = resolve_path(raw_path)?;
    let path = Path::new(&resolved_path);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(path).map_err(|source| ManagedSshHostsError::Read {
        path: resolved_path.clone(),
        source,
    })?;
    let hosts: Vec<SshHostConfig> =
        serde_json::from_str(&content).map_err(|source| ManagedSshHostsError::Parse {
            path: resolved_path.clone(),
            source,
        })?;
    normalize_hosts(hosts)
}

pub fn save_managed_hosts(
    raw_path: &str,
    hosts: &[SshHostConfig],
) -> Result<String, ManagedSshHostsError> {
    let resolved_path = resolve_path(raw_path)?;
    let normalized = normalize_hosts(hosts.to_vec())?;
    let parent = Path::new(&resolved_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| ManagedSshHostsError::Write {
        path: resolved_path.clone(),
        source,
    })?;

    let content = serde_json::to_vec_pretty(&normalized)
        .map_err(|source| ManagedSshHostsError::Serialize { source })?;
    let mut temp_file =
        tempfile::NamedTempFile::new_in(parent).map_err(|source| ManagedSshHostsError::Write {
            path: resolved_path.clone(),
            source,
        })?;
    temp_file
        .write_all(&content)
        .map_err(|source| ManagedSshHostsError::Write {
            path: resolved_path.clone(),
            source,
        })?;
    temp_file
        .flush()
        .map_err(|source| ManagedSshHostsError::Write {
            path: resolved_path.clone(),
            source,
        })?;
    temp_file
        .persist(&resolved_path)
        .map_err(|error| ManagedSshHostsError::Write {
            path: resolved_path.clone(),
            source: error.error,
        })?;
    Ok(resolved_path)
}

fn resolve_path(raw_path: &str) -> Result<String, ManagedSshHostsError> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return Err(ManagedSshHostsError::EmptyPath);
    }

    paths::resolve_named_path(trimmed, "managed ssh hosts").map_err(|source| {
        ManagedSshHostsError::Resolve {
            raw: trimmed.to_string(),
            source,
        }
    })
}

fn normalize_hosts(
    mut hosts: Vec<SshHostConfig>,
) -> Result<Vec<SshHostConfig>, ManagedSshHostsError> {
    hosts.sort_by(|left, right| left.alias.cmp(&right.alias));
    for pair in hosts.windows(2) {
        if pair[0].alias == pair[1].alias {
            return Err(ManagedSshHostsError::DuplicateAlias {
                alias: pair[0].alias.clone(),
            });
        }
    }
    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(alias: &str, hostname: &str) -> SshHostConfig {
        SshHostConfig {
            alias: alias.to_string(),
            hostname: hostname.to_string(),
            user: "alice".to_string(),
            port: 22,
            identity_file: None,
        }
    }

    #[test]
    fn load_managed_hosts_returns_empty_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let hosts = load_managed_hosts(path.to_string_lossy().as_ref()).unwrap();
        assert!(hosts.is_empty());
    }

    #[test]
    fn save_and_load_managed_hosts_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.json");
        save_managed_hosts(
            path.to_string_lossy().as_ref(),
            &[
                host("prod", "prod.example.com"),
                host("staging", "staging.example.com"),
            ],
        )
        .unwrap();

        let loaded = load_managed_hosts(path.to_string_lossy().as_ref()).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].alias, "prod");
        assert_eq!(loaded[1].alias, "staging");
    }

    #[test]
    fn save_managed_hosts_rejects_duplicate_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.json");
        let error = save_managed_hosts(
            path.to_string_lossy().as_ref(),
            &[
                host("prod", "prod-a.example.com"),
                host("prod", "prod-b.example.com"),
            ],
        )
        .unwrap_err();
        assert!(matches!(error, ManagedSshHostsError::DuplicateAlias { .. }));
    }
}
