use std::collections::BTreeMap;
use std::fs;

use thiserror::Error;

use crate::paths;

pub const DEFAULT_SSH_CONFIG_PATH: &str = "~/.ssh/config";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshHostConfig {
    pub alias: String,
    pub hostname: String,
    pub user: String,
    pub port: u16,
    pub identity_file: Option<String>,
}

#[derive(Debug, Error)]
pub enum SshConfigError {
    #[error("ssh config path cannot be empty")]
    EmptyPath,
    #[error("failed to resolve ssh config path '{raw}': {source}")]
    Resolve {
        raw: String,
        #[source]
        source: paths::PathResolutionError,
    },
    #[error("failed to read ssh config '{path}': {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Default)]
struct PartialHost {
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
}

impl PartialHost {
    fn apply_defaults(&mut self, defaults: &Self) {
        if self.hostname.is_none() {
            self.hostname = defaults.hostname.clone();
        }
        if self.user.is_none() {
            self.user = defaults.user.clone();
        }
        if self.port.is_none() {
            self.port = defaults.port;
        }
        if self.identity_file.is_none() {
            self.identity_file = defaults.identity_file.clone();
        }
    }

    fn merge_missing_from(&mut self, other: &Self) {
        if self.hostname.is_none() {
            self.hostname = other.hostname.clone();
        }
        if self.user.is_none() {
            self.user = other.user.clone();
        }
        if self.port.is_none() {
            self.port = other.port;
        }
        if self.identity_file.is_none() {
            self.identity_file = other.identity_file.clone();
        }
    }
}

fn strip_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or("")
}

fn trim_quotes(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 {
        let first = trimmed.as_bytes()[0];
        let last = trimmed.as_bytes()[trimmed.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    }
    trimmed.to_string()
}

fn contains_pattern(alias: &str) -> bool {
    alias.contains('*') || alias.contains('?') || alias.starts_with('!')
}

fn apply_directive(target: &mut PartialHost, key: &str, value: &str) {
    match key {
        "hostname" => {
            let parsed = trim_quotes(value);
            if !parsed.is_empty() {
                target.hostname = Some(parsed);
            }
        }
        "user" => {
            let parsed = trim_quotes(value);
            if !parsed.is_empty() {
                target.user = Some(parsed);
            }
        }
        "port" => {
            if let Ok(parsed) = value.trim().parse::<u16>() {
                target.port = Some(parsed);
            }
        }
        "identityfile" => {
            let parsed = trim_quotes(value);
            if !parsed.is_empty() {
                target.identity_file = Some(parsed);
            }
        }
        _ => {}
    }
}

fn finalize_block(
    hosts: &mut Vec<(Vec<String>, PartialHost)>,
    defaults: &mut PartialHost,
    current_aliases: &mut Vec<String>,
    current_host: &mut PartialHost,
    current_is_default: &mut bool,
) {
    if current_aliases.is_empty() {
        return;
    }

    if *current_is_default {
        defaults.merge_missing_from(current_host);
    } else {
        hosts.push((
            std::mem::take(current_aliases),
            std::mem::take(current_host),
        ));
    }

    current_aliases.clear();
    *current_host = PartialHost::default();
    *current_is_default = false;
}

pub fn load_ssh_hosts(raw_path: &str) -> Result<Vec<SshHostConfig>, SshConfigError> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return Err(SshConfigError::EmptyPath);
    }

    let resolved_path = paths::resolve_named_path(trimmed, "ssh config").map_err(|source| {
        SshConfigError::Resolve {
            raw: trimmed.to_string(),
            source,
        }
    })?;
    let content = fs::read_to_string(&resolved_path).map_err(|source| SshConfigError::Read {
        path: resolved_path.clone(),
        source,
    })?;

    let mut defaults = PartialHost::default();
    let mut hosts = Vec::new();
    let mut current_aliases = Vec::new();
    let mut current_host = PartialHost::default();
    let mut current_is_default = false;

    for raw_line in content.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        let Some((key, value)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();

        if key == "host" {
            finalize_block(
                &mut hosts,
                &mut defaults,
                &mut current_aliases,
                &mut current_host,
                &mut current_is_default,
            );

            current_aliases = value
                .split_whitespace()
                .map(trim_quotes)
                .filter(|alias| !alias.is_empty())
                .collect();
            current_is_default = current_aliases.len() == 1 && current_aliases[0] == "*";
            continue;
        }

        if current_aliases.is_empty() {
            apply_directive(&mut defaults, &key, value);
        } else {
            apply_directive(&mut current_host, &key, value);
        }
    }

    finalize_block(
        &mut hosts,
        &mut defaults,
        &mut current_aliases,
        &mut current_host,
        &mut current_is_default,
    );

    let fallback_user = std::env::var("USER")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let mut by_alias = BTreeMap::new();

    for (aliases, mut partial) in hosts {
        partial.apply_defaults(&defaults);

        for alias in aliases {
            if contains_pattern(&alias) {
                continue;
            }

            let user = partial.user.clone().or_else(|| fallback_user.clone());
            let Some(user) = user else {
                continue;
            };

            let hostname = partial.hostname.clone().unwrap_or_else(|| alias.clone());
            let identity_file = partial
                .identity_file
                .as_ref()
                .and_then(|path| paths::resolve_named_path(path, "ssh key").ok());

            by_alias.insert(
                alias.clone(),
                SshHostConfig {
                    alias,
                    hostname,
                    user,
                    port: partial.port.unwrap_or(22),
                    identity_file,
                },
            );
        }
    }

    Ok(by_alias.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_ssh_hosts_parses_defaults_and_multiple_aliases() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("id_ed25519");
        std::fs::write(&key_path, "dummy").unwrap();
        let cfg_path = tmp.path().join("config");
        std::fs::write(
            &cfg_path,
            format!(
                "Host *\n  User deploy\n  Port 2222\n  IdentityFile {}\n\nHost prod\n  HostName prod.example.com\n\nHost dev devbox\n  HostName 10.0.0.9\n  User alice\n",
                key_path.to_string_lossy()
            ),
        )
        .unwrap();

        let hosts = load_ssh_hosts(cfg_path.to_string_lossy().as_ref()).unwrap();
        assert_eq!(hosts.len(), 3);
        assert_eq!(hosts[0].alias, "dev");
        assert_eq!(hosts[0].user, "alice");
        assert_eq!(hosts[0].hostname, "10.0.0.9");
        assert_eq!(hosts[1].alias, "devbox");
        assert_eq!(hosts[1].port, 2222);
        assert_eq!(hosts[2].alias, "prod");
        assert_eq!(hosts[2].hostname, "prod.example.com");
        assert_eq!(
            hosts[2].identity_file.as_deref(),
            Some(key_path.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn load_ssh_hosts_skips_patterns_and_invalid_ports() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg_path = tmp.path().join("config");
        std::fs::write(
            &cfg_path,
            "Host wildcard-*\n  HostName ignored.example.com\n\nHost bad\n  HostName bad.example.com\n  Port nope\n\nHost ok\n  HostName ok.example.com\n  User deploy\n",
        )
        .unwrap();

        let hosts = load_ssh_hosts(cfg_path.to_string_lossy().as_ref()).unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].alias, "bad");
        assert_eq!(hosts[0].port, 22);
        assert_eq!(hosts[1].alias, "ok");
    }

    #[test]
    fn load_ssh_hosts_errors_when_file_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing-config");
        let error = load_ssh_hosts(missing.to_string_lossy().as_ref()).unwrap_err();
        assert!(matches!(error, SshConfigError::Read { .. }));
    }
}
