//! Five-layer YAML config merge for Enva.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub shell: ShellConfig,
    #[serde(default)]
    pub web: WebConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub vault_path: Option<String>,
    #[serde(default)]
    pub default_app: Option<String>,
    #[serde(default)]
    pub apps: BTreeMap<String, AppConfig>,
}

fn default_version() -> String {
    "1".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Defaults {
    #[serde(default = "default_vault_path")]
    pub vault_path: String,
    #[serde(default = "default_timeout")]
    pub password_timeout: u64,
    #[serde(default = "default_cache")]
    pub password_cache: String,
    #[serde(default)]
    pub kdf: KdfConfig,
}

fn default_vault_path() -> String {
    "~/.enva/vault.json".into()
}
fn default_timeout() -> u64 {
    300
}
fn default_cache() -> String {
    "memory".into()
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            vault_path: default_vault_path(),
            password_timeout: default_timeout(),
            password_cache: default_cache(),
            kdf: KdfConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfConfig {
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    #[serde(default = "default_memory")]
    pub memory_cost: u32,
    #[serde(default = "default_time")]
    pub time_cost: u32,
    #[serde(default = "default_parallelism")]
    pub parallelism: u32,
}

fn default_algorithm() -> String {
    "argon2id".into()
}
fn default_memory() -> u32 {
    65536
}
fn default_time() -> u32 {
    3
}
fn default_parallelism() -> u32 {
    4
}

impl Default for KdfConfig {
    fn default() -> Self {
        Self {
            algorithm: default_algorithm(),
            memory_cost: default_memory(),
            time_cost: default_time(),
            parallelism: default_parallelism(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShellConfig {
    #[serde(default)]
    pub default_mode: Option<String>,
    #[serde(default)]
    pub auto_inject: bool,
    #[serde(default = "default_true")]
    pub history_protection: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_timeout_web")]
    pub session_timeout: u64,
}

fn default_host() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    8080
}
fn default_timeout_web() -> u64 {
    1800
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            session_timeout: default_timeout_web(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default)]
    pub audit_file: Option<String>,
    #[serde(default = "default_true")]
    pub redact_values: bool,
}

fn default_level() -> String {
    "warning".into()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_level(),
            audit_file: None,
            redact_values: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub app_path: String,
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(default)]
    pub overrides: BTreeMap<String, String>,
    #[serde(default)]
    pub override_system: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: default_version(),
            defaults: Defaults::default(),
            shell: ShellConfig::default(),
            web: WebConfig::default(),
            logging: LoggingConfig::default(),
            vault_path: None,
            default_app: None,
            apps: BTreeMap::new(),
        }
    }
}

pub struct ConfigLoader;

impl ConfigLoader {
    pub fn load(config_path: Option<&str>, env_name: Option<&str>) -> Config {
        let mut config = Config::default();

        if let Some(global) = Self::load_yaml(&Self::global_config_path()) {
            config = Config::merge(config, global);
        }

        if let Some(project_path) = Self::discover_project_config() {
            if let Some(project) = Self::load_yaml(&project_path) {
                config = Config::merge(config, project);
            }
            if let Some(env) = env_name {
                let env_path = project_path.with_file_name(format!(".enva.{env}.yaml"));
                if let Some(env_cfg) = Self::load_yaml(&env_path) {
                    config = Config::merge(config, env_cfg);
                }
            }
        }

        if let Some(p) = config_path {
            if let Some(custom) = Self::load_yaml(&PathBuf::from(p)) {
                config = Config::merge(config, custom);
            }
        }

        if let Ok(vp) = std::env::var("ENVA_VAULT_PATH") {
            config.vault_path = Some(vp);
        }
        if let Ok(app) = std::env::var("ENVA_APP") {
            config.default_app = Some(app);
        }

        config
    }

    fn global_config_path() -> PathBuf {
        if let Ok(p) = std::env::var("ENVA_CONFIG_DIR") {
            return PathBuf::from(p).join("config.yaml");
        }
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let enva_dir = home.join(".enva");
        if enva_dir.is_dir() {
            return enva_dir.join("config.yaml");
        }
        if let Some(config_dir) = dirs::config_dir() {
            let xdg = config_dir.join("enva").join("config.yaml");
            if xdg.exists() {
                return xdg;
            }
        }
        enva_dir.join("config.yaml")
    }

    fn discover_project_config() -> Option<PathBuf> {
        let mut current = std::env::current_dir().ok()?;
        let home = dirs::home_dir();
        loop {
            let candidate = current.join(".enva.yaml");
            if candidate.is_file() {
                return Some(candidate);
            }
            if Some(&current) == home.as_ref() || !current.pop() {
                break;
            }
        }
        None
    }

    fn load_yaml(path: &Path) -> Option<Config> {
        let content = std::fs::read_to_string(path).ok()?;
        match serde_yaml::from_str(&content) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                tracing::warn!("failed to parse config {}: {}", path.display(), e);
                None
            }
        }
    }

    fn merge(base: Config, overlay: Config) -> Config {
        let defaults_changed_vault = overlay.defaults.vault_path != default_vault_path();
        let defaults_changed_timeout = overlay.defaults.password_timeout != default_timeout();
        let defaults_changed_cache = overlay.defaults.password_cache != default_cache();
        let defaults_changed_kdf = overlay.defaults.kdf.algorithm != default_algorithm()
            || overlay.defaults.kdf.memory_cost != default_memory()
            || overlay.defaults.kdf.time_cost != default_time()
            || overlay.defaults.kdf.parallelism != default_parallelism();

        Config {
            version: if overlay.version != "1" {
                overlay.version
            } else {
                base.version
            },
            defaults: Defaults {
                vault_path: if defaults_changed_vault {
                    overlay.defaults.vault_path
                } else {
                    base.defaults.vault_path
                },
                password_timeout: if defaults_changed_timeout {
                    overlay.defaults.password_timeout
                } else {
                    base.defaults.password_timeout
                },
                password_cache: if defaults_changed_cache {
                    overlay.defaults.password_cache
                } else {
                    base.defaults.password_cache
                },
                kdf: if defaults_changed_kdf {
                    overlay.defaults.kdf
                } else {
                    base.defaults.kdf
                },
            },
            shell: if overlay.shell.default_mode.is_some() || overlay.shell.auto_inject {
                overlay.shell
            } else {
                base.shell
            },
            web: if overlay.web.host != default_host()
                || overlay.web.port != default_port()
                || overlay.web.session_timeout != default_timeout_web()
            {
                overlay.web
            } else {
                base.web
            },
            logging: if overlay.logging.level != default_level()
                || overlay.logging.audit_file.is_some()
            {
                overlay.logging
            } else {
                base.logging
            },
            vault_path: overlay
                .vault_path
                .filter(|s| !s.is_empty())
                .or(base.vault_path),
            default_app: overlay
                .default_app
                .filter(|s| !s.is_empty())
                .or(base.default_app),
            apps: {
                let mut merged = base.apps;
                merged.extend(overlay.apps);
                merged
            },
        }
    }
}

impl Config {
    pub fn merge(base: Config, overlay: Config) -> Config {
        ConfigLoader::merge(base, overlay)
    }

    pub fn resolve_vault_path(&self) -> String {
        let raw = self
            .vault_path
            .as_deref()
            .unwrap_or(&self.defaults.vault_path);
        shellexpand::tilde(raw).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let cfg = Config::default();
        assert_eq!(cfg.version, "1");
        assert!(cfg.defaults.vault_path.contains(".enva"));
        assert_eq!(cfg.defaults.password_timeout, 300);
        assert_eq!(cfg.defaults.password_cache, "memory");
        assert_eq!(cfg.web.port, 8080);
        assert_eq!(cfg.web.host, "127.0.0.1");
        assert!(cfg.apps.is_empty());
    }

    #[test]
    fn merge_empty_vault_path_falls_back() {
        let base = Config {
            vault_path: Some("~/.enva/vault.json".into()),
            ..Config::default()
        };
        let overlay = Config {
            vault_path: Some("".into()),
            ..Config::default()
        };
        let merged = Config::merge(base, overlay);
        assert_eq!(merged.vault_path, Some("~/.enva/vault.json".into()));
    }

    #[test]
    fn resolve_vault_path_expands_tilde() {
        let cfg = Config::default();
        let resolved = cfg.resolve_vault_path();
        assert!(!resolved.contains('~'));
        assert!(resolved.contains(".enva"));
        assert!(resolved.contains("vault.json"));
    }

    #[test]
    fn resolve_vault_path_uses_override() {
        let mut cfg = Config::default();
        cfg.vault_path = Some("/tmp/my-vault.json".to_owned());
        assert_eq!(cfg.resolve_vault_path(), "/tmp/my-vault.json");
    }

    #[test]
    fn load_with_no_files_returns_defaults() {
        let cfg = ConfigLoader::load(None, None);
        assert_eq!(cfg.version, "1");
        assert!(cfg.defaults.vault_path.contains(".enva"));
    }

    #[test]
    fn load_with_explicit_config_path() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg_path = tmp.path().join("custom.yaml");
        std::fs::write(
            &cfg_path,
            "vault_path: /custom/vault.json\ndefault_app: myapp\n",
        )
        .unwrap();
        let cfg = ConfigLoader::load(Some(cfg_path.to_str().unwrap()), None);
        assert_eq!(cfg.vault_path, Some("/custom/vault.json".to_owned()));
        assert_eq!(cfg.default_app, Some("myapp".to_owned()));
    }

    #[test]
    fn env_var_overrides_vault_path() {
        std::env::set_var("ENVA_VAULT_PATH", "/env/override.json");
        let cfg = ConfigLoader::load(None, None);
        std::env::remove_var("ENVA_VAULT_PATH");
        assert_eq!(cfg.vault_path, Some("/env/override.json".to_owned()));
    }

    #[test]
    fn env_var_overrides_app() {
        std::env::set_var("ENVA_APP", "from-env");
        let cfg = ConfigLoader::load(None, None);
        std::env::remove_var("ENVA_APP");
        assert_eq!(cfg.default_app, Some("from-env".to_owned()));
    }

    #[test]
    fn kdf_config_defaults() {
        let kdf = KdfConfig::default();
        assert_eq!(kdf.algorithm, "argon2id");
        assert_eq!(kdf.memory_cost, 65536);
        assert_eq!(kdf.time_cost, 3);
        assert_eq!(kdf.parallelism, 4);
    }

    #[test]
    fn load_yaml_valid_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.yaml");
        std::fs::write(&path, "version: '2'\n").unwrap();
        let loaded = ConfigLoader::load_yaml(&path);
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().version, "2");
    }

    #[test]
    fn load_yaml_missing_file_returns_none() {
        let result = ConfigLoader::load_yaml(&PathBuf::from("/nonexistent/path.yaml"));
        assert!(result.is_none());
    }
}
