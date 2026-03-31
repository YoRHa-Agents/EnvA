use std::path::Path;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PathResolutionError {
    #[error("{kind} path cannot be empty")]
    Empty { kind: &'static str },
    #[error(
        "Failed to determine the current directory while resolving {kind} path '{raw}': {source}"
    )]
    CurrentDirectory {
        kind: &'static str,
        raw: String,
        #[source]
        source: std::io::Error,
    },
}

pub fn resolve_vault_path(raw: &str) -> Result<String, PathResolutionError> {
    resolve_named_path(raw, "vault")
}

pub fn resolve_app_path(raw: &str) -> Result<String, PathResolutionError> {
    resolve_named_path(raw, "application")
}

pub fn resolve_optional_app_path(raw: &str) -> Result<Option<String>, PathResolutionError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    resolve_app_path(trimmed).map(Some)
}

pub(crate) fn resolve_required_path_from(
    raw: &str,
    cwd: &Path,
    kind: &'static str,
) -> Result<String, PathResolutionError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(PathResolutionError::Empty { kind });
    }

    let expanded = normalize_known_path_aliases(shellexpand::tilde(trimmed).as_ref());
    let path = Path::new(&expanded);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };

    Ok(resolved.to_string_lossy().into_owned())
}

fn normalize_known_path_aliases(raw: &str) -> String {
    if let Some(rest) = raw.strip_prefix("/User/") {
        if let Some(home) = dirs::home_dir() {
            if let Some(user) = home.file_name().and_then(|value| value.to_str()) {
                let home_str = home.to_string_lossy();
                if home_str.starts_with("/Users/")
                    && (rest == user || rest.starts_with(&format!("{user}/")))
                {
                    return format!("/Users/{rest}");
                }
            }
        }
    }

    raw.to_owned()
}

fn resolve_required_path(raw: &str, kind: &'static str) -> Result<String, PathResolutionError> {
    let cwd = std::env::current_dir().map_err(|source| PathResolutionError::CurrentDirectory {
        kind,
        raw: raw.trim().to_owned(),
        source,
    })?;
    resolve_required_path_from(raw, &cwd, kind)
}

pub fn resolve_named_path(raw: &str, kind: &'static str) -> Result<String, PathResolutionError> {
    resolve_required_path(raw, kind)
}

#[cfg(test)]
pub(crate) fn process_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn resolve_vault_path_expands_tilde() {
        let home = dirs::home_dir().unwrap();
        let resolved = resolve_vault_path("~/vault.json").unwrap();
        assert_eq!(resolved, home.join("vault.json").to_string_lossy());
    }

    #[test]
    fn resolve_required_path_from_resolves_relative_against_cwd() {
        let resolved =
            resolve_required_path_from("./vaults/dev.json", Path::new("/tmp/enva"), "vault")
                .unwrap();
        assert_eq!(resolved, "/tmp/enva/./vaults/dev.json");
    }

    #[test]
    fn resolve_optional_app_path_returns_none_for_blank_values() {
        assert_eq!(resolve_optional_app_path("   ").unwrap(), None);
    }

    #[test]
    fn resolve_app_path_rejects_blank_values() {
        let error = resolve_app_path(" ").unwrap_err();
        assert!(matches!(
            error,
            PathResolutionError::Empty {
                kind: "application"
            }
        ));
    }

    #[test]
    fn resolve_required_path_from_keeps_absolute_paths() {
        let resolved =
            resolve_required_path_from("/opt/enva/app", Path::new("/tmp/enva"), "application")
                .unwrap();
        assert_eq!(resolved, PathBuf::from("/opt/enva/app").to_string_lossy());
    }

    #[test]
    fn resolve_required_path_from_normalizes_common_user_prefix_typo() {
        let _lock = process_lock().lock().unwrap_or_else(|e| e.into_inner());
        let original_home = std::env::var_os("HOME");
        std::env::set_var("HOME", "/Users/alice");

        let resolved =
            resolve_required_path_from("/User/alice/.enva/vault.json", Path::new("/tmp"), "vault")
                .unwrap();

        match original_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }

        assert_eq!(resolved, "/Users/alice/.enva/vault.json");
    }
}
