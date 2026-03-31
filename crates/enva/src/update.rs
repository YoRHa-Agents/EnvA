use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use reqwest::blocking::Client;
use reqwest::header::ACCEPT;
use semver::Version;
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

const API_BASE: &str = "https://api.github.com";
const RELEASE_REPO: &str = "YoRHa-Agents/EnvA";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize)]
pub struct UpdateCheck {
    pub current_version: String,
    pub target_version: String,
    pub release_url: String,
    pub asset_name: String,
    pub needs_update: bool,
}

#[derive(Debug, Clone)]
pub struct UpdateResult {
    pub updated_version: String,
}

#[derive(Debug, Clone)]
pub enum UpdateOutcome {
    Updated(UpdateResult),
    AlreadyUpToDate { current_version: String },
}

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("unsupported platform '{os}-{arch}' for self-update")]
    UnsupportedPlatform { os: String, arch: String },
    #[error("failed to contact GitHub Releases API: {source}")]
    Network {
        #[source]
        source: reqwest::Error,
    },
    #[error("release not found: {tag}")]
    ReleaseNotFound { tag: String },
    #[error("GitHub API returned {status} for {url}")]
    ApiStatus { status: u16, url: String },
    #[error("release {tag} does not contain asset '{asset_name}'")]
    AssetMissing { tag: String, asset_name: String },
    #[error("download verification failed: {details}")]
    Verification { details: String },
    #[error("refusing to downgrade from {current} to {target} without --force")]
    DowngradeRequiresForce { current: String, target: String },
    #[error("failed to replace '{path}': permission denied ({source})")]
    PermissionDenied {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("I/O error while updating '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid release payload: {details}")]
    InvalidPayload { details: String },
}

impl UpdateError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Network { .. } | Self::ApiStatus { .. } => 4,
            Self::ReleaseNotFound { .. } => 5,
            Self::AssetMissing { .. } => 6,
            Self::PermissionDenied { .. } => 7,
            Self::Verification { .. } => 8,
            Self::UnsupportedPlatform { .. }
            | Self::DowngradeRequiresForce { .. }
            | Self::InvalidPayload { .. }
            | Self::Io { .. } => 1,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    size: u64,
    #[serde(default)]
    digest: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct Release {
    tag_name: String,
    html_url: String,
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Clone)]
struct ResolvedRelease {
    release: Release,
    asset: ReleaseAsset,
    current_version: Version,
    target_version: Version,
}

pub fn check_for_update(version: Option<&str>) -> Result<UpdateCheck, UpdateError> {
    let resolved = resolve_release(version)?;
    Ok(UpdateCheck {
        current_version: format_version(&resolved.current_version),
        target_version: format_version(&resolved.target_version),
        release_url: resolved.release.html_url,
        asset_name: resolved.asset.name,
        needs_update: resolved.target_version > resolved.current_version,
    })
}

pub fn update_binary(version: Option<&str>, force: bool) -> Result<UpdateOutcome, UpdateError> {
    let resolved = resolve_release(version)?;
    if !force {
        if resolved.target_version == resolved.current_version {
            return Ok(UpdateOutcome::AlreadyUpToDate {
                current_version: format_version(&resolved.current_version),
            });
        }
        if resolved.target_version < resolved.current_version {
            return Err(UpdateError::DowngradeRequiresForce {
                current: format_version(&resolved.current_version),
                target: format_version(&resolved.target_version),
            });
        }
    }

    let client = http_client()?;
    let bytes = download_asset(&client, &resolved.asset)?;
    let binary_path = current_executable_path()?;
    atomically_replace_binary(&binary_path, &bytes)?;

    Ok(UpdateOutcome::Updated(UpdateResult {
        updated_version: format_version(&resolved.target_version),
    }))
}

fn resolve_release(version: Option<&str>) -> Result<ResolvedRelease, UpdateError> {
    let client = http_client()?;
    let asset_name = platform_asset_name()?;
    let current_version = parse_version(CURRENT_VERSION)?;
    let requested_tag = version.map(normalize_tag);
    let release = if let Some(ref tag) = requested_tag {
        fetch_release_by_tag(&client, tag)?
    } else {
        fetch_latest_release(&client)?
    };
    let target_version = parse_tag_version(&release.tag_name)?;
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == asset_name)
        .cloned()
        .ok_or_else(|| UpdateError::AssetMissing {
            tag: release.tag_name.clone(),
            asset_name: asset_name.clone(),
        })?;

    Ok(ResolvedRelease {
        release,
        asset,
        current_version,
        target_version,
    })
}

fn fetch_latest_release(client: &Client) -> Result<Release, UpdateError> {
    let url = format!("{}/repos/{RELEASE_REPO}/releases/latest", api_base());
    fetch_release(client, &url, "latest".to_string())
}

fn fetch_release_by_tag(client: &Client, tag: &str) -> Result<Release, UpdateError> {
    let url = format!("{}/repos/{RELEASE_REPO}/releases/tags/{tag}", api_base());
    fetch_release(client, &url, tag.to_string())
}

fn fetch_release(client: &Client, url: &str, tag: String) -> Result<Release, UpdateError> {
    let response = client
        .get(url)
        .send()
        .map_err(|source| UpdateError::Network { source })?;

    if response.status().as_u16() == 404 {
        return Err(UpdateError::ReleaseNotFound { tag });
    }
    if !response.status().is_success() {
        return Err(UpdateError::ApiStatus {
            status: response.status().as_u16(),
            url: url.to_string(),
        });
    }

    response
        .json::<Release>()
        .map_err(|err| UpdateError::InvalidPayload {
            details: err.to_string(),
        })
}

fn download_asset(client: &Client, asset: &ReleaseAsset) -> Result<Vec<u8>, UpdateError> {
    let response = client
        .get(&asset.browser_download_url)
        .header(ACCEPT, "application/octet-stream")
        .send()
        .map_err(|source| UpdateError::Network { source })?;

    if !response.status().is_success() {
        return Err(UpdateError::ApiStatus {
            status: response.status().as_u16(),
            url: asset.browser_download_url.clone(),
        });
    }

    let bytes = response
        .bytes()
        .map_err(|source| UpdateError::Network { source })?;
    if bytes.len() as u64 != asset.size {
        return Err(UpdateError::Verification {
            details: format!(
                "expected {} bytes for {}, downloaded {} bytes",
                asset.size,
                asset.name,
                bytes.len(),
            ),
        });
    }

    if let Some(digest) = asset.digest.as_deref() {
        verify_digest(&bytes, digest)?;
    }

    Ok(bytes.to_vec())
}

fn verify_digest(bytes: &[u8], digest: &str) -> Result<(), UpdateError> {
    let Some(expected) = digest.strip_prefix("sha256:") else {
        return Err(UpdateError::Verification {
            details: format!("unsupported digest format '{digest}'"),
        });
    };

    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut actual = String::with_capacity(expected.len());
    for byte in hasher.finalize() {
        let _ = write!(&mut actual, "{byte:02x}");
    }

    if actual != expected {
        return Err(UpdateError::Verification {
            details: format!("sha256 mismatch (expected {expected}, got {actual})"),
        });
    }

    Ok(())
}

fn atomically_replace_binary(target_path: &Path, bytes: &[u8]) -> Result<(), UpdateError> {
    let target_display = target_path.display().to_string();
    let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| map_io_error(target_display.clone(), source))?;

    let permissions = fs::metadata(target_path)
        .map(|metadata| metadata.permissions())
        .map_err(|source| map_io_error(target_display.clone(), source))?;

    let mut temp_file = tempfile::NamedTempFile::new_in(parent)
        .map_err(|source| map_io_error(target_display.clone(), source))?;
    temp_file
        .write_all(bytes)
        .map_err(|source| map_io_error(target_display.clone(), source))?;
    temp_file
        .flush()
        .map_err(|source| map_io_error(target_display.clone(), source))?;
    fs::set_permissions(temp_file.path(), permissions)
        .map_err(|source| map_io_error(target_display.clone(), source))?;

    temp_file
        .persist(target_path)
        .map_err(|error| map_io_error(target_display, error.error))?;
    Ok(())
}

fn map_io_error(path: String, source: std::io::Error) -> UpdateError {
    if source.kind() == std::io::ErrorKind::PermissionDenied {
        UpdateError::PermissionDenied { path, source }
    } else {
        UpdateError::Io { path, source }
    }
}

fn http_client() -> Result<Client, UpdateError> {
    Client::builder()
        .user_agent(format!("enva/{CURRENT_VERSION}"))
        .build()
        .map_err(|source| UpdateError::Network { source })
}

fn api_base() -> String {
    std::env::var("ENVA_UPDATE_API_BASE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| API_BASE.to_string())
        .trim_end_matches('/')
        .to_string()
}

fn current_executable_path() -> Result<PathBuf, UpdateError> {
    if let Some(path) = std::env::var_os("ENVA_UPDATE_BIN_PATH") {
        return Ok(PathBuf::from(path));
    }

    std::env::current_exe().map_err(|source| UpdateError::Io {
        path: "<current-exe>".into(),
        source,
    })
}

fn platform_asset_name() -> Result<String, UpdateError> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let asset = match (os, arch) {
        ("linux", "x86_64") => "enva-linux-x86_64",
        ("linux", "aarch64") => "enva-linux-aarch64",
        ("macos", "aarch64") => "enva-macos-aarch64",
        _ => {
            return Err(UpdateError::UnsupportedPlatform {
                os: os.to_string(),
                arch: arch.to_string(),
            });
        }
    };

    Ok(asset.to_string())
}

fn normalize_tag(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with('v') {
        trimmed.to_string()
    } else {
        format!("v{trimmed}")
    }
}

fn parse_tag_version(tag: &str) -> Result<Version, UpdateError> {
    parse_version(tag.strip_prefix('v').unwrap_or(tag))
}

fn parse_version(raw: &str) -> Result<Version, UpdateError> {
    Version::parse(raw).map_err(|err| UpdateError::InvalidPayload {
        details: format!("invalid version '{raw}': {err}"),
    })
}

fn format_version(version: &Version) -> String {
    format!("v{version}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_tag_adds_prefix_when_missing() {
        assert_eq!(normalize_tag("0.3.0"), "v0.3.0");
    }

    #[test]
    fn normalize_tag_keeps_existing_prefix() {
        assert_eq!(normalize_tag("v0.3.0"), "v0.3.0");
    }

    #[test]
    fn verify_digest_accepts_matching_sha256() {
        verify_digest(
            b"abc",
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .unwrap();
    }

    #[test]
    fn verify_digest_rejects_mismatched_sha256() {
        let error = verify_digest(
            b"abc",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert!(matches!(error, UpdateError::Verification { .. }));
    }

    #[test]
    fn platform_asset_name_matches_supported_linux_x86_64() {
        if std::env::consts::OS == "linux" && std::env::consts::ARCH == "x86_64" {
            assert_eq!(platform_asset_name().unwrap(), "enva-linux-x86_64");
        }
    }
}
