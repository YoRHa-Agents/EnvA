use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

use ssh2::{ErrorCode, RenameFlags, Session, Sftp};
use thiserror::Error;

use crate::{paths, vault::VaultStore};

const SFTP_FX_NO_SUCH_FILE: i32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteTarget {
    pub user: String,
    pub host: String,
    pub path: String,
    pub port: u16,
}

impl RemoteTarget {
    pub fn parse(raw: &str, port: u16) -> Result<Self, SyncError> {
        let trimmed = raw.trim();
        let (user_host, path) = trimmed
            .rsplit_once(':')
            .ok_or_else(|| SyncError::InvalidRemoteTarget(trimmed.to_owned()))?;
        let (user, host) = user_host
            .split_once('@')
            .ok_or_else(|| SyncError::InvalidRemoteTarget(trimmed.to_owned()))?;
        if user.trim().is_empty() || host.trim().is_empty() || path.trim().is_empty() {
            return Err(SyncError::InvalidRemoteTarget(trimmed.to_owned()));
        }

        Ok(Self {
            user: user.trim().to_owned(),
            host: host.trim().to_owned(),
            path: path.trim().to_owned(),
            port,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SshAuthOptions {
    pub password: Option<String>,
    pub key_path: Option<String>,
    pub passphrase: Option<String>,
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("Invalid remote target '{0}'. Use user@host:/path")]
    InvalidRemoteTarget(String),
    #[error("Remote vault already exists at {0}. Pass --overwrite to replace it.")]
    RemoteVaultExists(String),
    #[error("Remote vault not found at {0}")]
    RemoteVaultNotFound(String),
    #[error("Local vault already exists at {0}. Pass --overwrite to replace it.")]
    LocalVaultExists(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SSH error: {0}")]
    Ssh(String),
    #[error("Vault validation failed: {0}")]
    Vault(String),
}

pub trait RemoteVaultTransport {
    fn upload_vault(
        &self,
        target: &RemoteTarget,
        contents: &[u8],
        overwrite: bool,
    ) -> Result<(), SyncError>;

    fn download_vault(&self, target: &RemoteTarget) -> Result<Vec<u8>, SyncError>;
}

pub struct SftpTransport {
    auth: SshAuthOptions,
}

struct ConnectedSftp {
    _session: Session,
    sftp: Sftp,
}

impl SftpTransport {
    pub fn new(auth: SshAuthOptions) -> Self {
        Self { auth }
    }

    fn connect(&self, target: &RemoteTarget) -> Result<ConnectedSftp, SyncError> {
        let tcp = TcpStream::connect((target.host.as_str(), target.port))?;
        let mut session = Session::new().map_err(|e| SyncError::Ssh(e.to_string()))?;
        session.set_tcp_stream(tcp);
        session
            .handshake()
            .map_err(|e| SyncError::Ssh(e.to_string()))?;

        if let Some(password) = self.auth.password.as_deref() {
            session
                .userauth_password(&target.user, password)
                .map_err(|e| SyncError::Ssh(e.to_string()))?;
        } else if let Some(key_path) = self.auth.key_path.as_deref() {
            let resolved_key = paths::resolve_named_path(key_path, "ssh key")
                .map_err(|e| SyncError::Ssh(e.to_string()))?;
            session
                .userauth_pubkey_file(
                    &target.user,
                    None,
                    Path::new(&resolved_key),
                    self.auth.passphrase.as_deref(),
                )
                .map_err(|e| SyncError::Ssh(e.to_string()))?;
        } else {
            session
                .userauth_agent(&target.user)
                .map_err(|e| SyncError::Ssh(e.to_string()))?;
        }

        if !session.authenticated() {
            return Err(SyncError::Ssh("SSH authentication failed".into()));
        }

        let sftp = session.sftp().map_err(|e| SyncError::Ssh(e.to_string()))?;
        Ok(ConnectedSftp {
            _session: session,
            sftp,
        })
    }
}

impl RemoteVaultTransport for SftpTransport {
    fn upload_vault(
        &self,
        target: &RemoteTarget,
        contents: &[u8],
        overwrite: bool,
    ) -> Result<(), SyncError> {
        let connected = self.connect(target)?;
        let resolved = resolve_remote_path(&connected.sftp, &target.path)?;
        let remote_path = Path::new(&resolved);
        let file_exists = remote_exists(&connected.sftp, remote_path)?;
        if file_exists && !overwrite {
            return Err(SyncError::RemoteVaultExists(target.path.clone()));
        }

        ensure_remote_parent_dir(&connected.sftp, remote_path)?;

        let temp_path = remote_temp_path(&resolved);
        let temp_remote_path = Path::new(&temp_path);
        let mut remote_file = connected
            .sftp
            .create(temp_remote_path)
            .map_err(|e| SyncError::Ssh(e.to_string()))?;
        remote_file.write_all(contents)?;
        remote_file.flush()?;
        drop(remote_file);

        let rename_result = if overwrite {
            connected.sftp.rename(
                temp_remote_path,
                remote_path,
                Some(RenameFlags::OVERWRITE | RenameFlags::ATOMIC),
            )
        } else {
            connected
                .sftp
                .rename(temp_remote_path, remote_path, Some(RenameFlags::ATOMIC))
        };

        if let Err(first_error) = rename_result {
            if overwrite && file_exists {
                let _ = connected.sftp.unlink(remote_path);
                if let Err(retry_error) =
                    connected
                        .sftp
                        .rename(temp_remote_path, remote_path, Some(RenameFlags::ATOMIC))
                {
                    let _ = connected.sftp.unlink(temp_remote_path);
                    return Err(SyncError::Ssh(retry_error.to_string()));
                }
            } else {
                let _ = connected.sftp.unlink(temp_remote_path);
                return Err(SyncError::Ssh(first_error.to_string()));
            }
        }

        Ok(())
    }

    fn download_vault(&self, target: &RemoteTarget) -> Result<Vec<u8>, SyncError> {
        let connected = self.connect(target)?;
        let resolved = resolve_remote_path(&connected.sftp, &target.path)?;
        let mut remote_file = connected.sftp.open(Path::new(&resolved)).map_err(|error| {
            if is_sftp_not_found(&error) {
                SyncError::RemoteVaultNotFound(target.path.clone())
            } else {
                SyncError::Ssh(error.to_string())
            }
        })?;
        let mut bytes = Vec::new();
        remote_file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

pub fn upload_remote_vault_with_transport<T: RemoteVaultTransport>(
    transport: &T,
    remote_spec: &str,
    port: u16,
    overwrite: bool,
    contents: &[u8],
) -> Result<(), SyncError> {
    let target = RemoteTarget::parse(remote_spec, port)?;
    transport.upload_vault(&target, contents, overwrite)
}

pub fn deploy_vault_with_transport<T: RemoteVaultTransport>(
    transport: &T,
    local_vault_path: &str,
    vault_password: &str,
    remote_spec: &str,
    port: u16,
    overwrite: bool,
) -> Result<(), SyncError> {
    validate_local_vault(local_vault_path, vault_password)?;
    let target = RemoteTarget::parse(remote_spec, port)?;
    let contents = std::fs::read(local_vault_path)?;
    transport.upload_vault(&target, &contents, overwrite)
}

pub fn sync_from_remote_with_transport<T: RemoteVaultTransport>(
    transport: &T,
    local_vault_path: &str,
    vault_password: &str,
    remote_spec: &str,
    port: u16,
    overwrite: bool,
) -> Result<(), SyncError> {
    let target = RemoteTarget::parse(remote_spec, port)?;
    let local_path = Path::new(local_vault_path);
    if local_path.exists() && !overwrite {
        return Err(SyncError::LocalVaultExists(local_vault_path.to_owned()));
    }

    let contents = transport.download_vault(&target)?;
    if let Some(parent) = local_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let temp_dir = local_path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = tempfile::NamedTempFile::new_in(temp_dir)?;
    temp_file.write_all(&contents)?;
    temp_file.flush()?;

    validate_local_vault(temp_file.path().to_string_lossy().as_ref(), vault_password)?;

    temp_file
        .persist(local_path)
        .map_err(|e| SyncError::Io(e.error))?;
    Ok(())
}

pub fn deploy_vault(
    local_vault_path: &str,
    vault_password: &str,
    remote_spec: &str,
    port: u16,
    overwrite: bool,
    auth: SshAuthOptions,
) -> Result<(), SyncError> {
    let transport = SftpTransport::new(auth);
    deploy_vault_with_transport(
        &transport,
        local_vault_path,
        vault_password,
        remote_spec,
        port,
        overwrite,
    )
}

pub fn sync_from_remote(
    local_vault_path: &str,
    vault_password: &str,
    remote_spec: &str,
    port: u16,
    overwrite: bool,
    auth: SshAuthOptions,
) -> Result<(), SyncError> {
    let transport = SftpTransport::new(auth);
    sync_from_remote_with_transport(
        &transport,
        local_vault_path,
        vault_password,
        remote_spec,
        port,
        overwrite,
    )
}

pub fn upload_remote_vault(
    remote_spec: &str,
    port: u16,
    overwrite: bool,
    auth: SshAuthOptions,
    contents: &[u8],
) -> Result<(), SyncError> {
    let transport = SftpTransport::new(auth);
    upload_remote_vault_with_transport(&transport, remote_spec, port, overwrite, contents)
}

pub fn download_remote_vault(
    remote_spec: &str,
    port: u16,
    auth: SshAuthOptions,
) -> Result<Vec<u8>, SyncError> {
    let target = RemoteTarget::parse(remote_spec, port)?;
    let transport = SftpTransport::new(auth);
    transport.download_vault(&target)
}

fn validate_local_vault(local_vault_path: &str, vault_password: &str) -> Result<(), SyncError> {
    VaultStore::load(local_vault_path, vault_password)
        .map(|_| ())
        .map_err(|e| SyncError::Vault(e.to_string()))
}

fn resolve_remote_path(sftp: &Sftp, remote_path: &str) -> Result<String, SyncError> {
    if !remote_path.starts_with('~') {
        return Ok(remote_path.to_owned());
    }
    let home = sftp
        .realpath(Path::new("."))
        .map_err(|e| SyncError::Ssh(format!("failed to resolve remote home directory: {e}")))?;
    Ok(expand_remote_tilde(remote_path, &home.to_string_lossy()))
}

pub(crate) fn expand_remote_tilde(remote_path: &str, home_dir: &str) -> String {
    if remote_path == "~" {
        home_dir.to_owned()
    } else if let Some(rest) = remote_path.strip_prefix("~/") {
        format!("{}/{rest}", home_dir.trim_end_matches('/'))
    } else {
        remote_path.to_owned()
    }
}

fn is_sftp_not_found(error: &ssh2::Error) -> bool {
    matches!(error.code(), ErrorCode::SFTP(SFTP_FX_NO_SUCH_FILE))
}

fn remote_exists(sftp: &Sftp, remote_path: &Path) -> Result<bool, SyncError> {
    match sftp.stat(remote_path) {
        Ok(_) => Ok(true),
        Err(error) if is_sftp_not_found(&error) => Ok(false),
        Err(error) => Err(SyncError::Ssh(error.to_string())),
    }
}

fn ensure_remote_parent_dir(sftp: &Sftp, remote_path: &Path) -> Result<(), SyncError> {
    let parent = match remote_path.parent() {
        Some(p) if !p.as_os_str().is_empty() && p != Path::new("/") => p,
        _ => return Ok(()),
    };

    if remote_exists(sftp, parent)? {
        return Ok(());
    }

    let mut ancestors: Vec<&Path> = Vec::new();
    let mut current = parent;
    loop {
        if remote_exists(sftp, current)? {
            break;
        }
        ancestors.push(current);
        match current.parent() {
            Some(p) if !p.as_os_str().is_empty() && p != Path::new("/") => current = p,
            _ => break,
        }
    }

    for dir in ancestors.into_iter().rev() {
        sftp.mkdir(dir, 0o755).map_err(|e| {
            SyncError::Ssh(format!(
                "failed to create remote directory '{}': {e}",
                dir.display()
            ))
        })?;
    }
    Ok(())
}

fn remote_temp_path(remote_path: &str) -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{remote_path}.enva-upload-{stamp}.tmp")
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct FakeTransport {
        uploaded: Mutex<Vec<u8>>,
        upload_result: Mutex<Option<Result<(), SyncError>>>,
        download_result: Mutex<Option<Result<Vec<u8>, SyncError>>>,
    }

    impl RemoteVaultTransport for FakeTransport {
        fn upload_vault(
            &self,
            _target: &RemoteTarget,
            contents: &[u8],
            _overwrite: bool,
        ) -> Result<(), SyncError> {
            self.uploaded.lock().unwrap().clear();
            self.uploaded.lock().unwrap().extend_from_slice(contents);
            self.upload_result.lock().unwrap().take().unwrap_or(Ok(()))
        }

        fn download_vault(&self, _target: &RemoteTarget) -> Result<Vec<u8>, SyncError> {
            self.download_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Ok(Vec::new()))
        }
    }

    fn create_test_vault(path: &Path, password: &str) -> Vec<u8> {
        let vault_path = path.to_string_lossy().to_string();
        VaultStore::create(&vault_path, password, None).unwrap();
        std::fs::read(path).unwrap()
    }

    #[test]
    fn remote_target_parse_requires_user_host_and_path() {
        assert!(RemoteTarget::parse("host:/vault.json", 22).is_err());
        assert!(RemoteTarget::parse("user@host", 22).is_err());
        assert!(RemoteTarget::parse("user@host:/vault.json", 22).is_ok());
    }

    #[test]
    fn deploy_vault_with_transport_uploads_validated_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let vault_path = tmp.path().join("deploy.vault.json");
        let expected = create_test_vault(&vault_path, "testpass1234");
        let transport = FakeTransport::default();

        deploy_vault_with_transport(
            &transport,
            vault_path.to_string_lossy().as_ref(),
            "testpass1234",
            "user@example:/vaults/prod.json",
            22,
            false,
        )
        .unwrap();

        assert_eq!(*transport.uploaded.lock().unwrap(), expected);
    }

    #[test]
    fn upload_remote_vault_with_transport_sends_raw_contents() {
        let transport = FakeTransport::default();
        upload_remote_vault_with_transport(
            &transport,
            "user@example:/vaults/prod.json",
            22,
            true,
            b"raw-vault-bytes",
        )
        .unwrap();

        assert_eq!(*transport.uploaded.lock().unwrap(), b"raw-vault-bytes");
    }

    #[test]
    fn deploy_vault_with_transport_rejects_invalid_password() {
        let tmp = tempfile::tempdir().unwrap();
        let vault_path = tmp.path().join("deploy-invalid.vault.json");
        create_test_vault(&vault_path, "testpass1234");
        let transport = FakeTransport::default();

        let error = deploy_vault_with_transport(
            &transport,
            vault_path.to_string_lossy().as_ref(),
            "wrongpass",
            "user@example:/vaults/prod.json",
            22,
            false,
        )
        .unwrap_err();
        assert!(matches!(error, SyncError::Vault(_)));
    }

    #[test]
    fn sync_from_remote_with_transport_writes_and_validates_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let source_path = tmp.path().join("remote-source.vault.json");
        let source_bytes = create_test_vault(&source_path, "testpass1234");
        let local_path = tmp.path().join("synced.vault.json");
        let transport = FakeTransport::default();
        *transport.download_result.lock().unwrap() = Some(Ok(source_bytes));

        sync_from_remote_with_transport(
            &transport,
            local_path.to_string_lossy().as_ref(),
            "testpass1234",
            "user@example:/vaults/prod.json",
            22,
            false,
        )
        .unwrap();

        assert!(local_path.exists());
        VaultStore::load(local_path.to_string_lossy().as_ref(), "testpass1234").unwrap();
    }

    #[test]
    fn expand_remote_tilde_replaces_leading_tilde() {
        assert_eq!(
            expand_remote_tilde("~/.enva/vault.json", "/home/alice"),
            "/home/alice/.enva/vault.json"
        );
    }

    #[test]
    fn expand_remote_tilde_handles_bare_tilde() {
        assert_eq!(expand_remote_tilde("~", "/home/alice"), "/home/alice");
    }

    #[test]
    fn expand_remote_tilde_ignores_absolute_path() {
        assert_eq!(
            expand_remote_tilde("/opt/vault.json", "/home/alice"),
            "/opt/vault.json"
        );
    }

    #[test]
    fn expand_remote_tilde_ignores_relative_path() {
        assert_eq!(
            expand_remote_tilde("data/vault.json", "/home/alice"),
            "data/vault.json"
        );
    }

    #[test]
    fn expand_remote_tilde_strips_trailing_slash_from_home() {
        assert_eq!(
            expand_remote_tilde("~/.enva/vault.json", "/root/"),
            "/root/.enva/vault.json"
        );
    }

    #[test]
    fn expand_remote_tilde_preserves_other_user_tilde() {
        assert_eq!(
            expand_remote_tilde("~bob/.enva/vault.json", "/home/alice"),
            "~bob/.enva/vault.json"
        );
    }

    #[test]
    fn sync_from_remote_with_transport_rejects_existing_file_without_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let local_path = tmp.path().join("existing.vault.json");
        std::fs::write(&local_path, b"already here").unwrap();
        let transport = FakeTransport::default();

        let error = sync_from_remote_with_transport(
            &transport,
            local_path.to_string_lossy().as_ref(),
            "testpass1234",
            "user@example:/vaults/prod.json",
            22,
            false,
        )
        .unwrap_err();
        assert!(matches!(error, SyncError::LocalVaultExists(_)));
    }
}
