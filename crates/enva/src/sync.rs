use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

use ssh2::{RenameFlags, Session, Sftp};
use thiserror::Error;

use crate::{paths, vault::VaultStore};

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
        let remote_path = Path::new(&target.path);
        if remote_exists(&connected.sftp, remote_path)? && !overwrite {
            return Err(SyncError::RemoteVaultExists(target.path.clone()));
        }

        let temp_path = remote_temp_path(&target.path);
        let temp_remote_path = Path::new(&temp_path);
        let mut remote_file = connected
            .sftp
            .create(temp_remote_path)
            .map_err(|e| SyncError::Ssh(e.to_string()))?;
        remote_file.write_all(contents)?;
        remote_file.flush()?;
        drop(remote_file);

        let flags = if overwrite {
            RenameFlags::OVERWRITE | RenameFlags::ATOMIC
        } else {
            RenameFlags::ATOMIC
        };
        if let Err(error) = connected
            .sftp
            .rename(temp_remote_path, remote_path, Some(flags))
        {
            let _ = connected.sftp.unlink(temp_remote_path);
            return Err(SyncError::Ssh(error.to_string()));
        }

        Ok(())
    }

    fn download_vault(&self, target: &RemoteTarget) -> Result<Vec<u8>, SyncError> {
        let connected = self.connect(target)?;
        let mut remote_file = connected
            .sftp
            .open(Path::new(&target.path))
            .map_err(|e| SyncError::Ssh(e.to_string()))?;
        let mut bytes = Vec::new();
        remote_file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
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

fn validate_local_vault(local_vault_path: &str, vault_password: &str) -> Result<(), SyncError> {
    VaultStore::load(local_vault_path, vault_password)
        .map(|_| ())
        .map_err(|e| SyncError::Vault(e.to_string()))
}

fn remote_exists(sftp: &Sftp, remote_path: &Path) -> Result<bool, SyncError> {
    match sftp.stat(remote_path) {
        Ok(_) => Ok(true),
        Err(error) => {
            let message = error.to_string();
            if message.contains("No such file")
                || message.contains("not found")
                || message.contains("no such file")
            {
                Ok(false)
            } else {
                Err(SyncError::Ssh(message))
            }
        }
    }
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
