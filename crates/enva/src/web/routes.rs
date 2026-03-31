//! API route handlers for the secrets manager web server.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex as TokioMutex;

use super::auth::AuthManager;
use crate::{
    paths,
    ssh_config::{self, SshConfigError, SshHostConfig},
    sync,
    vault::{VaultError, VaultStore},
};

pub struct AppState {
    vault_path: RwLock<String>,
    auth: AuthManager,
    password: RwLock<SecretString>,
    vault_write_lock: TokioMutex<()>,
    ssh_config_path: RwLock<String>,
    ssh_hosts: RwLock<Option<Vec<SshHostConfig>>>,
    remote_sync: Arc<dyn RemoteSyncExecutor>,
}

trait RemoteSyncExecutor: Send + Sync {
    fn deploy(
        &self,
        local_vault_path: &str,
        vault_password: &str,
        remote_spec: &str,
        port: u16,
        overwrite: bool,
        auth: sync::SshAuthOptions,
    ) -> Result<(), sync::SyncError>;

    fn sync_from(
        &self,
        local_vault_path: &str,
        vault_password: &str,
        remote_spec: &str,
        port: u16,
        overwrite: bool,
        auth: sync::SshAuthOptions,
    ) -> Result<(), sync::SyncError>;
}

struct DefaultRemoteSyncExecutor;

impl RemoteSyncExecutor for DefaultRemoteSyncExecutor {
    fn deploy(
        &self,
        local_vault_path: &str,
        vault_password: &str,
        remote_spec: &str,
        port: u16,
        overwrite: bool,
        auth: sync::SshAuthOptions,
    ) -> Result<(), sync::SyncError> {
        sync::deploy_vault(
            local_vault_path,
            vault_password,
            remote_spec,
            port,
            overwrite,
            auth,
        )
    }

    fn sync_from(
        &self,
        local_vault_path: &str,
        vault_password: &str,
        remote_spec: &str,
        port: u16,
        overwrite: bool,
        auth: sync::SshAuthOptions,
    ) -> Result<(), sync::SyncError> {
        sync::sync_from_remote(
            local_vault_path,
            vault_password,
            remote_spec,
            port,
            overwrite,
            auth,
        )
    }
}

impl AppState {
    pub fn new(vault_path: String) -> Arc<Self> {
        Self::new_with_options(
            vault_path,
            ssh_config::DEFAULT_SSH_CONFIG_PATH.to_string(),
            Arc::new(DefaultRemoteSyncExecutor),
        )
    }

    fn new_with_options(
        vault_path: String,
        ssh_config_path: String,
        remote_sync: Arc<dyn RemoteSyncExecutor>,
    ) -> Arc<Self> {
        let mut secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Arc::new(Self {
            vault_path: RwLock::new(vault_path),
            auth: AuthManager::new(&secret),
            password: RwLock::new(SecretString::from(String::new())),
            vault_write_lock: TokioMutex::new(()),
            ssh_config_path: RwLock::new(ssh_config_path),
            ssh_hosts: RwLock::new(None),
            remote_sync,
        })
    }

    fn vault_path(&self) -> String {
        self.vault_path
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn set_vault_path(&self, vault_path: String) {
        *self.vault_path.write().unwrap_or_else(|e| e.into_inner()) = vault_path;
    }

    fn ssh_config_path(&self) -> String {
        self.ssh_config_path
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn load_ssh_hosts(&self, force_refresh: bool) -> Result<Vec<SshHostConfig>, SshConfigError> {
        if !force_refresh {
            let cached = self
                .ssh_hosts
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if let Some(hosts) = cached {
                return Ok(hosts);
            }
        }

        let hosts = ssh_config::load_ssh_hosts(&self.ssh_config_path())?;
        *self.ssh_hosts.write().unwrap_or_else(|e| e.into_inner()) = Some(hosts.clone());
        Ok(hosts)
    }

    fn clear_password(&self) {
        *self.password.write().unwrap() = SecretString::from(String::new());
    }

    fn set_password(&self, password: String) {
        *self.password.write().unwrap() = SecretString::from(password);
    }
}

fn extract_token(headers: &HeaderMap) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Missing or invalid Authorization header".into(),
                }),
            )
        })
}

fn require_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let token = extract_token(headers)?;
    let claims = state
        .auth
        .verify_token(&token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: e })))?;
    if claims.vault_path != state.vault_path() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Vault path changed. Please sign in again.".into(),
            }),
        ));
    }
    Ok(())
}

fn get_store(state: &AppState) -> Result<VaultStore, (StatusCode, Json<ErrorResponse>)> {
    let pw = state.password.read().unwrap();
    if pw.expose_secret().is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Not authenticated".into(),
            }),
        ));
    }
    let vault_path = state.vault_path();
    VaultStore::load(&vault_path, pw.expose_secret()).map_err(|e| {
        let status = match &e {
            VaultError::Auth(_) => StatusCode::UNAUTHORIZED,
            VaultError::Corrupted(_) => StatusCode::UNPROCESSABLE_ENTITY,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })
}

fn current_vault_context(
    state: &AppState,
) -> Result<(String, String), (StatusCode, Json<ErrorResponse>)> {
    let pw = state.password.read().unwrap();
    if pw.expose_secret().is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Not authenticated".into(),
            }),
        ));
    }

    Ok((state.vault_path(), pw.expose_secret().to_string()))
}

fn ssh_config_error_response(error: SshConfigError) -> (StatusCode, Json<ErrorResponse>) {
    let status = match &error {
        SshConfigError::EmptyPath | SshConfigError::Resolve { .. } => StatusCode::BAD_REQUEST,
        SshConfigError::Read { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
            StatusCode::NOT_FOUND
        }
        SshConfigError::Read { .. } => StatusCode::INTERNAL_SERVER_ERROR,
    };

    (
        status,
        Json(ErrorResponse {
            error: error.to_string(),
        }),
    )
}

fn sync_error_response(error: sync::SyncError) -> (StatusCode, Json<ErrorResponse>) {
    let status = match error {
        sync::SyncError::InvalidRemoteTarget(_) => StatusCode::BAD_REQUEST,
        sync::SyncError::RemoteVaultExists(_) | sync::SyncError::LocalVaultExists(_) => {
            StatusCode::CONFLICT
        }
        sync::SyncError::Vault(_) => StatusCode::UNPROCESSABLE_ENTITY,
        sync::SyncError::Ssh(_) => StatusCode::BAD_GATEWAY,
        sync::SyncError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };

    (
        status,
        Json(ErrorResponse {
            error: error.to_string(),
        }),
    )
}

fn ssh_host_remote_spec(
    host: &SshHostConfig,
    remote_path: &str,
) -> Result<(String, sync::SshAuthOptions), (StatusCode, Json<ErrorResponse>)> {
    let trimmed = remote_path.trim();
    if trimmed.is_empty() {
        return Err(bad_request("Remote path must not be empty"));
    }

    Ok((
        format!("{}@{}:{trimmed}", host.user, host.hostname),
        sync::SshAuthOptions {
            password: None,
            key_path: host.identity_file.clone(),
            passphrase: None,
        },
    ))
}

fn ssh_host_response(host: &SshHostConfig) -> serde_json::Value {
    serde_json::json!({
        "alias": host.alias,
        "hostname": host.hostname,
        "user": host.user,
        "port": host.port,
        "identity_file": host.identity_file,
        "auth_source": if host.identity_file.is_some() { "identity_file" } else { "ssh_agent" }
    })
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct PathResponse {
    resolved_path: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    password: String,
    #[serde(default)]
    vault_path: String,
}

#[derive(Deserialize)]
struct InitRequest {
    password: String,
    #[serde(default)]
    vault_path: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    expires_in: u64,
    vault_path: String,
}

#[derive(Serialize)]
struct SessionSettingsResponse {
    vault_path: String,
    relogin_required: bool,
}

#[derive(Deserialize)]
struct SessionSettingsRequest {
    vault_path: String,
}

#[derive(Deserialize)]
struct ResolvePathRequest {
    kind: String,
    path: String,
}

#[derive(Deserialize)]
struct RemoteActionInput {
    host_alias: String,
    remote_path: String,
    #[serde(default)]
    overwrite: bool,
}

#[derive(Deserialize)]
struct SecretInput {
    key: String,
    value: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct SecretPatchInput {
    #[serde(default)]
    alias: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct AppSecretsInput {
    secrets: Vec<String>,
    #[serde(default)]
    overrides: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ListQuery {
    app: Option<String>,
}

#[derive(Deserialize)]
struct RevealQuery {
    #[serde(default)]
    reveal: bool,
}

#[derive(Deserialize)]
struct CreateAppInput {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    app_path: String,
}

#[derive(Deserialize)]
struct UpdateAppInput {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    app_path: Option<String>,
}

pub fn api_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/paths/resolve", post(resolve_path))
        .route(
            "/session/settings",
            get(get_session_settings).put(update_session_settings),
        )
        .route("/ssh/hosts", get(list_ssh_hosts))
        .route("/ssh/refresh", post(refresh_ssh_hosts))
        .route("/ssh/deploy", post(deploy_vault_to_ssh_host))
        .route("/ssh/sync-from", post(sync_vault_from_ssh_host))
        .route("/vault/init", post(init_vault))
        .route("/secrets", get(list_secrets))
        .route("/secrets/{alias}", get(get_secret))
        .route("/secrets/{alias}", put(upsert_secret).patch(edit_secret))
        .route("/secrets/{alias}", delete(delete_secret))
        .route("/apps", get(list_apps).post(create_app))
        .route("/apps/{app}", put(update_app).delete(delete_app))
        .route("/apps/{app}/secrets", get(get_app_secrets))
        .route("/apps/{app}/secrets", put(update_app_secrets))
        .route("/apps/{app}/secrets/{alias}", delete(unassign_secret))
        .with_state(state)
}

fn bad_request(error: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: error.into(),
        }),
    )
}

fn resolve_requested_vault_path(
    state: &AppState,
    requested_path: &str,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    if requested_path.trim().is_empty() {
        return Ok(state.vault_path());
    }

    paths::resolve_vault_path(requested_path).map_err(|e| bad_request(e.to_string()))
}

async fn resolve_path(
    Json(body): Json<ResolvePathRequest>,
) -> Result<Json<PathResponse>, (StatusCode, Json<ErrorResponse>)> {
    let resolved = match body.kind.as_str() {
        "vault" => paths::resolve_vault_path(&body.path).map_err(|e| bad_request(e.to_string()))?,
        "app" => paths::resolve_app_path(&body.path).map_err(|e| bad_request(e.to_string()))?,
        _ => {
            return Err(bad_request("Unsupported path kind"));
        }
    };

    Ok(Json(PathResponse {
        resolved_path: resolved,
    }))
}

async fn get_session_settings(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SessionSettingsResponse>, (StatusCode, Json<ErrorResponse>)> {
    Ok(Json(SessionSettingsResponse {
        vault_path: state.vault_path(),
        relogin_required: false,
    }))
}

async fn list_ssh_hosts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let hosts = state
        .load_ssh_hosts(false)
        .map_err(ssh_config_error_response)?;
    let payload: Vec<serde_json::Value> = hosts.iter().map(ssh_host_response).collect();
    Ok(Json(serde_json::json!({
        "config_path": state.ssh_config_path(),
        "hosts": payload,
    })))
}

async fn refresh_ssh_hosts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let hosts = state
        .load_ssh_hosts(true)
        .map_err(ssh_config_error_response)?;
    let payload: Vec<serde_json::Value> = hosts.iter().map(ssh_host_response).collect();
    Ok(Json(serde_json::json!({
        "config_path": state.ssh_config_path(),
        "hosts": payload,
        "refreshed": true,
    })))
}

async fn deploy_vault_to_ssh_host(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RemoteActionInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let _guard = state.vault_write_lock.lock().await;
    let (vault_path, password) = current_vault_context(&state)?;
    let hosts = state
        .load_ssh_hosts(false)
        .map_err(ssh_config_error_response)?;
    let host = hosts
        .into_iter()
        .find(|candidate| candidate.alias == body.host_alias)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("SSH host not found: {}", body.host_alias),
                }),
            )
        })?;
    let (remote_spec, auth) = ssh_host_remote_spec(&host, &body.remote_path)?;
    let executor = state.remote_sync.clone();
    let overwrite = body.overwrite;
    let remote_spec_for_response = remote_spec.clone();
    tokio::task::spawn_blocking(move || {
        executor.deploy(
            &vault_path,
            &password,
            &remote_spec,
            host.port,
            overwrite,
            auth,
        )
    })
    .await
    .map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Remote deploy task failed: {error}"),
            }),
        )
    })?
    .map_err(sync_error_response)?;

    Ok(Json(serde_json::json!({
        "deployed": true,
        "host_alias": body.host_alias,
        "remote_spec": remote_spec_for_response,
        "overwrite": overwrite,
    })))
}

async fn sync_vault_from_ssh_host(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RemoteActionInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let _guard = state.vault_write_lock.lock().await;
    let (vault_path, password) = current_vault_context(&state)?;
    let hosts = state
        .load_ssh_hosts(false)
        .map_err(ssh_config_error_response)?;
    let host = hosts
        .into_iter()
        .find(|candidate| candidate.alias == body.host_alias)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: format!("SSH host not found: {}", body.host_alias),
                }),
            )
        })?;
    let (remote_spec, auth) = ssh_host_remote_spec(&host, &body.remote_path)?;
    let executor = state.remote_sync.clone();
    let overwrite = body.overwrite;
    let remote_spec_for_response = remote_spec.clone();
    tokio::task::spawn_blocking(move || {
        executor.sync_from(
            &vault_path,
            &password,
            &remote_spec,
            host.port,
            overwrite,
            auth,
        )
    })
    .await
    .map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Remote sync task failed: {error}"),
            }),
        )
    })?
    .map_err(sync_error_response)?;

    Ok(Json(serde_json::json!({
        "synced": true,
        "host_alias": body.host_alias,
        "remote_spec": remote_spec_for_response,
        "overwrite": overwrite,
    })))
}

async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').next().unwrap_or("unknown").trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    if body.password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Password must not be empty".into(),
            }),
        ));
    }

    state
        .auth
        .check_rate_limit(&client_ip)
        .map_err(|e| (StatusCode::FORBIDDEN, Json(ErrorResponse { error: e })))?;

    let vault_path = resolve_requested_vault_path(&state, &body.vault_path)?;

    VaultStore::load(&vault_path, &body.password).map_err(|_| {
        state.auth.record_failure(&client_ip);
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid password".into(),
            }),
        )
    })?;

    state.set_password(body.password);
    state.set_vault_path(vault_path.clone());

    let token = state.auth.create_token(&vault_path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    Ok(Json(LoginResponse {
        token,
        expires_in: 1800,
        vault_path,
    }))
}

async fn init_vault(
    State(state): State<Arc<AppState>>,
    Json(body): Json<InitRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    if body.password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Password must not be empty".into(),
            }),
        ));
    }
    if body.password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Password must be at least 8 characters".into(),
            }),
        ));
    }
    let vault_path = resolve_requested_vault_path(&state, &body.vault_path)?;
    let _guard = state.vault_write_lock.lock().await;
    if std::path::Path::new(&vault_path).exists() {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Vault already exists. Delete it first or choose a different path.".into(),
            }),
        ));
    }
    VaultStore::create(&vault_path, &body.password, None).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    state.set_vault_path(vault_path.clone());
    state.clear_password();
    Ok(Json(
        serde_json::json!({"status": "created", "vault_path": vault_path}),
    ))
}

async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    state.clear_password();
    Ok(Json(serde_json::json!({"status": "logged_out"})))
}

async fn update_session_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SessionSettingsRequest>,
) -> Result<Json<SessionSettingsResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let vault_path =
        paths::resolve_vault_path(&body.vault_path).map_err(|e| bad_request(e.to_string()))?;
    let relogin_required = vault_path != state.vault_path();
    if relogin_required {
        state.set_vault_path(vault_path.clone());
        state.clear_password();
    }

    Ok(Json(SessionSettingsResponse {
        vault_path,
        relogin_required,
    }))
}

async fn create_app(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateAppInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let _guard = state.vault_write_lock.lock().await;
    let mut store = get_store(&state)?;
    store
        .create_app(&body.name, &body.description, &body.app_path)
        .map_err(|e| {
            let status = if matches!(e, VaultError::AppExists(_)) {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            (
                status,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;
    store.save().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"app": body.name, "created": true})),
    ))
}

async fn update_app(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(app): Path<String>,
    Json(body): Json<UpdateAppInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let _guard = state.vault_write_lock.lock().await;
    let mut store = get_store(&state)?;
    let mut current_app = app.clone();
    if let Some(new_name) = body.name.as_deref() {
        let trimmed = new_name.trim();
        if !trimmed.is_empty() && trimmed != app {
            store.rename_app(&app, trimmed).map_err(|e| {
                let status = match e {
                    VaultError::AppNotFound(_) => StatusCode::NOT_FOUND,
                    VaultError::AppExists(_) => StatusCode::CONFLICT,
                    _ => StatusCode::BAD_REQUEST,
                };
                (
                    status,
                    Json(ErrorResponse {
                        error: e.to_string(),
                    }),
                )
            })?;
            current_app = trimmed.to_string();
        }
    }
    {
        let ad = store.get_app_entry_mut(&current_app).map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;
        if let Some(desc) = body.description {
            ad.description = desc;
        }
        if let Some(path) = body.app_path {
            ad.app_path = path;
        }
    }
    store.save().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    Ok(Json(serde_json::json!({
        "app": current_app,
        "previous_app": app,
        "updated": true
    })))
}

async fn delete_app(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(app): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let _guard = state.vault_write_lock.lock().await;
    let mut store = get_store(&state)?;
    store.delete_app(&app).map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    store.save().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    Ok(Json(serde_json::json!({"deleted": true, "app": app})))
}

async fn list_secrets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let store = get_store(&state)?;
    let secrets = store.list(q.app.as_deref()).map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    let result: Vec<serde_json::Value> = secrets
        .iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id, "alias": s.alias, "key": s.key, "description": s.description,
                "tags": s.tags, "apps": s.apps, "updated_at": s.updated_at,
                "value_masked": "••••••••"
            })
        })
        .collect();
    Ok(Json(result))
}

async fn get_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(alias): Path<String>,
    Query(q): Query<RevealQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let store = get_store(&state)?;
    let secrets = store.list(None).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    let info = secrets.iter().find(|s| s.alias == alias).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Alias not found: {alias}"),
            }),
        )
    })?;
    let mut result = serde_json::json!({
        "id": info.id, "alias": info.alias, "key": info.key, "description": info.description,
        "tags": info.tags, "apps": info.apps, "updated_at": info.updated_at
    });
    if q.reveal {
        let value = store.get(&alias).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;
        result["value"] = serde_json::Value::String(value);
    }
    Ok(Json(result))
}

async fn upsert_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(alias): Path<String>,
    Json(body): Json<SecretInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let _guard = state.vault_write_lock.lock().await;
    let mut store = get_store(&state)?;
    let existed = store.get(&alias).is_ok();
    store
        .set(
            &alias,
            &body.key,
            &body.value,
            &body.description,
            &body.tags,
        )
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;
    store.save().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    let status_code = if existed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((
        status_code,
        Json(serde_json::json!({
            "alias": alias,
            "created": !existed,
            "updated_at": chrono::Utc::now().to_rfc3339()
        })),
    ))
}

async fn edit_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(alias): Path<String>,
    Json(body): Json<SecretPatchInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let requested_alias = body
        .alias
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if requested_alias.is_none()
        && body.key.is_none()
        && body.value.is_none()
        && body.description.is_none()
        && body.tags.is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error:
                    "Nothing to edit. Provide at least one of: alias, key, value, description, tags."
                        .into(),
            }),
        ));
    }
    let _guard = state.vault_write_lock.lock().await;
    let mut store = get_store(&state)?;
    let mut current_alias = alias.clone();
    if let Some(new_alias) = requested_alias {
        if new_alias != alias {
            store.rename_secret(&alias, new_alias).map_err(|e| {
                let status = match e {
                    VaultError::AliasNotFound(_) => StatusCode::NOT_FOUND,
                    VaultError::AliasExists(_) => StatusCode::CONFLICT,
                    _ => StatusCode::BAD_REQUEST,
                };
                (
                    status,
                    Json(ErrorResponse {
                        error: e.to_string(),
                    }),
                )
            })?;
            current_alias = new_alias.to_string();
        }
    }

    if body.key.is_some()
        || body.value.is_some()
        || body.description.is_some()
        || body.tags.is_some()
    {
        store
            .edit(
                &current_alias,
                body.key.as_deref(),
                body.value.as_deref(),
                body.description.as_deref(),
                body.tags.as_deref(),
            )
            .map_err(|e| {
                let status = if matches!(e, VaultError::AliasNotFound(_)) {
                    StatusCode::NOT_FOUND
                } else {
                    StatusCode::BAD_REQUEST
                };
                (
                    status,
                    Json(ErrorResponse {
                        error: e.to_string(),
                    }),
                )
            })?;
    }
    store.save().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    let mut fields = Vec::new();
    if current_alias != alias {
        fields.push("alias");
    }
    if body.key.is_some() {
        fields.push("key");
    }
    if body.value.is_some() {
        fields.push("value");
    }
    if body.description.is_some() {
        fields.push("description");
    }
    if body.tags.is_some() {
        fields.push("tags");
    }
    Ok(Json(serde_json::json!({
        "alias": current_alias,
        "previous_alias": alias,
        "updated_fields": fields,
        "updated_at": chrono::Utc::now().to_rfc3339()
    })))
}

async fn delete_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(alias): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let _guard = state.vault_write_lock.lock().await;
    let mut store = get_store(&state)?;
    let apps_before: Vec<String> = store
        .list(None)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?
        .iter()
        .filter(|s| s.alias == alias)
        .flat_map(|s| s.apps.clone())
        .collect();
    store.delete(&alias).map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    store.save().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    Ok(Json(
        serde_json::json!({"deleted": true, "removed_from_apps": apps_before}),
    ))
}

async fn list_apps(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let store = get_store(&state)?;
    let apps: Vec<serde_json::Value> = store
        .list_apps()
        .iter()
        .map(|a| {
            serde_json::json!({
                "id": a.id,
                "name": a.name,
                "description": a.description,
                "app_path": a.app_path,
                "key_count": a.secret_count
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "apps": apps })))
}

async fn get_app_secrets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(app): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let store = get_store(&state)?;
    let bindings = store.get_app_secret_bindings(&app).map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    let secrets: Vec<serde_json::Value> = bindings
        .iter()
        .map(|binding| {
            serde_json::json!({
                "id": binding.secret_id,
                "alias": binding.alias,
                "key": binding.key,
                "injected_as": binding.injected_as,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "app": app, "secrets": secrets })))
}

async fn update_app_secrets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(app): Path<String>,
    Json(body): Json<AppSecretsInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let _guard = state.vault_write_lock.lock().await;
    let mut store = get_store(&state)?;
    if store.list_apps().iter().all(|a| a.name != app) {
        store.create_app(&app, "", "").map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;
    }
    let mut errors = Vec::new();
    for alias in &body.secrets {
        let ovr = body.overrides.get(alias).map(|s| s.as_str());
        if let Err(e) = store.assign(&app, alias, ovr) {
            errors.push(format!("{alias}: {e}"));
        }
    }
    if !errors.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Failed to assign: {}", errors.join("; ")),
            }),
        ));
    }
    store.save().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    Ok(Json(serde_json::json!({"app": app, "status": "updated"})))
}

async fn unassign_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((app, alias)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let _guard = state.vault_write_lock.lock().await;
    let mut store = get_store(&state)?;
    store.unassign(&app, &alias).map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    store.save().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    Ok(Json(serde_json::json!({"unassigned": true})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::KdfParams;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use tower::ServiceExt;

    fn build_app(vault_path: &str) -> (Router, Arc<AppState>) {
        let state = AppState::new(vault_path.to_string());
        let router = Router::new().nest("/api", api_router(state.clone()));
        (router, state)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RemoteCall {
        action: &'static str,
        remote_spec: String,
        port: u16,
        overwrite: bool,
        key_path: Option<String>,
    }

    #[derive(Default)]
    struct FakeRemoteSyncExecutor {
        calls: Mutex<Vec<RemoteCall>>,
        deploy_error: Mutex<Option<sync::SyncError>>,
        sync_error: Mutex<Option<sync::SyncError>>,
    }

    impl RemoteSyncExecutor for FakeRemoteSyncExecutor {
        fn deploy(
            &self,
            _local_vault_path: &str,
            _vault_password: &str,
            remote_spec: &str,
            port: u16,
            overwrite: bool,
            auth: sync::SshAuthOptions,
        ) -> Result<(), sync::SyncError> {
            self.calls.lock().unwrap().push(RemoteCall {
                action: "deploy",
                remote_spec: remote_spec.to_string(),
                port,
                overwrite,
                key_path: auth.key_path,
            });
            if let Some(error) = self.deploy_error.lock().unwrap().take() {
                return Err(error);
            }
            Ok(())
        }

        fn sync_from(
            &self,
            _local_vault_path: &str,
            _vault_password: &str,
            remote_spec: &str,
            port: u16,
            overwrite: bool,
            auth: sync::SshAuthOptions,
        ) -> Result<(), sync::SyncError> {
            self.calls.lock().unwrap().push(RemoteCall {
                action: "sync_from",
                remote_spec: remote_spec.to_string(),
                port,
                overwrite,
                key_path: auth.key_path,
            });
            if let Some(error) = self.sync_error.lock().unwrap().take() {
                return Err(error);
            }
            Ok(())
        }
    }

    fn build_app_with_ssh(
        vault_path: &str,
        ssh_config_path: &str,
    ) -> (Router, Arc<AppState>, Arc<FakeRemoteSyncExecutor>) {
        let remote = Arc::new(FakeRemoteSyncExecutor::default());
        let state = AppState::new_with_options(
            vault_path.to_string(),
            ssh_config_path.to_string(),
            remote.clone(),
        );
        let router = Router::new().nest("/api", api_router(state.clone()));
        (router, state, remote)
    }

    fn fast_kdf() -> KdfParams {
        KdfParams {
            algorithm: "argon2id".into(),
            memory_cost: 8192,
            time_cost: 1,
            parallelism: 1,
        }
    }

    fn current_dir_lock() -> &'static Mutex<()> {
        crate::paths::process_lock()
    }

    struct CurrentDirGuard {
        original: PathBuf,
    }

    impl Drop for CurrentDirGuard {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.original).unwrap();
        }
    }

    fn push_current_dir(path: &Path) -> CurrentDirGuard {
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(path).unwrap();
        CurrentDirGuard { original }
    }

    async fn get_token(router: &Router, password: &str) -> String {
        let app = router.clone();
        let req = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"password":"{password}"}}"#)))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "login must succeed");
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        json["token"].as_str().unwrap().to_string()
    }

    async fn login_and_get_token(router: &Router, state: &Arc<AppState>, password: &str) -> String {
        let vault_path = state.vault_path();
        VaultStore::create(&vault_path, password, Some(fast_kdf())).unwrap();
        get_token(router, password).await
    }

    fn authed_request(method: &str, uri: &str, token: &str, body: Option<&str>) -> Request<Body> {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json");
        match body {
            Some(b) => builder.body(Body::from(b.to_string())).unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        }
    }

    #[test]
    fn app_state_new_constructs_valid_state() {
        let state = AppState::new("/tmp/test.vault.json".to_string());
        assert_eq!(state.vault_path(), "/tmp/test.vault.json");
    }

    #[test]
    fn api_router_builds_without_panic() {
        let state = AppState::new("/tmp/test.vault.json".to_string());
        let _router = api_router(state);
    }

    #[tokio::test]
    async fn init_vault_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("new.vault.json");
        let (app, _) = build_app(vp.to_str().unwrap());

        let req = Request::builder()
            .method("POST")
            .uri("/api/vault/init")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"password":"securepass123"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(vp.exists(), "vault file should be created on disk");
    }

    #[tokio::test]
    async fn init_vault_uses_requested_relative_path() {
        let _lock = current_dir_lock().lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let _cwd = push_current_dir(tmp.path());
        let fallback = tmp.path().join("fallback.vault.json");
        let (app, state) = build_app(fallback.to_str().unwrap());

        let req = Request::builder()
            .method("POST")
            .uri("/api/vault/init")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"password":"securepass123","vault_path":"./relative-init.vault.json"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resolved = tmp.path().join("./relative-init.vault.json");
        assert!(resolved.exists());
        assert_eq!(state.vault_path(), resolved.to_string_lossy());
    }

    #[tokio::test]
    async fn init_vault_rejects_empty_password() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("empty.vault.json");
        let (app, _) = build_app(vp.to_str().unwrap());

        let req = Request::builder()
            .method("POST")
            .uri("/api/vault/init")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"password":""}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(!vp.exists());
    }

    #[tokio::test]
    async fn init_vault_rejects_short_password() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("short.vault.json");
        let (app, _) = build_app(vp.to_str().unwrap());

        let req = Request::builder()
            .method("POST")
            .uri("/api/vault/init")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"password":"abc"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(!vp.exists());
    }

    #[tokio::test]
    async fn init_vault_rejects_duplicate() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("dup.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        VaultStore::create(&vps, "existingpass1", None).unwrap();
        assert!(vp.exists());

        let (app, _) = build_app(&vps);
        let req = Request::builder()
            .method("POST")
            .uri("/api/vault/init")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"password":"anotherpass1"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn login_rejects_wrong_password() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("auth.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        VaultStore::create(&vps, "correctpw", None).unwrap();

        let (app, _) = build_app(&vps);
        let req = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"password":"wrongpass"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_rejects_missing_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("nonexistent.vault.json");
        let (app, _) = build_app(vp.to_str().unwrap());

        let req = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"password":"anything"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_accepts_correct_password() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("ok.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        VaultStore::create(&vps, "correctpw", None).unwrap();

        let (app, _) = build_app(&vps);
        let req = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"password":"correctpw"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn login_uses_requested_relative_path() {
        let _lock = current_dir_lock().lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let _cwd = push_current_dir(tmp.path());
        let requested = tmp.path().join("./selected.vault.json");
        let requested_str = requested.to_string_lossy().to_string();
        VaultStore::create(&requested_str, "correctpw", None).unwrap();

        let fallback = tmp.path().join("fallback.vault.json");
        let (app, state) = build_app(fallback.to_str().unwrap());
        let req = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"password":"correctpw","vault_path":"./selected.vault.json"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["vault_path"], requested.to_string_lossy().to_string());
        assert_eq!(state.vault_path(), requested.to_string_lossy());
    }

    #[tokio::test]
    async fn update_session_settings_requires_relogin_after_path_change() {
        let _lock = current_dir_lock().lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let _cwd = push_current_dir(tmp.path());
        let current = tmp.path().join("current.vault.json");
        let current_str = current.to_string_lossy().to_string();
        let (router, state) = build_app(&current_str);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let req = authed_request(
            "PUT",
            "/api/session/settings",
            &token,
            Some(r#"{"vault_path":"./next.vault.json"}"#),
        );
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["relogin_required"], true);
        assert_eq!(
            state.vault_path(),
            tmp.path().join("./next.vault.json").to_string_lossy()
        );

        let req = authed_request("GET", "/api/apps", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn resolve_path_endpoint_resolves_relative_app_path() {
        let _lock = current_dir_lock().lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let _cwd = push_current_dir(tmp.path());
        let vp = tmp.path().join("resolve-endpoint.vault.json");
        let (router, _) = build_app(vp.to_str().unwrap());

        let req = Request::builder()
            .method("POST")
            .uri("/api/paths/resolve")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"kind":"app","path":"./bin/tool"}"#))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["resolved_path"],
            tmp.path().join("./bin/tool").to_string_lossy().to_string()
        );
    }

    #[tokio::test]
    async fn list_secrets_empty_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("list-empty.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let req = authed_request("GET", "/api/secrets", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_secrets_with_data() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("list-data.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store
            .set("api-key", "API_KEY", "sk-12345", "", &[])
            .unwrap();
        store
            .set(
                "db-url",
                "DATABASE_URL",
                "postgres://localhost/db",
                "DB conn",
                &[],
            )
            .unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request("GET", "/api/secrets", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["value_masked"], "••••••••");
    }

    #[tokio::test]
    async fn upsert_secret_creates_new() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("upsert-new.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let payload = r#"{"key":"MY_SECRET","value":"s3cret","description":"test","tags":["dev"]}"#;
        let req = authed_request("PUT", "/api/secrets/my-secret", &token, Some(payload));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["alias"], "my-secret");
        assert_eq!(json["created"], true);
    }

    #[tokio::test]
    async fn upsert_secret_updates_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("upsert-update.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let payload = r#"{"key":"MY_KEY","value":"v1","description":"","tags":[]}"#;
        let req = authed_request("PUT", "/api/secrets/update-me", &token, Some(payload));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let payload = r#"{"key":"MY_KEY","value":"v2","description":"updated","tags":["new"]}"#;
        let req = authed_request("PUT", "/api/secrets/update-me", &token, Some(payload));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["created"], false);
    }

    #[tokio::test]
    async fn upsert_secret_rejects_invalid_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("upsert-bad.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let payload = r#"{"key":"K","value":"v","description":"","tags":[]}"#;
        let req = authed_request("PUT", "/api/secrets/UPPER_CASE", &token, Some(payload));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_secret_masked() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("get-masked.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store
            .set(
                "my-sec",
                "MY_SEC",
                "hidden-val",
                "a secret",
                &["tag1".into()],
            )
            .unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request("GET", "/api/secrets/my-sec", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["alias"], "my-sec");
        assert_eq!(json["key"], "MY_SEC");
        assert!(
            json.get("value").is_none(),
            "value should not be present when not revealed"
        );
    }

    #[tokio::test]
    async fn get_secret_revealed() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("get-reveal.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store
            .set("my-sec", "MY_SEC", "hidden-val", "", &[])
            .unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request("GET", "/api/secrets/my-sec?reveal=true", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["value"], "hidden-val");
    }

    #[tokio::test]
    async fn get_secret_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("get-404.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let req = authed_request("GET", "/api/secrets/nonexistent", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_secret_success() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("del-ok.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store.set("rm-me", "RM_ME", "gone", "", &[]).unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request("DELETE", "/api/secrets/rm-me", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["deleted"], true);
    }

    #[tokio::test]
    async fn delete_secret_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("del-404.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let req = authed_request("DELETE", "/api/secrets/ghost", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_app_success() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("create-app.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let payload = r#"{"name":"myapp","description":"My App","app_path":"/usr/local/myapp"}"#;
        let req = authed_request("POST", "/api/apps", &token, Some(payload));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["app"], "myapp");
        assert_eq!(json["created"], true);
    }

    #[tokio::test]
    async fn create_app_accepts_relative_app_path() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("create-rel-app.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let payload = r#"{"name":"worker","description":"Worker","app_path":"./bin/worker"}"#;
        let req = authed_request("POST", "/api/apps", &token, Some(payload));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let req = authed_request("GET", "/api/apps", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let apps = json["apps"].as_array().unwrap();
        assert_eq!(apps[0]["app_path"], "./bin/worker");
    }

    #[tokio::test]
    async fn create_app_duplicate_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("dup-app.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let payload = r#"{"name":"dupapp","description":"","app_path":""}"#;
        let req = authed_request("POST", "/api/apps", &token, Some(payload));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let req = authed_request("POST", "/api/apps", &token, Some(payload));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn list_apps_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("apps-empty.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let req = authed_request("GET", "/api/apps", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["apps"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_apps_with_data() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("apps-data.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store
            .create_app("backend", "Backend service", "/opt/be")
            .unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request("GET", "/api/apps", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let apps = json["apps"].as_array().unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0]["name"], "backend");
    }

    #[tokio::test]
    async fn update_app_secrets_success() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("upd-app-sec.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store
            .set("db-url", "DATABASE_URL", "postgres://x", "", &[])
            .unwrap();
        store.create_app("myapp", "", "").unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let payload = r#"{"secrets":["db-url"],"overrides":{}}"#;
        let req = authed_request("PUT", "/api/apps/myapp/secrets", &token, Some(payload));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "updated");
    }

    #[tokio::test]
    async fn update_app_secrets_rejects_nonexistent_secret() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("app-sec-bad.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let payload = r#"{"secrets":["no-such-secret"],"overrides":{}}"#;
        let req = authed_request("PUT", "/api/apps/testapp/secrets", &token, Some(payload));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_app_secrets_success() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("get-app-sec.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store
            .set("db-url", "DATABASE_URL", "postgres://x", "", &[])
            .unwrap();
        store.create_app("myapp", "", "").unwrap();
        store.assign("myapp", "db-url", None).unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request("GET", "/api/apps/myapp/secrets", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["app"], "myapp");
        let secrets = json["secrets"].as_array().unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0]["alias"], "db-url");
        assert_eq!(secrets[0]["key"], "DATABASE_URL");
    }

    #[tokio::test]
    async fn get_app_secrets_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("app-sec-nf.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let req = authed_request("GET", "/api/apps/nonexistent/secrets", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unassign_secret_success() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("unassign-ok.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store
            .set("db-url", "DATABASE_URL", "postgres://x", "", &[])
            .unwrap();
        store.create_app("myapp", "", "").unwrap();
        store.assign("myapp", "db-url", None).unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request("DELETE", "/api/apps/myapp/secrets/db-url", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["unassigned"], true);
    }

    #[tokio::test]
    async fn unassign_secret_app_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("unassign-nf.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let req = authed_request("DELETE", "/api/apps/ghost/secrets/something", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn logout_clears_session() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("logout.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let req = authed_request("POST", "/api/auth/logout", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "logged_out");

        let req = authed_request("GET", "/api/secrets", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_app_success() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("del-app.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store.create_app("myapp", "test app", "").unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request("DELETE", "/api/apps/myapp", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["deleted"], true);

        let req = authed_request("GET", "/api/apps", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["apps"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_app_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("del-app-nf.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let req = authed_request("DELETE", "/api/apps/ghost", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn update_app_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("upd-app.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store.create_app("myapp", "old desc", "/old/path").unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request(
            "PUT",
            "/api/apps/myapp",
            &token,
            Some(r#"{"description":"new desc","app_path":"/new/path"}"#),
        );
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let req = authed_request("GET", "/api/apps", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let apps = json["apps"].as_array().unwrap();
        assert_eq!(apps[0]["description"], "new desc");
        assert_eq!(apps[0]["app_path"], "/new/path");
    }

    #[tokio::test]
    async fn update_app_fields_accepts_tilde_app_path() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("upd-app-tilde.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store.create_app("myapp", "old desc", "/old/path").unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request(
            "PUT",
            "/api/apps/myapp",
            &token,
            Some(r#"{"description":"new desc","app_path":"~/bin/new-path"}"#),
        );
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let req = authed_request("GET", "/api/apps", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let apps = json["apps"].as_array().unwrap();
        assert_eq!(apps[0]["app_path"], "~/bin/new-path");
    }

    #[tokio::test]
    async fn edit_secret_key_only() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("edit-key.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store
            .set("my-sec", "OLD_KEY", "the-value", "desc", &["tag1".into()])
            .unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request(
            "PATCH",
            "/api/secrets/my-sec",
            &token,
            Some(r#"{"key":"NEW_KEY"}"#),
        );
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["alias"], "my-sec");
        let fields = json["updated_fields"].as_array().unwrap();
        assert!(fields.iter().any(|f| f == "key"));

        let req = authed_request("GET", "/api/secrets/my-sec?reveal=true", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["key"], "NEW_KEY");
        assert_eq!(json["value"], "the-value");
        assert_eq!(json["description"], "desc");
    }

    #[tokio::test]
    async fn edit_secret_value_only() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("edit-val.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store.set("my-sec", "MY_KEY", "old-val", "", &[]).unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request(
            "PATCH",
            "/api/secrets/my-sec",
            &token,
            Some(r#"{"value":"new-val"}"#),
        );
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let req = authed_request("GET", "/api/secrets/my-sec?reveal=true", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["key"], "MY_KEY");
        assert_eq!(json["value"], "new-val");
    }

    #[tokio::test]
    async fn edit_secret_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("edit-nf.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state) = build_app(&vps);
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let req = authed_request(
            "PATCH",
            "/api/secrets/ghost",
            &token,
            Some(r#"{"key":"X"}"#),
        );
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn edit_secret_empty_body_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("edit-empty.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store.set("s1", "K", "v", "", &[]).unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request("PATCH", "/api/secrets/s1", &token, Some(r#"{}"#));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ssh_hosts_requires_auth() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config");
        std::fs::write(&cfg, "Host prod\n  HostName prod.example.com\n").unwrap();
        let vp = tmp.path().join("ssh-auth.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, _, _) = build_app_with_ssh(&vps, cfg.to_string_lossy().as_ref());

        let req = Request::builder()
            .method("GET")
            .uri("/api/ssh/hosts")
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ssh_hosts_list_and_refresh_work() {
        let tmp = tempfile::tempdir().unwrap();
        let key = tmp.path().join("id_ed25519");
        std::fs::write(&key, "dummy").unwrap();
        let cfg = tmp.path().join("config");
        std::fs::write(
            &cfg,
            format!(
                "Host *\n  User deploy\n  Port 2200\n  IdentityFile {}\n\nHost prod\n  HostName prod.example.com\n",
                key.to_string_lossy()
            ),
        )
        .unwrap();
        let vp = tmp.path().join("ssh-refresh.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state, _) = build_app_with_ssh(&vps, cfg.to_string_lossy().as_ref());
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let req = authed_request("GET", "/api/ssh/hosts", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["hosts"].as_array().unwrap().len(), 1);
        assert_eq!(json["hosts"][0]["alias"], "prod");

        std::fs::write(
            &cfg,
            format!(
                "Host *\n  User deploy\n  Port 2200\n  IdentityFile {}\n\nHost prod\n  HostName prod.example.com\n\nHost staging\n  HostName staging.example.com\n",
                key.to_string_lossy()
            ),
        )
        .unwrap();

        let req = authed_request("POST", "/api/ssh/refresh", &token, Some(r#"{}"#));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let hosts = json["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[1]["alias"], "staging");
    }

    #[tokio::test]
    async fn ssh_deploy_uses_selected_host_config() {
        let tmp = tempfile::tempdir().unwrap();
        let key = tmp.path().join("id_ed25519");
        std::fs::write(&key, "dummy").unwrap();
        let cfg = tmp.path().join("config");
        std::fs::write(
            &cfg,
            format!(
                "Host prod\n  HostName prod.example.com\n  User deploy\n  Port 2201\n  IdentityFile {}\n",
                key.to_string_lossy()
            ),
        )
        .unwrap();
        let vp = tmp.path().join("ssh-deploy.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state, remote) = build_app_with_ssh(&vps, cfg.to_string_lossy().as_ref());
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let req = authed_request(
            "POST",
            "/api/ssh/deploy",
            &token,
            Some(
                r#"{"host_alias":"prod","remote_path":"/srv/enva/prod.vault.json","overwrite":true}"#,
            ),
        );
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let calls = remote.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].action, "deploy");
        assert_eq!(
            calls[0].remote_spec,
            "deploy@prod.example.com:/srv/enva/prod.vault.json"
        );
        assert_eq!(calls[0].port, 2201);
        assert!(calls[0].overwrite);
        assert_eq!(
            calls[0].key_path.as_deref(),
            Some(key.to_string_lossy().as_ref())
        );
    }

    #[tokio::test]
    async fn ssh_sync_maps_executor_conflict_to_http_conflict() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = tmp.path().join("config");
        std::fs::write(
            &cfg,
            "Host prod\n  HostName prod.example.com\n  User deploy\n  Port 2201\n",
        )
        .unwrap();
        let vp = tmp.path().join("ssh-sync.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        let (router, state, remote) = build_app_with_ssh(&vps, cfg.to_string_lossy().as_ref());
        *remote.sync_error.lock().unwrap() = Some(sync::SyncError::LocalVaultExists(vps.clone()));
        let token = login_and_get_token(&router, &state, "testpass1234").await;

        let req = authed_request(
            "POST",
            "/api/ssh/sync-from",
            &token,
            Some(
                r#"{"host_alias":"prod","remote_path":"/srv/enva/prod.vault.json","overwrite":false}"#,
            ),
        );
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn edit_secret_can_rename_alias_and_preserve_app_binding() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("rename-secret-route.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store
            .set("db", "DATABASE_URL", "postgres://x", "", &[])
            .unwrap();
        store.create_app("backend", "backend", "./run.sh").unwrap();
        store.assign("backend", "db", Some("BACKEND_DB")).unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request(
            "PATCH",
            "/api/secrets/db",
            &token,
            Some(r#"{"alias":"primary-db"}"#),
        );
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["alias"], "primary-db");
        assert!(json["updated_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "alias"));

        let req = authed_request("GET", "/api/secrets/primary-db?reveal=true", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["value"], "postgres://x");

        let req = authed_request("GET", "/api/secrets/db?reveal=true", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let req = authed_request("GET", "/api/apps/backend/secrets", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let secrets = json["secrets"].as_array().unwrap();
        assert_eq!(secrets[0]["alias"], "primary-db");
        assert_eq!(secrets[0]["injected_as"], "BACKEND_DB");
    }

    #[tokio::test]
    async fn update_app_can_rename_name_and_preserve_bindings() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("rename-app-route.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store.set("api", "API_KEY", "secret", "", &[]).unwrap();
        store
            .create_app("backend", "old desc", "/old/path")
            .unwrap();
        store.assign("backend", "api", Some("RENAMED_KEY")).unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request(
            "PUT",
            "/api/apps/backend",
            &token,
            Some(r#"{"name":"api-service","description":"new desc","app_path":"/new/path"}"#),
        );
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["app"], "api-service");

        let req = authed_request("GET", "/api/apps", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let apps = json["apps"].as_array().unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0]["name"], "api-service");
        assert_eq!(apps[0]["description"], "new desc");
        assert_eq!(apps[0]["app_path"], "/new/path");

        let req = authed_request("GET", "/api/apps/api-service/secrets", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["secrets"][0]["alias"], "api");
        assert_eq!(json["secrets"][0]["injected_as"], "RENAMED_KEY");

        let req = authed_request("GET", "/api/apps/backend/secrets", &token, None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn request_without_auth_header_returns_401() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("no-auth.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        let (router, _) = build_app(&vps);

        let req = Request::builder()
            .method("GET")
            .uri("/api/secrets")
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["error"].as_str().unwrap().contains("Authorization"));
    }

    #[tokio::test]
    async fn request_with_invalid_token_returns_401() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("bad-token.vault.json");
        let vps = vp.to_str().unwrap().to_string();
        VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        let (router, _) = build_app(&vps);

        let req = authed_request("GET", "/api/secrets", "not.a.valid.jwt", None);
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
