//! API route handlers for the secrets manager web server.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use rand::RngCore;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex as TokioMutex;

use super::auth::AuthManager;
use crate::vault::{VaultError, VaultStore};

pub struct AppState {
    pub vault_path: String,
    pub auth: AuthManager,
    pub password: RwLock<SecretString>,
    pub vault_write_lock: TokioMutex<()>,
}

impl AppState {
    pub fn new(vault_path: String) -> Arc<Self> {
        let mut secret = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Arc::new(Self {
            vault_path,
            auth: AuthManager::new(&secret),
            password: RwLock::new(SecretString::from(String::new())),
            vault_write_lock: TokioMutex::new(()),
        })
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
    state
        .auth
        .verify_token(&token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: e })))?;
    Ok(())
}

fn get_store(state: &AppState) -> Result<VaultStore, (StatusCode, Json<ErrorResponse>)> {
    use secrecy::ExposeSecret;
    let pw = state.password.read().unwrap();
    if pw.expose_secret().is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Not authenticated".into(),
            }),
        ));
    }
    VaultStore::load(&state.vault_path, pw.expose_secret()).map_err(|e| {
        let status = match &e {
            VaultError::Auth(_) => StatusCode::UNAUTHORIZED,
            VaultError::Corrupted(_) => StatusCode::UNPROCESSABLE_ENTITY,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(ErrorResponse { error: e.to_string() }))
    })
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    password: String,
}

#[derive(Deserialize)]
struct InitRequest {
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    expires_in: u64,
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
    description: Option<String>,
    #[serde(default)]
    app_path: Option<String>,
}

pub fn api_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
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

    VaultStore::load(&state.vault_path, &body.password).map_err(|_| {
        state.auth.record_failure(&client_ip);
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid password".into(),
            }),
        )
    })?;

    *state.password.write().unwrap() = SecretString::from(body.password);

    let token = state.auth.create_token(&state.vault_path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e }),
        )
    })?;

    Ok(Json(LoginResponse {
        token,
        expires_in: 1800,
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
    let _guard = state.vault_write_lock.lock().await;
    if std::path::Path::new(&state.vault_path).exists() {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Vault already exists. Delete it first or choose a different path.".into(),
            }),
        ));
    }
    VaultStore::create(&state.vault_path, &body.password, None).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    Ok(Json(
        serde_json::json!({"status": "created", "vault_path": state.vault_path}),
    ))
}

async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    *state.password.write().unwrap() = SecretString::from(String::new());
    Ok(Json(serde_json::json!({"status": "logged_out"})))
}

async fn create_app(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateAppInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    require_auth(&state, &headers)?;
    let _guard = state.vault_write_lock.lock().await;
    let mut store = get_store(&state)?;
    store.create_app(&body.name, &body.description, &body.app_path).map_err(|e| {
        let status = if e.to_string().contains("already exists") {
            StatusCode::CONFLICT
        } else {
            StatusCode::BAD_REQUEST
        };
        (status, Json(ErrorResponse { error: e.to_string() }))
    })?;
    store.save().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e.to_string() }),
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
    {
        let ad = store.get_app_entry_mut(&app).map_err(|e| {
            (StatusCode::NOT_FOUND, Json(ErrorResponse { error: e.to_string() }))
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
            Json(ErrorResponse { error: e.to_string() }),
        )
    })?;
    Ok(Json(serde_json::json!({"app": app, "updated": true})))
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
            Json(ErrorResponse { error: e.to_string() }),
        )
    })?;
    store.save().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e.to_string() }),
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
                "alias": s.alias, "key": s.key, "description": s.description,
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
        "alias": info.alias, "key": info.key, "description": info.description,
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
    if body.key.is_none() && body.value.is_none() && body.description.is_none() && body.tags.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Nothing to edit. Provide at least one of: key, value, description, tags.".into(),
            }),
        ));
    }
    let _guard = state.vault_write_lock.lock().await;
    let mut store = get_store(&state)?;
    store
        .edit(
            &alias,
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
            (status, Json(ErrorResponse { error: e.to_string() }))
        })?;
    store.save().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: e.to_string() }),
        )
    })?;
    let mut fields = Vec::new();
    if body.key.is_some() { fields.push("key"); }
    if body.value.is_some() { fields.push("value"); }
    if body.description.is_some() { fields.push("description"); }
    if body.tags.is_some() { fields.push("tags"); }
    Ok(Json(serde_json::json!({
        "alias": alias,
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
            serde_json::json!({"name": a.name, "description": a.description, "app_path": a.app_path, "key_count": a.secret_count})
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
    let secrets_info = store.list(Some(&app)).map_err(|e| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;
    let secrets: Vec<serde_json::Value> = secrets_info
        .iter()
        .map(|s| {
            serde_json::json!({
                "alias": s.alias,
                "key": s.key,
                "injected_as": s.key,
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
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use crate::vault::KdfParams;
    use tower::ServiceExt;

    fn build_app(vault_path: &str) -> (Router, Arc<AppState>) {
        let state = AppState::new(vault_path.to_string());
        let router = Router::new()
            .nest("/api", api_router(state.clone()));
        (router, state)
    }

    fn fast_kdf() -> KdfParams {
        KdfParams {
            algorithm: "argon2id".into(),
            memory_cost: 8192,
            time_cost: 1,
            parallelism: 1,
        }
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
        VaultStore::create(&state.vault_path, password, Some(fast_kdf())).unwrap();
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
        assert_eq!(state.vault_path, "/tmp/test.vault.json");
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
            .set("db-url", "DATABASE_URL", "postgres://localhost/db", "DB conn", &[])
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
            .set("my-sec", "MY_SEC", "hidden-val", "a secret", &["tag1".into()])
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

        let req = authed_request("PUT", "/api/apps/myapp", &token,
            Some(r#"{"description":"new desc","app_path":"/new/path"}"#));
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
    async fn edit_secret_key_only() {
        let tmp = tempfile::tempdir().unwrap();
        let vp = tmp.path().join("edit-key.vault.json");
        let vps = vp.to_str().unwrap().to_string();

        let mut store = VaultStore::create(&vps, "testpass1234", Some(fast_kdf())).unwrap();
        store.set("my-sec", "OLD_KEY", "the-value", "desc", &["tag1".into()]).unwrap();
        store.save().unwrap();

        let (router, _) = build_app(&vps);
        let token = get_token(&router, "testpass1234").await;

        let req = authed_request("PATCH", "/api/secrets/my-sec", &token, Some(r#"{"key":"NEW_KEY"}"#));
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

        let req = authed_request("PATCH", "/api/secrets/my-sec", &token, Some(r#"{"value":"new-val"}"#));
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

        let req = authed_request("PATCH", "/api/secrets/ghost", &token, Some(r#"{"key":"X"}"#));
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
