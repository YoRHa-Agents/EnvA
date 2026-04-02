use crate::vault::{AppInfo, SecretInfo, VaultError, VaultStore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const BUNDLE_SCHEMA: &str = "enva-bundle";
const BUNDLE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferFormat {
    Env,
    Json,
    EnvaJson,
    Yaml,
}

impl TransferFormat {
    pub fn parse(raw: &str) -> Result<Self, TransferError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "env" => Ok(Self::Env),
            "json" => Ok(Self::Json),
            "enva-json" => Ok(Self::EnvaJson),
            "yaml" | "yml" => Ok(Self::Yaml),
            other => Err(TransferError::UnsupportedFormat(other.to_string())),
        }
    }

    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Json => "json",
            Self::EnvaJson => "enva-json",
            Self::Yaml => "yaml",
        }
    }
}

#[derive(Debug)]
pub struct ExportOptions<'a> {
    pub format: TransferFormat,
    pub app: Option<&'a str>,
    pub shell_prefix: bool,
}

#[derive(Debug)]
pub struct ImportOptions<'a> {
    pub format: Option<TransferFormat>,
    pub source_name: Option<&'a str>,
    pub target_app: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportSummary {
    pub format: String,
    pub imported_secrets: usize,
    pub imported_apps: usize,
    pub assigned_bindings: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("unsupported format '{0}'. Supported formats: env, json, enva-json, yaml, yml")]
    UnsupportedFormat(String),
    #[error("bundle imports do not accept --app because the file already contains app bindings")]
    BundleTargetAppUnsupported,
    #[error("invalid bundle schema '{0}'. Expected '{BUNDLE_SCHEMA}'")]
    InvalidBundleSchema(String),
    #[error("unsupported bundle version '{0}'. Expected '{BUNDLE_VERSION}'")]
    UnsupportedBundleVersion(u32),
    #[error("bundle secret alias '{0}' is duplicated")]
    DuplicateSecretAlias(String),
    #[error("bundle app '{0}' is duplicated")]
    DuplicateAppName(String),
    #[error("bundle app '{app}' references secret alias '{alias}' in a binding, but no such secret exists")]
    MissingBundleSecret { app: String, alias: String },
    #[error("bundle app '{app}' has an empty injected_as value for alias '{alias}'")]
    EmptyInjectedAs { app: String, alias: String },
    #[error("bundle export requires a valid app when app scope is selected")]
    MissingExportScope,
    #[error("invalid .env line {line}: {message}")]
    InvalidEnvLine { line: usize, message: String },
    #[error("invalid flat json: expected an object of string values")]
    InvalidFlatJson,
    #[error("invalid derived alias for key '{0}'")]
    InvalidDerivedAlias(String),
    #[error("utf-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("{0}")]
    Vault(#[from] VaultError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableBundle {
    pub schema: String,
    pub version: u32,
    #[serde(default)]
    pub secrets: Vec<PortableSecret>,
    #[serde(default)]
    pub apps: Vec<PortableApp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableSecret {
    pub alias: String,
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableApp {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub app_path: String,
    #[serde(default)]
    pub bindings: Vec<PortableBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortableBinding {
    pub alias: String,
    pub injected_as: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FlatEntry {
    alias: String,
    key: String,
    value: String,
}

pub fn export_text(
    store: &VaultStore,
    options: ExportOptions<'_>,
) -> Result<String, TransferError> {
    match options.format {
        TransferFormat::Env => Ok(format_env(
            resolved_pairs(store, options.app)?,
            options.shell_prefix,
        )),
        TransferFormat::Json => Ok(serde_json::to_string_pretty(&pairs_to_map(
            resolved_pairs(store, options.app)?,
        ))?),
        TransferFormat::EnvaJson => {
            let bundle = export_bundle(store, options.app)?;
            Ok(serde_json::to_string_pretty(&bundle)?)
        }
        TransferFormat::Yaml => {
            let bundle = export_bundle(store, options.app)?;
            bundle_to_yaml(&bundle)
        }
    }
}

pub fn import_text(
    store: &mut VaultStore,
    text: &str,
    options: ImportOptions<'_>,
) -> Result<ImportSummary, TransferError> {
    let format = match options.format {
        Some(format) => format,
        None => infer_import_format(text, options.source_name)?,
    };
    match format {
        TransferFormat::Env => {
            import_flat_entries(store, parse_env_entries(text)?, options.target_app, format)
        }
        TransferFormat::Json => import_flat_entries(
            store,
            parse_flat_json_entries(text)?,
            options.target_app,
            format,
        ),
        TransferFormat::EnvaJson => {
            if options.target_app.is_some() {
                return Err(TransferError::BundleTargetAppUnsupported);
            }
            let bundle: PortableBundle = serde_json::from_str(text)?;
            import_bundle(store, bundle, format)
        }
        TransferFormat::Yaml => {
            if options.target_app.is_some() {
                return Err(TransferError::BundleTargetAppUnsupported);
            }
            let bundle: PortableBundle = serde_yaml::from_str(text)?;
            import_bundle(store, bundle, format)
        }
    }
}

pub fn infer_import_format(
    text: &str,
    source_name: Option<&str>,
) -> Result<TransferFormat, TransferError> {
    if let Some(name) = source_name {
        if let Some(ext) = Path::new(name).extension().and_then(|value| value.to_str()) {
            match ext.to_ascii_lowercase().as_str() {
                "env" | "txt" => return Ok(TransferFormat::Env),
                "yaml" | "yml" => return Ok(TransferFormat::Yaml),
                "json" => return infer_json_format(text),
                _ => {}
            }
        }
    }

    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        return infer_json_format(text);
    }
    if trimmed.starts_with("schema:") || trimmed.contains("\nschema:") {
        return Ok(TransferFormat::Yaml);
    }
    Ok(TransferFormat::Env)
}

fn infer_json_format(text: &str) -> Result<TransferFormat, TransferError> {
    let value: serde_json::Value = serde_json::from_str(text)?;
    let object = value.as_object().ok_or(TransferError::InvalidFlatJson)?;
    if object.contains_key("schema")
        || object.contains_key("apps")
        || object.contains_key("secrets")
    {
        return Ok(TransferFormat::EnvaJson);
    }
    Ok(TransferFormat::Json)
}

fn resolved_pairs(
    store: &VaultStore,
    app: Option<&str>,
) -> Result<Vec<(String, String)>, TransferError> {
    if let Some(app_name) = app {
        let resolved = store.get_app_secrets(app_name)?;
        return Ok(resolved.into_iter().collect());
    }

    let mut pairs = Vec::new();
    for secret in store.list(None)? {
        pairs.push((secret.key.clone(), store.get(&secret.alias)?));
    }
    pairs.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    Ok(pairs)
}

fn pairs_to_map(pairs: Vec<(String, String)>) -> BTreeMap<String, String> {
    let mut mapped = BTreeMap::new();
    for (key, value) in pairs {
        mapped.insert(key, value);
    }
    mapped
}

fn format_env(pairs: Vec<(String, String)>, shell_prefix: bool) -> String {
    pairs
        .into_iter()
        .map(|(key, value)| {
            if shell_prefix {
                format!("export {key}={value}")
            } else {
                format!("{key}={value}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn bundle_to_yaml(bundle: &PortableBundle) -> Result<String, TransferError> {
    Ok([
        format!("schema: {}", serde_json::to_string(&bundle.schema)?),
        format!("version: {}", bundle.version),
        format!("secrets: {}", serde_json::to_string(&bundle.secrets)?),
        format!("apps: {}", serde_json::to_string(&bundle.apps)?),
    ]
    .join("\n"))
}

fn export_bundle(store: &VaultStore, app: Option<&str>) -> Result<PortableBundle, TransferError> {
    let secrets_by_alias = all_secret_info(store)?;
    let apps = selected_apps(store, app)?;
    let mut aliases = BTreeSet::new();
    let portable_apps = apps
        .into_iter()
        .map(|info| build_portable_app(store, &info, &mut aliases))
        .collect::<Result<Vec<_>, _>>()?;

    if app.is_none() {
        aliases.extend(secrets_by_alias.keys().cloned());
    }

    let portable_secrets = aliases
        .into_iter()
        .map(|alias| build_portable_secret(store, &secrets_by_alias, &alias))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(PortableBundle {
        schema: BUNDLE_SCHEMA.to_string(),
        version: BUNDLE_VERSION,
        secrets: portable_secrets,
        apps: portable_apps,
    })
}

fn selected_apps(store: &VaultStore, app: Option<&str>) -> Result<Vec<AppInfo>, TransferError> {
    let apps = store.list_apps();
    if let Some(app_name) = app {
        let selected = apps
            .into_iter()
            .find(|item| item.name == app_name)
            .ok_or(TransferError::MissingExportScope)?;
        return Ok(vec![selected]);
    }
    Ok(apps)
}

fn all_secret_info(store: &VaultStore) -> Result<BTreeMap<String, SecretInfo>, TransferError> {
    Ok(store
        .list(None)?
        .into_iter()
        .map(|info| (info.alias.clone(), info))
        .collect())
}

fn build_portable_secret(
    store: &VaultStore,
    secrets: &BTreeMap<String, SecretInfo>,
    alias: &str,
) -> Result<PortableSecret, TransferError> {
    let info = secrets
        .get(alias)
        .ok_or_else(|| VaultError::AliasNotFound(alias.to_string()))?;
    let mut tags = info.tags.clone();
    tags.sort();
    tags.dedup();
    Ok(PortableSecret {
        alias: alias.to_string(),
        key: info.key.clone(),
        value: store.get(alias)?,
        description: info.description.clone(),
        tags,
    })
}

fn build_portable_app(
    store: &VaultStore,
    app: &AppInfo,
    aliases: &mut BTreeSet<String>,
) -> Result<PortableApp, TransferError> {
    let bindings = store
        .get_app_secret_bindings(&app.name)?
        .into_iter()
        .map(|binding| {
            aliases.insert(binding.alias.clone());
            PortableBinding {
                alias: binding.alias,
                injected_as: binding.injected_as,
            }
        })
        .collect();
    Ok(PortableApp {
        name: app.name.clone(),
        description: app.description.clone(),
        app_path: app.app_path.clone(),
        bindings,
    })
}

fn import_bundle(
    store: &mut VaultStore,
    bundle: PortableBundle,
    format: TransferFormat,
) -> Result<ImportSummary, TransferError> {
    validate_bundle(&bundle)?;

    for secret in &bundle.secrets {
        let mut tags = secret.tags.clone();
        tags.sort();
        tags.dedup();
        store.set(
            &secret.alias,
            &secret.key,
            &secret.value,
            &secret.description,
            &tags,
        )?;
    }

    let secret_keys = all_secret_info(store)?
        .into_iter()
        .map(|(alias, info)| (alias, info.key))
        .collect::<BTreeMap<_, _>>();

    let mut assigned_bindings = 0usize;
    for app in &bundle.apps {
        if store.list_apps().iter().all(|info| info.name != app.name) {
            store.create_app(&app.name, &app.description, &app.app_path)?;
        }
        let entry = store.get_app_entry_mut(&app.name)?;
        entry.description = app.description.clone();
        entry.app_path = app.app_path.clone();
        for binding in &app.bindings {
            let key = secret_keys.get(&binding.alias).ok_or_else(|| {
                TransferError::MissingBundleSecret {
                    app: app.name.clone(),
                    alias: binding.alias.clone(),
                }
            })?;
            let override_key = if binding.injected_as == *key {
                None
            } else {
                Some(binding.injected_as.as_str())
            };
            store.assign(&app.name, &binding.alias, override_key)?;
            assigned_bindings += 1;
        }
    }

    Ok(ImportSummary {
        format: format.canonical_name().to_string(),
        imported_secrets: bundle.secrets.len(),
        imported_apps: bundle.apps.len(),
        assigned_bindings,
    })
}

fn validate_bundle(bundle: &PortableBundle) -> Result<(), TransferError> {
    if bundle.schema != BUNDLE_SCHEMA {
        return Err(TransferError::InvalidBundleSchema(bundle.schema.clone()));
    }
    if bundle.version != BUNDLE_VERSION {
        return Err(TransferError::UnsupportedBundleVersion(bundle.version));
    }

    let mut seen_secrets = BTreeSet::new();
    for secret in &bundle.secrets {
        if !seen_secrets.insert(secret.alias.clone()) {
            return Err(TransferError::DuplicateSecretAlias(secret.alias.clone()));
        }
    }

    let secret_aliases = seen_secrets;
    let mut seen_apps = BTreeSet::new();
    for app in &bundle.apps {
        if !seen_apps.insert(app.name.clone()) {
            return Err(TransferError::DuplicateAppName(app.name.clone()));
        }
        let mut seen_bindings = BTreeSet::new();
        for binding in &app.bindings {
            if binding.injected_as.trim().is_empty() {
                return Err(TransferError::EmptyInjectedAs {
                    app: app.name.clone(),
                    alias: binding.alias.clone(),
                });
            }
            if !secret_aliases.contains(&binding.alias) {
                return Err(TransferError::MissingBundleSecret {
                    app: app.name.clone(),
                    alias: binding.alias.clone(),
                });
            }
            seen_bindings.insert(binding.alias.clone());
        }
    }
    Ok(())
}

fn import_flat_entries(
    store: &mut VaultStore,
    entries: Vec<FlatEntry>,
    target_app: Option<&str>,
    format: TransferFormat,
) -> Result<ImportSummary, TransferError> {
    let mut assigned_bindings = 0usize;
    for entry in &entries {
        store.set(&entry.alias, &entry.key, &entry.value, "", &[])?;
        if let Some(app) = target_app {
            store.assign(app, &entry.alias, None)?;
            assigned_bindings += 1;
        }
    }
    Ok(ImportSummary {
        format: format.canonical_name().to_string(),
        imported_secrets: entries.len(),
        imported_apps: usize::from(target_app.is_some()),
        assigned_bindings,
    })
}

fn parse_flat_json_entries(text: &str) -> Result<Vec<FlatEntry>, TransferError> {
    let value: serde_json::Value = serde_json::from_str(text)?;
    let object = value.as_object().ok_or(TransferError::InvalidFlatJson)?;
    object
        .iter()
        .map(|(key, value)| {
            let value = value
                .as_str()
                .ok_or(TransferError::InvalidFlatJson)?
                .to_string();
            Ok(FlatEntry {
                alias: alias_from_key(key)?,
                key: key.clone(),
                value,
            })
        })
        .collect()
}

fn parse_env_entries(text: &str) -> Result<Vec<FlatEntry>, TransferError> {
    text.lines()
        .enumerate()
        .filter_map(|(idx, line)| match parse_env_line(idx + 1, line) {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn parse_env_line(line_number: usize, line: &str) -> Result<Option<FlatEntry>, TransferError> {
    let mut trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }
    if let Some(rest) = trimmed.strip_prefix("export ") {
        trimmed = rest.trim_start();
    }
    let Some((raw_key, raw_value)) = trimmed.split_once('=') else {
        return Err(TransferError::InvalidEnvLine {
            line: line_number,
            message: "expected KEY=VALUE".to_string(),
        });
    };
    let key = raw_key.trim();
    if key.is_empty() {
        return Err(TransferError::InvalidEnvLine {
            line: line_number,
            message: "missing key".to_string(),
        });
    }
    let value = parse_env_value(raw_value.trim(), line_number)?;
    Ok(Some(FlatEntry {
        alias: alias_from_key(key)?,
        key: key.to_string(),
        value,
    }))
}

fn parse_env_value(value: &str, line_number: usize) -> Result<String, TransferError> {
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        let mut result = String::new();
        let mut chars = value[1..value.len() - 1].chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                let escaped = chars.next().ok_or_else(|| TransferError::InvalidEnvLine {
                    line: line_number,
                    message: "unfinished escape sequence".to_string(),
                })?;
                match escaped {
                    'n' => result.push('\n'),
                    'r' => result.push('\r'),
                    't' => result.push('\t'),
                    '\\' => result.push('\\'),
                    '"' => result.push('"'),
                    other => result.push(other),
                }
            } else {
                result.push(ch);
            }
        }
        return Ok(result);
    }

    if value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2 {
        return Ok(value[1..value.len() - 1].to_string());
    }

    Ok(value.to_string())
}

fn alias_from_key(key: &str) -> Result<String, TransferError> {
    let mut alias = String::new();
    let mut previous_separator = false;
    for ch in key.chars() {
        if ch.is_ascii_alphanumeric() {
            alias.push(ch.to_ascii_lowercase());
            previous_separator = false;
            continue;
        }
        if (ch == '_' || ch == '-' || !ch.is_ascii()) && !alias.is_empty() && !previous_separator {
            alias.push('-');
            previous_separator = true;
        }
    }
    while alias.ends_with('-') {
        alias.pop();
    }
    if alias.is_empty() {
        return Err(TransferError::InvalidDerivedAlias(key.to_string()));
    }
    if alias.len() > 63 {
        alias.truncate(63);
        while alias.ends_with('-') {
            alias.pop();
        }
    }
    if alias.is_empty() {
        return Err(TransferError::InvalidDerivedAlias(key.to_string()));
    }
    Ok(alias)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::VaultStore;
    use tempfile::tempdir;

    fn test_store() -> VaultStore {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("bundle.vault.json");
        let mut store = VaultStore::create(path.to_str().unwrap(), "testpass", None).unwrap();
        store
            .set(
                "db-url",
                "DATABASE_URL",
                "postgres://example",
                "db connection",
                &["database".to_string(), "primary".to_string()],
            )
            .unwrap();
        store
            .set("api-key", "API_KEY", "super-secret", "token", &[])
            .unwrap();
        store
            .create_app("backend", "Backend", "/srv/backend")
            .unwrap();
        store
            .assign("backend", "db-url", Some("BACKEND_DB"))
            .unwrap();
        store.assign("backend", "api-key", None).unwrap();
        store
    }

    #[test]
    fn parse_env_entries_accepts_export_prefix_and_quotes() {
        let entries =
            parse_env_entries("export DATABASE_URL=\"postgres\\nurl\"\nAPI_KEY='abc'\n").unwrap();
        assert_eq!(entries[0].key, "DATABASE_URL");
        assert_eq!(entries[0].value, "postgres\nurl");
        assert_eq!(entries[1].value, "abc");
    }

    #[test]
    fn infer_import_format_detects_bundle_json() {
        let bundle = PortableBundle {
            schema: BUNDLE_SCHEMA.to_string(),
            version: BUNDLE_VERSION,
            secrets: vec![],
            apps: vec![],
        };
        let json = serde_json::to_string(&bundle).unwrap();
        assert_eq!(
            infer_import_format(&json, Some("bundle.json")).unwrap(),
            TransferFormat::EnvaJson
        );
    }

    #[test]
    fn bundle_export_and_import_round_trip_preserves_bindings() {
        let store = test_store();
        let exported = export_text(
            &store,
            ExportOptions {
                format: TransferFormat::EnvaJson,
                app: Some("backend"),
                shell_prefix: true,
            },
        )
        .unwrap();

        let tmp = tempdir().unwrap();
        let path = tmp.path().join("imported.vault.json");
        let mut imported = VaultStore::create(path.to_str().unwrap(), "testpass", None).unwrap();
        let summary = import_text(
            &mut imported,
            &exported,
            ImportOptions {
                format: Some(TransferFormat::EnvaJson),
                source_name: Some("bundle.json"),
                target_app: None,
            },
        )
        .unwrap();

        assert_eq!(summary.imported_secrets, 2);
        assert_eq!(summary.imported_apps, 1);
        let resolved = imported.get_app_secrets("backend").unwrap();
        assert_eq!(resolved["BACKEND_DB"], "postgres://example");
        assert_eq!(resolved["API_KEY"], "super-secret");
    }

    #[test]
    fn yaml_bundle_round_trip_preserves_schema() {
        let store = test_store();
        let yaml = export_text(
            &store,
            ExportOptions {
                format: TransferFormat::Yaml,
                app: Some("backend"),
                shell_prefix: false,
            },
        )
        .unwrap();
        assert!(yaml.contains("schema: \"enva-bundle\""));

        let tmp = tempdir().unwrap();
        let path = tmp.path().join("yaml-imported.vault.json");
        let mut imported = VaultStore::create(path.to_str().unwrap(), "testpass", None).unwrap();
        import_text(
            &mut imported,
            &yaml,
            ImportOptions {
                format: Some(TransferFormat::Yaml),
                source_name: Some("bundle.yaml"),
                target_app: None,
            },
        )
        .unwrap();

        let resolved = imported.get_app_secrets("backend").unwrap();
        assert_eq!(resolved["BACKEND_DB"], "postgres://example");
    }

    #[test]
    fn bundle_import_merges_existing_app_bindings() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("merge-existing.vault.json");
        let mut store = VaultStore::create(path.to_str().unwrap(), "testpass", None).unwrap();
        store
            .set("existing", "EXISTING_KEY", "existing-value", "", &[])
            .unwrap();
        store
            .set("db-url", "DATABASE_URL", "postgres://example", "", &[])
            .unwrap();
        store
            .create_app("backend", "Backend", "/srv/backend")
            .unwrap();
        store.assign("backend", "existing", None).unwrap();

        let bundle = PortableBundle {
            schema: BUNDLE_SCHEMA.to_string(),
            version: BUNDLE_VERSION,
            secrets: vec![PortableSecret {
                alias: "db-url".to_string(),
                key: "DATABASE_URL".to_string(),
                value: "postgres://example".to_string(),
                description: String::new(),
                tags: vec![],
            }],
            apps: vec![PortableApp {
                name: "backend".to_string(),
                description: "Backend".to_string(),
                app_path: "/srv/backend".to_string(),
                bindings: vec![PortableBinding {
                    alias: "db-url".to_string(),
                    injected_as: "BACKEND_DB".to_string(),
                }],
            }],
        };

        let payload = serde_json::to_string(&bundle).unwrap();
        import_text(
            &mut store,
            &payload,
            ImportOptions {
                format: Some(TransferFormat::EnvaJson),
                source_name: Some("bundle.json"),
                target_app: None,
            },
        )
        .unwrap();

        let resolved = store.get_app_secrets("backend").unwrap();
        assert_eq!(resolved["EXISTING_KEY"], "existing-value");
        assert_eq!(resolved["BACKEND_DB"], "postgres://example");
    }

    #[test]
    fn flat_json_import_uses_key_names_for_aliases() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("flat-json.vault.json");
        let mut store = VaultStore::create(path.to_str().unwrap(), "testpass", None).unwrap();
        let summary = import_text(
            &mut store,
            r#"{"DATABASE_URL":"postgres://example"}"#,
            ImportOptions {
                format: Some(TransferFormat::Json),
                source_name: Some("env.json"),
                target_app: Some("backend"),
            },
        )
        .unwrap();

        assert_eq!(summary.assigned_bindings, 1);
        let resolved = store.get_app_secrets("backend").unwrap();
        assert_eq!(resolved["DATABASE_URL"], "postgres://example");
    }
}
