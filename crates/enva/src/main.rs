mod config;
mod paths;
mod ssh_config;
mod ssh_hosts;
mod sync;
mod update;
mod vault;
mod web;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "enva",
    version,
    about = "Enva — encrypted environment variable manager with per-app injection and web UI",
    long_about = "Enva manages encrypted secrets in a local vault and injects them as environment\n\
                   variables into applications.\n\n\
                   Usage patterns:\n  \
                   enva                          Start the web configuration UI\n  \
                   enva <APP>                    Launch app_path with secrets (or dry-run if no path set)\n  \
                   enva <APP> -- <cmd>           Inject env vars and exec <cmd>\n  \
                   enva vault <subcommand>       Manage vault contents\n  \
                   enva serve                    Start web UI (explicit alias)\n  \
                   enva --env staging vault list Load .enva.staging.yaml overlay"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to vault file
    #[arg(long, global = true, env = "ENVA_VAULT_PATH")]
    vault: Option<String>,

    /// Path to config file
    #[arg(long, global = true, env = "ENVA_CONFIG")]
    config: Option<String>,

    /// Environment name for config overlay (loads .enva.{env}.yaml)
    #[arg(long, global = true)]
    env: Option<String>,

    /// Vault password (prefer --password-stdin or ENVA_PASSWORD for scripts)
    #[arg(long, short = 'P', global = true, env = "ENVA_PASSWORD")]
    password: Option<String>,

    /// Read password from stdin
    #[arg(long, global = true)]
    password_stdin: bool,

    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Vault management operations (init, set, get, list, delete, assign, etc.)
    Vault {
        #[command(subcommand)]
        cmd: VaultCommands,
    },
    /// Update the installed enva binary from GitHub Releases
    Update {
        /// Target release tag (defaults to the latest published release)
        #[arg(long)]
        version: Option<String>,
        /// Force reinstall the current version or allow downgrades
        #[arg(long)]
        force: bool,
    },
    /// Start the web configuration UI
    Serve {
        /// Port to listen on
        #[arg(short = 'p', long, default_value = "8080")]
        port: u16,
        /// Host to bind to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
    },
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Debug, Subcommand)]
enum VaultCommands {
    /// Create a new encrypted vault
    Init {
        /// Path for the new vault file
        #[arg(long)]
        vault: String,
    },
    /// Add or update a secret in the vault
    Set {
        /// Unique alias for the secret
        alias: String,
        /// Environment variable name
        #[arg(short, long)]
        key: String,
        /// Secret value
        #[arg(short = 'V', long)]
        value: String,
        /// Description
        #[arg(short, long, default_value = "")]
        description: String,
        /// Comma-separated tags
        #[arg(short, long, default_value = "")]
        tags: String,
    },
    /// Edit an existing secret (update individual fields without replacing all)
    Edit {
        /// Secret alias to edit
        alias: String,
        /// New environment variable name
        #[arg(short, long)]
        key: Option<String>,
        /// New secret value
        #[arg(short = 'V', long)]
        value: Option<String>,
        /// New description
        #[arg(short, long)]
        description: Option<String>,
        /// New comma-separated tags (replaces existing)
        #[arg(short, long)]
        tags: Option<String>,
    },
    /// Decrypt and print a secret
    Get {
        /// Secret alias
        alias: String,
    },
    /// List secrets in the vault
    List {
        /// Filter by app
        #[arg(short, long)]
        app: Option<String>,
    },
    /// Delete a secret from the vault
    Delete {
        /// Secret alias
        alias: String,
        /// Skip confirmation
        #[arg(short, long)]
        yes: bool,
    },
    /// Assign a secret to an app
    Assign {
        /// Secret alias
        alias: String,
        /// App name
        #[arg(short, long)]
        app: String,
        /// Override env var name for injection
        #[arg(long = "as")]
        override_key: Option<String>,
    },
    /// Remove a secret from an app
    Unassign {
        /// Secret alias
        alias: String,
        /// App name
        #[arg(short, long)]
        app: String,
    },
    /// Export resolved secrets for an app
    Export {
        /// App name
        #[arg(short, long)]
        app: String,
        /// Output format (env or json)
        #[arg(short, long, default_value = "env")]
        format: String,
    },
    /// Import secrets from a .env file
    ImportEnv {
        /// Path to .env file
        #[arg(long = "from")]
        from_file: String,
        /// App to assign imported secrets to
        #[arg(short, long)]
        app: String,
    },
    /// Upload the current vault to a remote SSH server
    Deploy {
        /// Remote target in the form user@host:/path/to/vault.json
        #[arg(long)]
        to: String,
        /// SSH port
        #[arg(long, default_value_t = 22)]
        ssh_port: u16,
        /// SSH password (falls back to SSH agent when omitted)
        #[arg(long, env = "ENVA_SSH_PASSWORD")]
        ssh_password: Option<String>,
        /// SSH private key path
        #[arg(long)]
        ssh_key: Option<String>,
        /// SSH private key passphrase
        #[arg(long, env = "ENVA_SSH_PASSPHRASE")]
        ssh_passphrase: Option<String>,
        /// Replace the remote vault if it already exists
        #[arg(long)]
        overwrite: bool,
    },
    /// Download a vault from a remote SSH server
    SyncFrom {
        /// Remote target in the form user@host:/path/to/vault.json
        #[arg(long = "from")]
        from: String,
        /// SSH port
        #[arg(long, default_value_t = 22)]
        ssh_port: u16,
        /// SSH password (falls back to SSH agent when omitted)
        #[arg(long, env = "ENVA_SSH_PASSWORD")]
        ssh_password: Option<String>,
        /// SSH private key path
        #[arg(long)]
        ssh_key: Option<String>,
        /// SSH private key passphrase
        #[arg(long, env = "ENVA_SSH_PASSPHRASE")]
        ssh_passphrase: Option<String>,
        /// Replace the local vault if it already exists
        #[arg(long, conflicts_with = "merge")]
        overwrite: bool,
        /// Merge remote vault into local instead of replacing
        #[arg(long)]
        merge: bool,
        /// Auto-resolve all conflicts by keeping local values (requires --merge)
        #[arg(long, requires = "merge", conflicts_with = "prefer_remote")]
        prefer_local: bool,
        /// Auto-resolve all conflicts by keeping remote values (requires --merge)
        #[arg(long, requires = "merge", conflicts_with = "prefer_local")]
        prefer_remote: bool,
    },
    /// Verify installation integrity
    SelfTest,
}

fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(if cli.verbose { "debug" } else { "warn" })
        .init();

    let result = run(cli);
    if let Err(e) = result {
        let msg = e.to_string();
        if !msg.is_empty() {
            eprintln!("Error: {msg}");
        }
        let code = if let Some(update_error) = e.downcast_ref::<update::UpdateError>() {
            update_error.exit_code()
        } else if msg.contains("authentication failed")
            || msg.contains("HMAC verification failed")
            || msg.contains("missing HMAC")
            || msg.contains("password")
        {
            2
        } else if msg.contains("alias not found") || msg.contains("app not found") {
            3
        } else {
            1
        };
        std::process::exit(code);
    }
}

fn get_password(cli: &Cli) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(ref pw) = cli.password {
        tracing::debug!("using password from --password flag");
        return Ok(pw.clone());
    }
    if cli.password_stdin {
        tracing::debug!("reading password from stdin");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        return Ok(line.trim_end().to_string());
    }
    tracing::debug!("prompting for password interactively");
    Ok(rpassword::prompt_password("Vault password: ")?)
}

fn resolve_vault_path(cli: &Cli) -> Result<String, paths::PathResolutionError> {
    if let Some(ref vp) = cli.vault {
        let resolved = paths::resolve_vault_path(vp)?;
        tracing::debug!(raw_vault_path = %vp, resolved_vault_path = %resolved, "using vault path from --vault flag");
        return Ok(resolved);
    }
    let cfg = config::ConfigLoader::load(cli.config.as_deref(), cli.env.as_deref());
    let resolved = cfg.resolve_vault_path()?;
    tracing::debug!(vault_path = %resolved, "resolved vault path from config");
    Ok(resolved)
}

fn resolve_launch_app_path(
    store: &vault::VaultStore,
    cfg: &config::Config,
    app_name: &str,
) -> Result<Option<String>, paths::PathResolutionError> {
    let stored_app_path = store.get_app_path(app_name).unwrap_or_default();
    if let Some(resolved) = paths::resolve_optional_app_path(&stored_app_path)? {
        tracing::debug!(app = %app_name, raw_app_path = %stored_app_path, resolved_app_path = %resolved, "resolved application path from vault");
        return Ok(Some(resolved));
    }

    if let Some(resolved) = cfg.resolve_app_path(app_name)? {
        tracing::debug!(app = %app_name, resolved_app_path = %resolved, "resolved application path from config");
        return Ok(Some(resolved));
    }

    Ok(None)
}

fn ssh_auth_options(
    ssh_password: Option<&String>,
    ssh_key: Option<&String>,
    ssh_passphrase: Option<&String>,
) -> sync::SshAuthOptions {
    sync::SshAuthOptions {
        password: ssh_password.cloned(),
        key_path: ssh_key.cloned(),
        passphrase: ssh_passphrase.cloned(),
    }
}

fn build_merge_resolutions(
    diff: &vault::VaultDiff,
    prefer_local: bool,
    prefer_remote: bool,
) -> Result<Vec<vault::ConflictResolution>, Box<dyn std::error::Error>> {
    use vault::{ConflictResolution, DiffStatus};

    let conflicts: Vec<_> = diff
        .secrets
        .iter()
        .filter(|s| s.status == DiffStatus::Modified)
        .map(|s| ("secret", s.alias.as_str(), s.local_key.as_deref()))
        .chain(
            diff.apps
                .iter()
                .filter(|a| a.status == DiffStatus::Modified)
                .map(|a| ("app", a.name.as_str(), None)),
        )
        .collect();

    if conflicts.is_empty() {
        return Ok(Vec::new());
    }

    if prefer_local {
        return Ok(conflicts
            .into_iter()
            .map(|(_, key, _)| ConflictResolution::KeepLocal {
                key: key.to_owned(),
            })
            .collect());
    }
    if prefer_remote {
        return Ok(conflicts
            .into_iter()
            .map(|(_, key, _)| ConflictResolution::KeepRemote {
                key: key.to_owned(),
            })
            .collect());
    }

    let mut resolutions = Vec::with_capacity(conflicts.len());
    let stdin = std::io::stdin();
    for (kind, name, env_key) in &conflicts {
        let key_info = env_key.map(|k| format!(" (key: {k})")).unwrap_or_default();
        eprintln!("Conflict in {kind} '{name}'{key_info} — [l]ocal / [r]emote / [b]oth? ",);
        let mut input = String::new();
        stdin.read_line(&mut input)?;
        let resolution = match input.trim().to_lowercase().as_str() {
            "r" | "remote" => ConflictResolution::KeepRemote {
                key: name.to_string(),
            },
            "b" | "both" => ConflictResolution::KeepBoth {
                key: name.to_string(),
            },
            _ => ConflictResolution::KeepLocal {
                key: name.to_string(),
            },
        };
        resolutions.push(resolution);
    }
    Ok(resolutions)
}

fn run_update_command(
    cli: &Cli,
    version: Option<&str>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match update::update_binary(version, force)? {
        update::UpdateOutcome::Updated(result) => {
            if !cli.quiet {
                println!("Updated enva to {}", result.updated_version);
            }
        }
        update::UpdateOutcome::AlreadyUpToDate { current_version } => {
            if !cli.quiet {
                println!("Already up to date ({current_version})");
            }
        }
    }
    Ok(())
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    tracing::debug!(command = ?cli.command, "dispatching command");
    match &cli.command {
        None => run_serve(&cli, "127.0.0.1", 8080),
        Some(Commands::Update { version, force }) => {
            run_update_command(&cli, version.as_deref(), *force)
        }
        Some(Commands::Serve { port, host }) => run_serve(&cli, host, *port),
        Some(Commands::Vault { cmd }) => run_vault_command(&cli, cmd),
        Some(Commands::External(args)) => run_app(&cli, args),
    }
}

fn run_serve(cli: &Cli, host: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let vp = resolve_vault_path(cli)?;
    tracing::debug!(host, port, vault_path = %vp, "starting web server");
    if !cli.quiet {
        println!("Enva Web UI: http://{host}:{port}");
    }
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(web::serve(&vp, host, port))?;
    Ok(())
}

fn run_app(cli: &Cli, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        return Err("No app name provided.".into());
    }

    let app_name = &args[0];
    tracing::debug!(app = %app_name, args = ?&args[1..], "running app injection");

    let separator = args.iter().position(|a| a == "--");
    let command_args: Vec<&str> = match separator {
        Some(pos) => args[pos + 1..].iter().map(|s| s.as_str()).collect(),
        None => args[1..].iter().map(|s| s.as_str()).collect(),
    };

    let vp = resolve_vault_path(cli)?;
    let pw = get_password(cli)?;
    let store = vault::VaultStore::load(&vp, &pw)?;
    let injected = store.get_app_secrets(app_name)?;

    let cfg = config::ConfigLoader::load(cli.config.as_deref(), cli.env.as_deref());
    let override_system = cfg
        .apps
        .get(app_name)
        .map(|a| a.override_system)
        .unwrap_or(false);
    let resolved: std::collections::BTreeMap<String, String> = if override_system {
        injected
    } else {
        injected
            .into_iter()
            .filter(|(k, _)| std::env::var(k).is_err())
            .collect()
    };
    let launch_app_path = resolve_launch_app_path(&store, &cfg, app_name)?;

    if command_args.is_empty() {
        if let Some(ref app_path) = launch_app_path {
            tracing::debug!(app = %app_name, app_path = %app_path, "launching via app_path");
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                let err = std::process::Command::new(app_path).envs(&resolved).exec();
                return Err(Box::new(err));
            }
            #[cfg(not(unix))]
            {
                let status = std::process::Command::new(&app_path)
                    .envs(&resolved)
                    .status()?;
                std::process::exit(status.code().unwrap_or(1));
            }
        }
        if resolved.is_empty() {
            println!("No secrets assigned to app '{app_name}'.");
        } else {
            println!("Environment variables for app '{app_name}':");
            for key in resolved.keys() {
                println!("  {key}=<redacted>");
            }
            println!("\nRun with a command to inject: enva {app_name} -- <cmd>");
            if launch_app_path.is_none() {
                println!("Tip: set app_path to launch directly with: enva {app_name}");
            }
        }
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(command_args[0])
            .args(&command_args[1..])
            .envs(resolved)
            .exec();
        Err(Box::new(err))
    }
    #[cfg(not(unix))]
    {
        let status = std::process::Command::new(command_args[0])
            .args(&command_args[1..])
            .envs(resolved)
            .status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn run_vault_command(cli: &Cli, cmd: &VaultCommands) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        VaultCommands::Init { vault: vault_path } => {
            let resolved_vault_path = paths::resolve_vault_path(vault_path)?;
            if std::path::Path::new(&resolved_vault_path).exists() {
                return Err(format!("Vault already exists at {resolved_vault_path}. Delete it first or choose a different path.").into());
            }
            let password = if let Some(ref pw) = cli.password {
                pw.clone()
            } else if cli.password_stdin {
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                line.trim_end().to_string()
            } else {
                let password = rpassword::prompt_password("Set vault password: ")?;
                let confirm = rpassword::prompt_password("Confirm password: ")?;
                if password != confirm {
                    eprintln!("Passwords do not match.");
                    std::process::exit(1);
                }
                password
            };
            vault::VaultStore::create(&resolved_vault_path, &password, None)?;
            if !cli.quiet {
                println!("Vault created: {resolved_vault_path}");
            }
        }
        VaultCommands::Set {
            alias,
            key,
            value,
            description,
            tags,
        } => {
            let vp = resolve_vault_path(cli)?;
            let pw = get_password(cli)?;
            let mut store = vault::VaultStore::load(&vp, &pw)?;
            let tag_list: Vec<String> = tags
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            store.set(alias, key, value, description, &tag_list)?;
            store.save()?;
            if !cli.quiet {
                println!("Secret \x1b[36m{alias}\x1b[0m set (key=\x1b[33m{key}\x1b[0m)");
            }
        }
        VaultCommands::Edit {
            alias,
            key,
            value,
            description,
            tags,
        } => {
            if key.is_none() && value.is_none() && description.is_none() && tags.is_none() {
                return Err("Nothing to edit. Provide at least one of --key, --value, --description, or --tags.".into());
            }
            let vp = resolve_vault_path(cli)?;
            let pw = get_password(cli)?;
            let mut store = vault::VaultStore::load(&vp, &pw)?;
            let tag_list: Option<Vec<String>> = tags.as_ref().map(|t| {
                t.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            });
            store.edit(
                alias,
                key.as_deref(),
                value.as_deref(),
                description.as_deref(),
                tag_list.as_deref(),
            )?;
            store.save()?;
            if !cli.quiet {
                let mut fields = Vec::new();
                if key.is_some() {
                    fields.push("key");
                }
                if value.is_some() {
                    fields.push("value");
                }
                if description.is_some() {
                    fields.push("description");
                }
                if tag_list.is_some() {
                    fields.push("tags");
                }
                println!("Updated \x1b[36m{alias}\x1b[0m ({})", fields.join(", "));
            }
        }
        VaultCommands::Get { alias } => {
            let vp = resolve_vault_path(cli)?;
            let pw = get_password(cli)?;
            let store = vault::VaultStore::load(&vp, &pw)?;
            let value = store.get(alias)?;
            println!("{value}");
        }
        VaultCommands::List { app } => {
            let vp = resolve_vault_path(cli)?;
            let pw = get_password(cli)?;
            let store = vault::VaultStore::load(&vp, &pw)?;
            let secrets = store.list(app.as_deref())?;
            if secrets.is_empty() {
                println!("No secrets found.");
                return Ok(());
            }
            println!(
                "{:<24} {:<24} {:<20} {:<20}",
                "ALIAS", "KEY", "APPS", "UPDATED"
            );
            println!("{}", "-".repeat(88));
            for s in &secrets {
                let apps_str = if s.apps.is_empty() {
                    "unassigned".to_string()
                } else {
                    s.apps.join(",")
                };
                println!(
                    "{:<24} {:<24} {:<20} {:<20}",
                    s.alias,
                    s.key,
                    apps_str,
                    &s.updated_at[..16.min(s.updated_at.len())]
                );
            }
        }
        VaultCommands::Delete { alias, yes } => {
            if !yes {
                eprint!("Delete secret '{alias}'? [y/N] ");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    return Ok(());
                }
            }
            let vp = resolve_vault_path(cli)?;
            let pw = get_password(cli)?;
            let mut store = vault::VaultStore::load(&vp, &pw)?;
            store.delete(alias)?;
            store.save()?;
            if !cli.quiet {
                println!("Deleted: {alias}");
            }
        }
        VaultCommands::Assign {
            alias,
            app,
            override_key,
        } => {
            let vp = resolve_vault_path(cli)?;
            let pw = get_password(cli)?;
            let mut store = vault::VaultStore::load(&vp, &pw)?;
            store.assign(app, alias, override_key.as_deref())?;
            store.save()?;
            let msg = match override_key {
                Some(k) => format!("Assigned {alias} to {app} (injected as {k})"),
                None => format!("Assigned {alias} to {app}"),
            };
            if !cli.quiet {
                println!("{msg}");
            }
        }
        VaultCommands::Unassign { alias, app } => {
            let vp = resolve_vault_path(cli)?;
            let pw = get_password(cli)?;
            let mut store = vault::VaultStore::load(&vp, &pw)?;
            store.unassign(app, alias)?;
            store.save()?;
            if !cli.quiet {
                println!("Unassigned {alias} from {app}");
            }
        }
        VaultCommands::Export { app, format } => {
            let vp = resolve_vault_path(cli)?;
            let pw = get_password(cli)?;
            let store = vault::VaultStore::load(&vp, &pw)?;
            let resolved = store.get_app_secrets(app)?;
            match format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&resolved)?),
                _ => {
                    for (k, v) in &resolved {
                        println!("export {k}={v}");
                    }
                }
            }
        }
        VaultCommands::ImportEnv { from_file, app } => {
            let vp = resolve_vault_path(cli)?;
            let pw = get_password(cli)?;
            let mut store = vault::VaultStore::load(&vp, &pw)?;
            if store.list_apps().iter().all(|a| a.name != *app) {
                store.create_app(app, "", "")?;
            }
            let content = std::fs::read_to_string(from_file)?;
            let mut count = 0u32;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((key, value)) = line.split_once('=') {
                    let key = key.trim();
                    let value = value.trim().trim_matches('"').trim_matches('\'');
                    let alias = key.to_lowercase().replace('_', "-");
                    store.set(&alias, key, value, "", &[])?;
                    store.assign(app, &alias, None)?;
                    count += 1;
                }
            }
            store.save()?;
            if !cli.quiet {
                println!("Imported {count} secrets into app '{app}'");
            }
        }
        VaultCommands::Deploy {
            to,
            ssh_port,
            ssh_password,
            ssh_key,
            ssh_passphrase,
            overwrite,
        } => {
            let vp = resolve_vault_path(cli)?;
            let pw = get_password(cli)?;
            sync::deploy_vault(
                &vp,
                &pw,
                to,
                *ssh_port,
                *overwrite,
                ssh_auth_options(
                    ssh_password.as_ref(),
                    ssh_key.as_ref(),
                    ssh_passphrase.as_ref(),
                ),
            )?;
            if !cli.quiet {
                println!("Deployed vault to {to}");
            }
        }
        VaultCommands::SyncFrom {
            from,
            ssh_port,
            ssh_password,
            ssh_key,
            ssh_passphrase,
            overwrite,
            merge,
            prefer_local,
            prefer_remote,
        } => {
            let vp = resolve_vault_path(cli)?;
            let pw = get_password(cli)?;
            let auth = ssh_auth_options(
                ssh_password.as_ref(),
                ssh_key.as_ref(),
                ssh_passphrase.as_ref(),
            );
            if *merge {
                let remote_bytes = sync::download_remote_vault(from, *ssh_port, auth)?;
                let mut local_store =
                    vault::VaultStore::load(&vp, &pw).map_err(|e| e.to_string())?;
                let remote_store = vault::VaultStore::load_from_bytes(&remote_bytes, &pw)
                    .map_err(|e| e.to_string())?;
                let diff = local_store.diff(&remote_store);

                if diff.secrets.is_empty() && diff.apps.is_empty() {
                    if !cli.quiet {
                        println!("Vaults are identical — nothing to merge.");
                    }
                    return Ok(());
                }

                let resolutions = build_merge_resolutions(&diff, *prefer_local, *prefer_remote)?;

                local_store
                    .merge_from(&remote_store, &resolutions, None, None)
                    .map_err(|e| e.to_string())?;
                local_store.save().map_err(|e| e.to_string())?;
                if !cli.quiet {
                    println!("Merged vault from {from}");
                }
            } else {
                sync::sync_from_remote(&vp, &pw, from, *ssh_port, *overwrite, auth)?;
                if !cli.quiet {
                    println!("Synced vault from {from}");
                }
            }
        }
        VaultCommands::SelfTest => {
            println!("Running self-test...");
            let salt = enva_core::vault_crypto::gen_salt();
            let (ek, hk) = enva_core::vault_crypto::derive_key("test", &salt, 1024, 1, 1)
                .map_err(|e| format!("KDF failed: {e}"))?;
            let enc = enva_core::vault_crypto::encrypt_value(&ek, "hello", "test")
                .map_err(|e| format!("Encrypt failed: {e}"))?;
            let dec = enva_core::vault_crypto::decrypt_value(&ek, &enc, "test")
                .map_err(|e| format!("Decrypt failed: {e}"))?;
            let mac = enva_core::vault_crypto::compute_hmac(&hk, b"data")
                .map_err(|e| format!("HMAC compute failed: {e}"))?;
            let ok = enva_core::vault_crypto::verify_hmac(&hk, b"data", &mac)
                .map_err(|e| format!("HMAC verify failed: {e}"))?;
            let pass = |b: bool| {
                if b {
                    "\x1b[32mPASS\x1b[0m"
                } else {
                    "\x1b[31mFAIL\x1b[0m"
                }
            };
            println!("  [{}] Argon2id key derivation", pass(ek.len() == 32));
            println!("  [{}] AES-256-GCM encrypt/decrypt", pass(dec == "hello"));
            println!("  [{}] HMAC-SHA256 verify", pass(ok));
            if dec != "hello" || !ok {
                std::process::exit(1);
            }
            println!("All checks passed.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use super::*;

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

    #[test]
    fn resolve_launch_app_path_prefers_vault_app_path() {
        let _lock = current_dir_lock().lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let _cwd = push_current_dir(tmp.path());

        let vault_path = tmp.path().join("vault.json");
        let mut store =
            vault::VaultStore::create(vault_path.to_str().unwrap(), "testpass", None).unwrap();
        store.create_app("backend", "", "./bin/from-vault").unwrap();

        let mut cfg = config::Config::default();
        cfg.apps.insert(
            "backend".to_owned(),
            config::AppConfig {
                app_path: "./bin/from-config".to_owned(),
                ..config::AppConfig::default()
            },
        );

        let resolved = resolve_launch_app_path(&store, &cfg, "backend")
            .unwrap()
            .unwrap();
        assert_eq!(
            resolved,
            tmp.path().join("./bin/from-vault").to_string_lossy()
        );
    }

    #[test]
    fn resolve_launch_app_path_falls_back_to_config_app_path() {
        let _lock = current_dir_lock().lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let _cwd = push_current_dir(tmp.path());

        let vault_path = tmp.path().join("vault.json");
        let mut store =
            vault::VaultStore::create(vault_path.to_str().unwrap(), "testpass", None).unwrap();
        store.create_app("backend", "", "").unwrap();

        let mut cfg = config::Config::default();
        cfg.apps.insert(
            "backend".to_owned(),
            config::AppConfig {
                app_path: "./bin/from-config".to_owned(),
                ..config::AppConfig::default()
            },
        );

        let resolved = resolve_launch_app_path(&store, &cfg, "backend")
            .unwrap()
            .unwrap();
        assert_eq!(
            resolved,
            tmp.path().join("./bin/from-config").to_string_lossy()
        );
    }

    #[test]
    fn serve_short_port_flag_is_accepted() {
        let cli = Cli::try_parse_from(["enva", "serve", "-p", "9091"]).unwrap();
        assert!(cli.password.is_none());
        match cli.command.as_ref() {
            Some(Commands::Serve { port, host }) => {
                assert_eq!(*port, 9091);
                assert_eq!(host, "127.0.0.1");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn password_short_flag_uses_uppercase_p() {
        let cli = Cli::try_parse_from(["enva", "-P", "secret", "vault", "list"]).unwrap();
        assert_eq!(cli.password.as_deref(), Some("secret"));
    }

    #[test]
    fn update_command_parses_version_and_force() {
        let cli =
            Cli::try_parse_from(["enva", "update", "--version", "v0.3.0", "--force"]).unwrap();
        match cli.command.as_ref() {
            Some(Commands::Update { version, force }) => {
                assert_eq!(version.as_deref(), Some("v0.3.0"));
                assert!(*force);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
