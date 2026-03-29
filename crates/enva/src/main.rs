mod config;
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
    #[arg(long, short = 'p', global = true, env = "ENVA_PASSWORD")]
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
    /// Start the web configuration UI
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
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
        let code = if msg.contains("authentication failed")
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

fn resolve_vault_path(cli: &Cli) -> String {
    if let Some(ref vp) = cli.vault {
        tracing::debug!(vault_path = %vp, "using vault path from --vault flag");
        return vp.clone();
    }
    let cfg = config::ConfigLoader::load(cli.config.as_deref(), cli.env.as_deref());
    let resolved = cfg.resolve_vault_path();
    tracing::debug!(vault_path = %resolved, "resolved vault path from config");
    resolved
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    tracing::debug!(command = ?cli.command, "dispatching command");
    match &cli.command {
        None => run_serve(&cli, "127.0.0.1", 8080),
        Some(Commands::Serve { port, host }) => run_serve(&cli, host, *port),
        Some(Commands::Vault { cmd }) => run_vault_command(&cli, cmd),
        Some(Commands::External(args)) => run_app(&cli, args),
    }
}

fn run_serve(cli: &Cli, host: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let vp = resolve_vault_path(cli);
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

    let vp = resolve_vault_path(cli);
    let pw = get_password(cli)?;
    let store = vault::VaultStore::load(&vp, &pw)?;
    let resolved = store.get_app_secrets(app_name)?;

    let cfg = config::ConfigLoader::load(cli.config.as_deref(), cli.env.as_deref());
    let override_system = cfg
        .apps
        .get(app_name)
        .map(|a| a.override_system)
        .unwrap_or(false);
    let resolved: std::collections::BTreeMap<String, String> = if override_system {
        resolved
    } else {
        resolved
            .into_iter()
            .filter(|(k, _)| std::env::var(k).is_err())
            .collect()
    };

    if command_args.is_empty() {
        let app_path = store.get_app_path(app_name).unwrap_or_default();
        if !app_path.is_empty() {
            tracing::debug!(app = %app_name, app_path = %app_path, "launching via app_path");
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                let err = std::process::Command::new(&app_path).envs(&resolved).exec();
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
            if store.get_app_path(app_name).unwrap_or_default().is_empty() {
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
            if std::path::Path::new(vault_path).exists() {
                return Err(format!("Vault already exists at {vault_path}. Delete it first or choose a different path.").into());
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
            vault::VaultStore::create(vault_path, &password, None)?;
            if !cli.quiet {
                println!("Vault created: {vault_path}");
            }
        }
        VaultCommands::Set {
            alias,
            key,
            value,
            description,
            tags,
        } => {
            let vp = resolve_vault_path(cli);
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
        VaultCommands::Get { alias } => {
            let vp = resolve_vault_path(cli);
            let pw = get_password(cli)?;
            let store = vault::VaultStore::load(&vp, &pw)?;
            let value = store.get(alias)?;
            println!("{value}");
        }
        VaultCommands::List { app } => {
            let vp = resolve_vault_path(cli);
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
            let vp = resolve_vault_path(cli);
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
            let vp = resolve_vault_path(cli);
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
            let vp = resolve_vault_path(cli);
            let pw = get_password(cli)?;
            let mut store = vault::VaultStore::load(&vp, &pw)?;
            store.unassign(app, alias)?;
            store.save()?;
            if !cli.quiet {
                println!("Unassigned {alias} from {app}");
            }
        }
        VaultCommands::Export { app, format } => {
            let vp = resolve_vault_path(cli);
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
            let vp = resolve_vault_path(cli);
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
