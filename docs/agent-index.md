# Enva — Agent Reference Index

Enva is an encrypted environment variable manager. It stores secrets in a local
AES-256-GCM vault (Argon2id KDF) and injects them as env vars into applications.
Single static binary, zero runtime dependencies.

---

## Install

```bash
# One-liner (Linux x86_64, Linux aarch64, macOS aarch64)
curl -fsSL https://raw.githubusercontent.com/YoRHa-Agents/EnvA/main/scripts/install.sh | bash

# From source
cargo build --release && cp target/release/enva ~/.local/bin/

# Verify
enva vault self-test
```

---

## Command Reference

### Top-level

| Command | Description | Interactive? |
|---------|-------------|-------------|
| `enva` | Start web configuration UI on `127.0.0.1:8080` | No |
| `enva <APP>` | Dry-run: list env vars that would be injected for APP | Yes (password) |
| `enva <APP> -- <cmd> [args...]` | Inject env vars and exec cmd | Yes (password) |
| `enva serve [--port N] [--host H]` | Start web UI (explicit alias) | No |

### Vault management: `enva vault <subcommand>`

| Subcommand | Syntax | Description | Interactive? |
|------------|--------|-------------|-------------|
| `init` | `enva vault init --vault <path>` | Create a new encrypted vault | Yes (set + confirm password) |
| `set` | `enva vault set <alias> -k <KEY> -V <value> [-d desc] [-t tags]` | Add or update a secret | Yes (password) |
| `get` | `enva vault get <alias>` | Decrypt and print secret value to stdout | Yes (password) |
| `list` | `enva vault list [--app <name>]` | List secrets (optionally filtered by app) | Yes (password) |
| `delete` | `enva vault delete <alias> [--yes]` | Delete a secret (`--yes` skips confirm) | Yes (password + confirm) |
| `assign` | `enva vault assign <alias> --app <name> [--as <KEY>]` | Assign secret to app (auto-creates app) | Yes (password) |
| `unassign` | `enva vault unassign <alias> --app <name>` | Remove secret from app | Yes (password) |
| `export` | `enva vault export --app <name> [--format json]` | Export resolved secrets (env or json) | Yes (password) |
| `import-env` | `enva vault import-env --from <.env file> --app <name>` | Import .env file into vault | Yes (password) |
| `self-test` | `enva vault self-test` | Verify crypto primitives work | No |

### Global flags (all commands)

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--vault <PATH>` | `ENVA_VAULT_PATH` | `~/.enva/vault.json` | Path to vault file |
| `--config <PATH>` | `ENVA_CONFIG` | `~/.enva/config.yaml` | Path to config file |
| `--password-stdin` | — | `false` | Read password from stdin (use this for non-interactive / CI) |
| `-q, --quiet` | — | `false` | Suppress non-essential output |
| `-v, --verbose` | — | `false` | Enable debug logging |

> **For non-interactive use (CI, agents):** Always pass `--password-stdin` and
> pipe the password. Example: `echo "$PW" | enva --password-stdin vault get my-secret`

---

## Configuration

### File locations (priority order, last wins)

| Priority | Path | Scope |
|----------|------|-------|
| 1 (lowest) | `~/.enva/config.yaml` | Global user defaults |
| 2 | XDG: `$XDG_CONFIG_HOME/enva/config.yaml` | Global (XDG fallback) |
| 3 | `.enva.yaml` (walk up from cwd to home) | Project |
| 4 | `.enva.<env>.yaml` (next to project config) | Environment overlay |
| 5 | `--config <path>` CLI flag | Explicit override |
| 6 (highest) | `ENVA_VAULT_PATH`, `ENVA_CONFIG`, `ENVA_APP` env vars | Environment |

### Environment variables

| Variable | Description |
|----------|-------------|
| `ENVA_VAULT_PATH` | Override vault file path |
| `ENVA_CONFIG` | Override config file path |
| `ENVA_CONFIG_DIR` | Override config directory |
| `ENVA_APP` | Override default app name |

---

## Agent Workflow Examples

### 1. Initialize vault, add secret, inject into app

```bash
# Create vault (non-interactive)
echo "my-vault-password" | enva --password-stdin vault init --vault ./project.vault.json

# Add a secret
echo "my-vault-password" | enva --password-stdin --vault ./project.vault.json \
  vault set db-url -k DATABASE_URL -V "postgres://user:pass@localhost/mydb"

# Assign to app
echo "my-vault-password" | enva --password-stdin --vault ./project.vault.json \
  vault assign db-url --app backend

# Run with injection
echo "my-vault-password" | enva --password-stdin --vault ./project.vault.json \
  backend -- printenv DATABASE_URL
# Output: postgres://user:pass@localhost/mydb
```

### 2. CI pipeline with `--password-stdin`

```bash
export ENVA_VAULT_PATH="./secrets/ci.vault.json"

# All commands read password from VAULT_PW variable
echo "$VAULT_PW" | enva --password-stdin backend -- ./run-tests.sh
echo "$VAULT_PW" | enva --password-stdin backend -- ./deploy.sh
```

### 3. Dry-run: inspect injected variables

```bash
echo "my-vault-password" | enva --password-stdin --vault ./project.vault.json backend
# Output:
#   Environment variables for app 'backend':
#     DATABASE_URL=<redacted>
#     REDIS_URL=<redacted>
#
#   Run with a command to inject: enva backend -- <cmd>
```

### 4. Start web configuration UI

```bash
enva                              # defaults to 127.0.0.1:8080
enva serve --port 3000            # custom port
```

### 5. Import from .env file

```bash
echo "my-vault-password" | enva --password-stdin --vault ./project.vault.json \
  vault import-env --from .env --app backend

# Verify import
echo "my-vault-password" | enva --password-stdin --vault ./project.vault.json \
  vault list --app backend
```

---

## Vault Format (v2.0)

Single JSON file with three sections:

```
{
  "_meta": {
    "format_version": "2.0",
    "kdf": { "algorithm": "argon2id", "memory_cost": 65536, "time_cost": 3, "parallelism": 4 },
    "salt": "<base64>",
    "hmac": "<base64>",
    "created_at": "ISO8601",
    "updated_at": "ISO8601"
  },
  "secrets": {
    "<alias>": {
      "key": "<ENV_VAR_NAME>",
      "value": "ENC[AES256_GCM,data:<b64>,iv:<b64>,tag:<b64>,type:str]",
      "description": "...",
      "tags": ["..."]
    }
  },
  "apps": {
    "<app_name>": {
      "secrets": ["<alias1>", "<alias2>"],
      "overrides": { "<alias>": "<CUSTOM_KEY>" }
    }
  }
}
```

- `_meta.kdf`: self-describing KDF parameters (no external config needed to decrypt)
- `secrets.<alias>.value`: AES-256-GCM ciphertext in SOPS-like `ENC[...]` format
- `apps.<app>.overrides`: optional alias → custom env var name mapping

---

## Error Reference

| Error Message | Cause | Fix |
|---------------|-------|-----|
| `alias not found: <x>` | Secret alias doesn't exist in vault | Check alias with `enva vault list` |
| `app not found: <x>` | App doesn't exist (only for `unassign`, `export`) | Use `enva vault assign` first (auto-creates app) |
| `wrong password` | Incorrect vault password provided | Re-enter password or check `--password-stdin` input |
| `vault file not found` | Vault path doesn't resolve to a file | Check `--vault` flag, `ENVA_VAULT_PATH`, or config |
| `HMAC verification failed` | Vault file was tampered with or corrupted | Restore from backup; do not modify vault JSON manually |
| `Passwords do not match` | Init confirm password didn't match | Re-run `enva vault init` |
| `Permission denied` | Can't read/write vault file | Check file permissions |

---

## Crate Structure

```
enva-core   (library)   AES-256-GCM, Argon2id, HMAC-SHA256, vault crypto, types, store trait
enva        (binary)    CLI (clap), config loader, web UI (Axum + rust-embed)
```
