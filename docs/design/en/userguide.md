# Enva -- User Guide

> Complete guide to installing, configuring, and using the Enva CLI, shell hooks, and Web UI.

---

## Table of Contents

1. [Installation](#1-installation)
2. [Quick Start](#2-quick-start)
3. [Core Concepts](#3-core-concepts)
4. [CLI Reference](#4-cli-reference)
5. [Configuration](#5-configuration)
6. [Shell Hooks](#6-shell-hooks)
7. [Web UI](#7-web-ui)
8. [Security](#8-security)
9. [Cross-Platform Notes](#9-cross-platform-notes)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Installation

### Prerequisites

- Linux x86_64 or macOS aarch64 (Apple Silicon)
- For building from source: Rust toolchain (stable)

### Install via Script

```bash
curl -fsSL https://example.com/install.sh | bash
```

The install script detects your platform and downloads the pre-compiled binary.

### Build from Source

```bash
cargo build --release
cp target/release/enva ~/.local/bin/
```

### Verify Installation

```bash
enva self-test
```

Expected output:

```
  [PASS] Crypto backend (Rust)
  [PASS] Encrypt/decrypt round-trip
  [PASS] CLI framework
```

---

## 2. Quick Start

### Step 1: Create a vault

```bash
enva init --vault ~/.enva/vault.json
```

You will be prompted to set and confirm a master password. The vault file is created with an empty secrets pool and Argon2id KDF parameters embedded in its metadata.

### Step 2: Add secrets

```bash
enva set prod-db \
  --key DATABASE_URL \
  --value "postgresql://user:pass@db.prod.internal:5432/myapp" \
  --vault ~/.enva/vault.json

enva set jwt-secret \
  --key JWT_SECRET \
  --value "super-secret-jwt-signing-key-2026" \
  --vault ~/.enva/vault.json

enva set shared-sentry \
  --key SENTRY_DSN \
  --value "https://abc123@sentry.io/42" \
  --vault ~/.enva/vault.json
```

Each `set` command encrypts the value with AES-256-GCM, stores it under the given alias, and updates the vault's HMAC.

### Step 3: Create apps and assign secrets

Apps are defined in the vault itself. First, create an app entry, then assign secrets:

```bash
enva assign prod-db --app backend --vault ~/.enva/vault.json
enva assign jwt-secret --app backend --vault ~/.enva/vault.json
enva assign shared-sentry --app backend --vault ~/.enva/vault.json
```

For a frontend app that needs a different env var name for the same secret:

```bash
enva assign shared-sentry --app frontend \
  --as NEXT_PUBLIC_SENTRY_DSN \
  --vault ~/.enva/vault.json
```

### Step 4: Run with injection

```bash
enva --vault ~/.enva/vault.json --cmd "./my-app" backend
```

The subprocess receives three environment variables: `DATABASE_URL`, `JWT_SECRET`, and `SENTRY_DSN`. The secrets never appear in shell history or on disk in plaintext.

If `backend` has an `app_path` configured, you can launch it directly and forward argv with:

```bash
enva --vault ~/.enva/vault.json backend --port 3000
```

### Step 5: Verify

```bash
enva list --vault ~/.enva/vault.json
```

```
ALIAS                    KEY                      APPS                 UPDATED
----------------------------------------------------------------------------------------
jwt-secret               JWT_SECRET               backend              2026-03-28T10:05
prod-db                  DATABASE_URL             backend              2026-03-28T10:03
shared-sentry            SENTRY_DSN               backend,frontend     2026-03-28T10:04
```

---

## 3. Core Concepts

### Alias vs Key

Every secret has two names:

- **Alias**: the unique identifier in the vault (lowercase, hyphens allowed). Examples: `prod-db`, `staging-redis`, `jwt-secret-v2`.
- **Key**: the environment variable name injected at runtime. Examples: `DATABASE_URL`, `REDIS_URL`, `JWT_SECRET`.

Multiple aliases can share the same key. This enables managing the same environment variable across different environments:

| Alias | Key | Value (encrypted) |
|-------|-----|-------------------|
| `prod-db` | `DATABASE_URL` | `ENC[...prod-connection-string...]` |
| `staging-db` | `DATABASE_URL` | `ENC[...staging-connection-string...]` |

The `backend` app references `prod-db` while `staging` references `staging-db`. Both inject `DATABASE_URL` but with different values.

### Secrets Pool

The vault maintains a flat pool of secrets keyed by alias. Secrets are not owned by any app -- they exist independently and can be referenced by zero or more apps.

### App References

An app holds:

- A list of alias references (which secrets to inject)
- An overrides map (alias → custom env var name)

Apps do not store encrypted values. They are lightweight reference structures.

### Overrides

When an app needs a secret injected under a different name than its default key:

```
Alias: shared-sentry → Key: SENTRY_DSN (default)

backend app:  injects as SENTRY_DSN           (no override)
frontend app: injects as NEXT_PUBLIC_SENTRY_DSN (override)
```

### Injection Resolution

For each alias in an app's secrets list:

```
env_var_name = overrides.get(alias, secret.key)
env_var_value = decrypt(secret.value)
```

### Vault File Format (v2.0)

A single JSON file with three top-level sections:

```json
{
  "_meta": {
    "format_version": "2.0",
    "kdf": {
      "algorithm": "argon2id",
      "memory_cost": 65536,
      "time_cost": 3,
      "parallelism": 4
    },
    "salt": "BASE64_32_BYTES",
    "hmac": "BASE64_32_BYTES",
    "created_at": "2026-03-28T10:00:00Z",
    "updated_at": "2026-03-28T14:30:00Z",
    "created_by": "dev@workstation"
  },
  "secrets": {
    "prod-db": {
      "key": "DATABASE_URL",
      "value": "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]",
      "description": "Production PostgreSQL",
      "tags": ["production", "database"],
      "created_at": "2026-03-28T10:00:00Z",
      "updated_at": "2026-03-28T10:00:00Z"
    }
  },
  "apps": {
    "backend": {
      "description": "Backend API service",
      "secrets": ["prod-db"],
      "overrides": {}
    }
  }
}
```

The vault is self-describing: all KDF parameters, salt, and format version are embedded in `_meta`. No external configuration is required to decrypt.

Each encrypted value uses the SOPS-inspired `ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]` format with per-value random nonces and alias-bound AAD (Additional Authenticated Data) to prevent ciphertext relocation attacks.

File-level integrity is protected by HMAC-SHA256 over a canonical serialization of all aliases, keys, values, and app references.

---

## 4. CLI Reference

All commands accept these global options:

| Option | Env Var | Description |
|--------|---------|-------------|
| `--vault PATH` | `ENVA_VAULT_PATH` | Vault file path |
| `--config PATH` | `ENVA_CONFIG` | Config file path |
| `--password-stdin` | -- | Read password from stdin (for scripting) |
| `--quiet` / `-q` | -- | Suppress non-essential output |
| `--verbose` / `-v` | -- | Enable verbose/debug output |

### `enva init`

Create a new encrypted vault file.

```bash
enva init --vault ~/.enva/vault.json
```

### `enva set`

Add or update a secret in the vault pool.

```bash
enva set <ALIAS> --key <ENV_VAR> --value <SECRET_VALUE> [OPTIONS]
```

### `enva edit`

Edit individual fields of an existing secret without replacing all fields. Useful for migration — update a single connection string or key after moving to a new device.

```bash
enva edit <ALIAS> [--key <NEW_KEY>] [--value <NEW_VALUE>] [--description <DESC>] [--tags <TAGS>]
```

At least one flag is required. Unspecified fields remain unchanged.

### `enva get`

Decrypt and print a single secret's value.

```bash
enva get <ALIAS> --vault vault.json
```

### `enva list`

List secrets with metadata.

```bash
enva list --vault vault.json
enva list --app backend --vault vault.json
```

### `enva delete`

Remove a secret from the vault pool and all app references.

```bash
enva delete <ALIAS> --vault vault.json
```

### `enva assign` / `enva unassign`

Assign or remove a secret reference from an app.

```bash
enva assign <ALIAS> --app <APP_NAME> [--as <OVERRIDE_KEY>]
enva unassign <ALIAS> --app <APP_NAME> --vault vault.json
```

### `enva <APP> [ARGS...]`

Launch the configured `app_path` for an app and forward any trailing argv.

```bash
enva <APP_NAME> [ARGS...]
```

Examples:

```bash
enva --vault vault.json backend
enva --vault vault.json backend --host 0.0.0.0 --port 8081
echo "$VAULT_PASSWORD" | enva --password-stdin --vault vault.json backend --config config.yaml
```

If `app_path` is not configured and no argv is passed, Enva prints the environment variables that would be injected instead of launching a child process.

### `enva --cmd "<command>" <APP>`

Run an arbitrary shell command with the app's secrets injected as environment variables.

```bash
enva --cmd "<COMMAND>" <APP_NAME>
```

Examples:

```bash
enva --vault vault.json --cmd "./my-server" backend
enva --vault vault.json --cmd "docker compose up" backend
echo "$VAULT_PASSWORD" | enva --password-stdin --vault vault.json --cmd "./start.sh" backend
```

### `enva vault export` / `enva vault import`

Export or import secrets.

```bash
enva vault export --app backend --vault vault.json --format json
enva vault import --from .env.production --app backend --vault vault.json
enva vault import --from bundle.yaml --vault vault.json
```

### `enva serve`

Start the Web UI management server.

```bash
enva serve --port 8080 --host 127.0.0.1 --vault vault.json
```

### `enva self-test`

Verify installation integrity.

```bash
enva self-test
```

---

## 5. Configuration

The Enva uses a five-layer configuration merge (later layers override earlier ones):

```
Built-in defaults  <  Global config  <  Project config  <  Env override  <  CLI flags
```

### Layer 2: Global Config (`~/.enva/config.yaml`)

User-level settings shared across all projects.

### Layer 3: Project Config (`.enva.yaml`)

Per-project settings. Place this file in your project root. Safe to commit to version control.

### Layer 5: CLI Flags and Environment Variables

| Env Var | Equivalent CLI Flag | Description |
|---------|---------------------|-------------|
| `ENVA_VAULT_PATH` | `--vault` | Vault file path |
| `ENVA_CONFIG` | `--config` | Config file path |
| `ENVA_APP` | N/A | Default app name |
| `ENVA_CONFIG_DIR` | N/A | Custom config directory |

---

## 6. Shell Hooks

Shell hooks enable automatic secret injection when you `cd` into a project directory containing `.enva.yaml`.

### Bash Setup

Add to `~/.bashrc`:

```bash
source ~/.enva/hooks/enva-hook.bash
```

### Zsh Setup

Add to `~/.zshrc`:

```zsh
source ~/.enva/hooks/enva-hook.zsh
```

---

## 7. Web UI

The Web UI provides a browser-based interface for managing secrets without using the command line.

### Starting the Server

```bash
enva serve --vault ~/.enva/vault.json --port 8080
```

Open `http://127.0.0.1:8080` in your browser.

---

## 8. Security

### Memory Safety

Enva is implemented entirely in Rust. Keys are zeroized on drop via the `zeroize` crate. `secrecy::SecretString` wraps all sensitive values, preventing accidental exposure through Debug output or logging.

### Key Derivation (Argon2id)

Passwords are never stored. The vault uses Argon2id (RFC 9106) to derive a 64-byte master key from the password + a 32-byte random salt. Default parameters: 64 MiB memory, 3 iterations, 4 threads.

### Encryption (AES-256-GCM)

Each secret value is encrypted independently with a fresh 12-byte random nonce, alias-bound AAD, and a 128-bit authentication tag.

---

## 9. Cross-Platform Notes

### Supported Platforms

| Platform | Status |
|----------|--------|
| Linux x86_64 | Pre-built binary |
| macOS aarch64 (Apple Silicon) | Pre-built binary |
| Others | Build from source with `cargo build --release` |

**Linux:** Config directory: `~/.enva/`

**macOS:** Config directory: `~/.enva/` (unified)

---

## 10. Troubleshooting

### Common Errors

**"Authentication failed"** — Wrong vault password.

**"HMAC verification failed"** — Vault file modified outside of Enva.

**"Unsupported format version"** — Upgrade Enva to the latest version.

### Self-Test

```bash
enva self-test
```

### Password Recovery

There is no password recovery mechanism. If you forget the master password, the vault cannot be decrypted.

---

*Document version: 2.0 | Updated: 2026-04-01*
*See also: [Architecture](architecture.md) · [Vault Format Spec](vault_spec.md) · [Config Reference](config_reference.md)*
