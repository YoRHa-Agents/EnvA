# Interface Specification — Secrets Manager

> **摘要:** Secrets Manager 接口规范的完整英文版。涵盖三大接口面：(1) 基于 Click 的 CLI 命令树（含 10 个子命令、全局选项和退出码）；(2) Bash/Zsh Shell Hook（自动密钥注入、历史保护和密码缓存）；(3) Axum RESTful Web API（JWT 认证、Secrets CRUD、导入导出、应用管理和错误模式）。

> **Cross-references:**
> - Encryption scheme and vault format → `secrets_manager_vault_spec.md` (to be written)
> - Configuration system (five-layer config, field definitions) → `secrets_manager_config_reference.md` (to be written)
> - Technology decisions (pure Rust + clap) → [`tech_decision.md`](./tech_decision.md)
> - Research report → [`secrets_manager_research.md`](./secrets_manager_research.md)
> - Architecture design → `secrets_manager_design.md` (to be written)

---

## Table of Contents

- [Part 1: CLI Interface Specification](#part-1-cli-interface-specification)
  - [1.1 Command Tree Overview](#11-command-tree-overview)
  - [1.2 Global Options](#12-global-options)
  - [1.3 Exit Code Specification](#13-exit-code-specification)
  - [1.4 Subcommand Detailed Specifications](#14-subcommand-detailed-specifications)
- [Part 2: Shell Hook Specification](#part-2-shell-hook-specification)
  - [2.1 Bash Hook](#21-bash-hook-secrets-hookbash)
  - [2.2 Zsh Hook](#22-zsh-hook-secrets-hookzsh)
  - [2.3 Injection Lifecycle](#23-injection-lifecycle)
  - [2.4 Configuration File Auto-Discovery](#24-configuration-file-auto-discovery)
- [Part 3: Web API Specification](#part-3-web-api-specification)
  - [3.1 Overview](#31-overview)
  - [3.2 Authentication](#32-authentication)
  - [3.3 Secrets CRUD](#33-secrets-crud)
  - [3.4 Import & Export](#34-import--export)
  - [3.5 App Management](#35-app-management)
  - [3.6 Error Responses](#36-error-responses)

---

## Part 1: CLI Interface Specification

> **Installation note**: The `enva` CLI is a standalone Rust binary. Install via `cargo install enva` or the install script (`scripts/install.sh`). No external runtime dependencies are required.

### 1.1 Command Tree Overview

The CLI is built on the Click framework (`click>=8`), with `secrets` as the top-level command group.

```
secrets
├── init --vault PATH                                              # Create a new vault (interactive password)
├── set ALIAS --key ENV_NAME --value VALUE --vault PATH            # Add/update secret in the pool
├── get ALIAS --vault PATH                                         # Decrypt by alias
├── list [--app NAME] --vault PATH                                 # List secrets (filter by app)
├── delete ALIAS --vault PATH                                      # Delete from pool
├── assign ALIAS --app NAME [--as CUSTOM_KEY] --vault PATH         # Assign secret to an app
├── unassign ALIAS --app NAME --vault PATH                         # Remove secret reference from app
├── run --app NAME --vault PATH -- CMD [ARGS]                      # Resolve aliases and inject into subprocess
├── export --app NAME --vault PATH [--format]                      # Export resolved env vars for app
├── import --from FILE --app NAME --vault PATH                     # Import from .env (auto-generates aliases)
├── serve --port PORT --vault PATH [--host]                        # Start the web management service
└── self-test                                                      # Verify installation integrity
```

### 1.2 Global Options

The following options are available on all subcommands (defined at the command group level):

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--vault PATH` | `click.Path` | `defaults.vault_path` from config, ultimate fallback `~/.secrets/vault.json` | Vault file path. Supports `~` expansion. |
| `--config PATH` | `click.Path` | `~/.secrets/config.yaml` | Global configuration file path. |
| `--password-stdin` | `bool` (flag) | `False` | Read password from stdin (for scripts/CI) instead of an interactive prompt. |
| `--quiet` / `-q` | `bool` (flag) | `False` | Quiet mode — only output data to stdout; suppress status messages on stderr. |
| `--verbose` / `-v` | `bool` (flag) | `False` | Verbose mode — output debug information to stderr. Mutually exclusive with `--quiet`. |

**Mutual exclusion constraint**: `--quiet` and `--verbose` cannot be used together. Enforced via `cls=MutuallyExclusive` or a callback validator in Click.

**Password acquisition priority**:
1. `--password-stdin` → read one line from stdin
2. Environment variable `ENVA_PASSWORD` → use directly
3. In-memory cache (Shell hook scenario) → use the cached password
4. Interactive prompt → `click.prompt("Vault password", hide_input=True)`

### 1.3 Exit Code Specification

| Exit Code | Constant | Meaning | Trigger Scenario |
|-----------|----------|---------|------------------|
| `0` | `EXIT_SUCCESS` | Success | All operations completed normally |
| `1` | `EXIT_ERROR` | General error | I/O errors, corrupt vault format, argument validation failures, unknown exceptions |
| `2` | `EXIT_AUTH_FAILED` | Authentication failed | Incorrect password (HMAC verification failed), vault decryption failure |
| `3` | `EXIT_KEY_NOT_FOUND` | Key not found | The key specified in `get`/`delete` does not exist in the vault |

**Output conventions**:
- **stdout**: Only command result data (values, lists, export statements, etc.)
- **stderr**: Status messages (`✓ Key stored`), error messages (`Error: ...`), debug logs (`--verbose`)
- In `--quiet` mode, stderr suppresses status messages and only outputs errors

### 1.4 Subcommand Detailed Specifications

---

#### 1.4.1 `secrets init`

**Purpose**: Create a new vault file. Interactively prompt for and confirm a password, generate a KDF salt, and initialize an empty vault structure.

**Signature**:

```
secrets init [--vault PATH]
```

| Parameter/Option | Type | Required | Default | Description |
|------------------|------|----------|---------|-------------|
| `--vault` | `click.Path` | No | Global default | Vault file output path |

**Behavior**:
1. If the vault file already exists → exit code `1`, stderr outputs `Error: Vault already exists at {path}. Use --force to overwrite.`
2. Interactively prompt for password (with confirmation): `New vault password:` / `Confirm password:`
3. Generate a 32-byte salt (`os.urandom(32)`)
4. Derive a 256-bit key via Argon2id
5. Write the initial vault JSON structure (with `_meta`, empty `global`/`apps`)
6. Compute and write the HMAC

**stdout**: None

**stderr** (normal):

```
✓ Vault created at /home/user/.secrets/vault.json
  KDF: argon2id (memory=64MB, iterations=3, parallelism=4)
```

**stderr** (already exists):

```
Error: Vault already exists at /home/user/.secrets/vault.json
```

**Examples**:

```bash
# Interactive creation
secrets init --vault ./my-vault.json

# CI scenario
echo "my-password" | secrets init --vault ./vault.json --password-stdin
```

---

#### 1.4.2 `secrets set`

**Purpose**: Add or update a secret in the global secrets pool, identified by alias. If the alias already exists, it is overwritten.

**Signature**:

```
secrets set ALIAS --key ENV_NAME --value VALUE [--description DESC] [--tags tag1,tag2] [--vault PATH]
```

| Parameter/Option | Type | Required | Default | Description |
|------------------|------|----------|---------|-------------|
| `ALIAS` | `str` (argument) | Yes | — | Secret alias (unique identifier). Validation: `^[a-z0-9][a-z0-9-]*$`, max 128 characters. |
| `--key` | `str` | Yes | — | Environment variable name for injection. Validation: `^[A-Za-z_][A-Za-z0-9_]*$`, max 128 characters. |
| `--value` | `str` | Yes | — | Secret value. If `-`, read from stdin. Max 64 KB. |
| `--description` | `str` | No | `""` | Optional description. |
| `--tags` | `str` | No | `""` | Comma-separated tag list. |
| `--vault` | `click.Path` | No | Global default | Vault file path |

**Behavior**:
1. Read and decrypt the vault (password obtained per §1.2 priority chain)
2. HMAC integrity verification
3. Encrypt VALUE with AES-256-GCM (independent 12-byte nonce)
4. Store in secrets pool as `secrets[ALIAS]` with `key`, `value`, `description`, `tags`
5. Update `_meta.updated_at`, recompute HMAC
6. Atomically write back to vault (write-to-temp + rename)

**stdout**: None

**stderr** (normal):

```
✓ Set alias "prod-db" (key=DATABASE_URL)
```

**stderr** (update existing alias):

```
✓ Updated alias "prod-db" (key=DATABASE_URL)
```

**Examples**:

```bash
# Add a new secret
secrets set prod-db --key DATABASE_URL --value "postgres://..." --vault ./vault.json

# With description and tags
secrets set jwt-secret --key JWT_SECRET --value "abc" --description "JWT signing key" --tags auth,backend --vault ./vault.json

# Read value from stdin (suitable for multiline or special-character values)
echo "long-secret-value" | secrets set my-secret --key MY_SECRET --value - --vault ./vault.json
```

---

#### 1.4.3 `secrets get`

**Purpose**: Decrypt and output the value of a secret by alias.

**Signature**:

```
secrets get ALIAS [--vault PATH]
```

| Parameter/Option | Type | Required | Default | Description |
|------------------|------|----------|---------|-------------|
| `ALIAS` | `str` (argument) | Yes | — | Secret alias |
| `--vault` | `click.Path` | No | Global default | Vault file path |

**Behavior**:
1. Read and decrypt the vault
2. HMAC integrity verification
3. Look up the alias in the secrets pool
4. Decrypt the value with AES-256-GCM
5. Output plaintext to stdout (no trailing newline unless the value itself contains one)

**Alias not found**: Exit code `3`, stderr outputs `Error: Alias "ALIAS" not found`

**stdout**: Raw plaintext value, no quotes, no trailing newline

```
sk-abc123
```

**Examples**:

```bash
# Get by alias
secrets get prod-db --vault ./vault.json

# Use in a pipeline
DB_URL=$(secrets get prod-db --vault ./vault.json)
```

---

#### 1.4.4 `secrets list`

**Purpose**: List secrets in the pool (values are not exposed). Optionally filter by app.

**Signature**:

```
secrets list [--app NAME] [--vault PATH]
```

| Parameter/Option | Type | Required | Default | Description |
|------------------|------|----------|---------|-------------|
| `--app` | `str` | No | `None` (list all) | If specified, list only secrets referenced by that app; otherwise list all secrets in the pool. |
| `--vault` | `click.Path` | No | Global default | Vault file path |

**stdout format** (without `--app`, tabular):

```
Alias           Key              App(s)              Updated
prod-db         DATABASE_URL     backend              2026-03-27
jwt-secret      JWT_SECRET       backend, auth        2026-03-26
shared-sentry   SENTRY_DSN       backend, frontend    2026-03-25
stripe-key      STRIPE_KEY       frontend             2026-03-24
redis-cache     REDIS_URL        worker, backend      2026-03-24
```

**stdout format** (with `--app backend`):

```
Alias           Injected As      Updated
prod-db         DB_URL           2026-03-27       (override)
jwt-secret      JWT_SECRET       2026-03-26
shared-sentry   SENTRY_DSN       2026-03-25
```

**Empty vault**: No output, exit code `0`.

**Examples**:

```bash
# List all secrets in the pool
secrets list --vault ./vault.json

# Only secrets referenced by an app
secrets list --app backend --vault ./vault.json

# Count secrets
secrets list --vault ./vault.json | tail -n +2 | wc -l
```

---

#### 1.4.5 `secrets delete`

**Purpose**: Delete a secret from the pool by alias. Also removes all app references to that alias.

**Signature**:

```
secrets delete ALIAS [--vault PATH]
```

| Parameter/Option | Type | Required | Default | Description |
|------------------|------|----------|---------|-------------|
| `ALIAS` | `str` (argument) | Yes | — | Alias of the secret to delete |
| `--vault` | `click.Path` | No | Global default | Vault file path |

**Alias not found**: Exit code `3`, stderr outputs `Error: Alias "ALIAS" not found`

**stdout**: None

**stderr** (normal):

```
✓ Deleted alias "prod-db" (was referenced by: backend)
```

**Examples**:

```bash
secrets delete prod-db --vault ./vault.json
secrets delete jwt-secret --vault ./vault.json
```

---

#### 1.4.5b `secrets assign`

**Purpose**: Assign a secret from the pool to a specified app, with an optional override for the injection environment variable name.

**Signature**:

```
secrets assign ALIAS --app NAME [--as CUSTOM_KEY] [--vault PATH]
```

| Parameter/Option | Type | Required | Default | Description |
|------------------|------|----------|---------|-------------|
| `ALIAS` | `str` (argument) | Yes | — | Secret alias |
| `--app` | `str` | Yes | — | Target application name |
| `--as` | `str` | No | `None` | Override the injection env var name |
| `--vault` | `click.Path` | No | Global default | Vault file path |

**stdout**: None

**stderr** (normal):

```
✓ Assigned "prod-db" to app "backend" (injected as DB_URL)
```

**Examples**:

```bash
# Assign directly (uses the secret's default key name for injection)
secrets assign jwt-secret --app backend --vault ./vault.json

# Assign with an injection key override
secrets assign prod-db --app backend --as DB_URL --vault ./vault.json
```

---

#### 1.4.5c `secrets unassign`

**Purpose**: Remove a secret reference from an app (does not delete the secret from the pool).

**Signature**:

```
secrets unassign ALIAS --app NAME [--vault PATH]
```

| Parameter/Option | Type | Required | Default | Description |
|------------------|------|----------|---------|-------------|
| `ALIAS` | `str` (argument) | Yes | — | Secret alias |
| `--app` | `str` | Yes | — | Application name |
| `--vault` | `click.Path` | No | Global default | Vault file path |

**stdout**: None

**stderr** (normal):

```
✓ Unassigned "prod-db" from app "backend"
```

**Examples**:

```bash
secrets unassign prod-db --app backend --vault ./vault.json
```

---

#### 1.4.6 `secrets run`

**Purpose**: Resolve the aliases referenced by a specified app, decrypt secret values, and inject them as environment variables into a subprocess running the specified command.

**Signature**:

```
secrets run --app NAME [--vault PATH] -- COMMAND [ARGS...]
```

| Parameter/Option | Type | Required | Default | Description |
|------------------|------|----------|---------|-------------|
| `--app` | `str` | Yes | — | Inject secrets referenced by the specified app. |
| `--vault` | `click.Path` | No | Global default | Vault file path |
| `COMMAND [ARGS...]` | `str` (variadic) | Yes | — | Command and arguments following `--` |

**Alias resolution injection logic**:
1. Read `apps[NAME].secrets` alias list
2. For each alias: check `overrides[alias]`; if present, use the override value as the env var name, otherwise use `secret.key`
3. Decrypt secret value
4. Existing system environment variables → not overridden by default (unless project config sets `override_system: true`)

**Behavior**:
1. Decrypt the vault and resolve key-value pairs by alias
2. Construct the subprocess environment: `{**os.environ, **resolved_secrets}`
3. Execute the subprocess via `os.execvpe(command, args, env)` (replaces the current process)
4. The subprocess exit code becomes the exit code of `secrets run`

**stderr** (`--verbose` mode):

```
[secrets] Resolving 3 aliases for app "backend"
[secrets] prod-db → DB_URL (override), jwt-secret → JWT_SECRET, shared-sentry → SENTRY_DSN
[secrets] Executing: python manage.py runserver
```

**Examples**:

```bash
# Inject resolved app secrets and run a command
secrets run --app backend --vault ./vault.json -- python manage.py runserver

# CI scenario
echo "$VAULT_PASSWORD" | secrets run --password-stdin --app backend --vault ./vault.json -- pytest
```

---

#### 1.4.7 `secrets export`

**Purpose**: Export the resolved environment variables for a specified app (after alias resolution and overrides).

**Signature**:

```
secrets export --app NAME [--vault PATH] [--format FORMAT]
```

| Parameter/Option | Type | Required | Default | Description |
|------------------|------|----------|---------|-------------|
| `--app` | `str` | Yes | — | Application name |
| `--vault` | `click.Path` | No | Global default | Vault file path |
| `--format` | `click.Choice(["env", "json"])` | No | `env` | Output format |

**stdout** (`--format env`):

```
export API_KEY='sk-abc123'
export DATABASE_URL='postgres://user:pass@host:5432/db'
export REDIS_URL='redis://localhost:6379/0'
```

Format rules: values are wrapped in single quotes; internal single quotes are escaped as `'\''`.

**stdout** (`--format json`):

```json
{
  "API_KEY": "sk-abc123",
  "DATABASE_URL": "postgres://user:pass@host:5432/db",
  "REDIS_URL": "redis://localhost:6379/0"
}
```

**Examples**:

```bash
# Inject into the current shell via eval
eval "$(secrets export --app backend --vault ./vault.json)"

# Export JSON for programmatic consumption
secrets export --app backend --vault ./vault.json --format json > /tmp/secrets.json

# Pipe to Docker
secrets export --app backend --vault ./vault.json --format env | xargs docker run --env
```

---

#### 1.4.8 `secrets import`

**Purpose**: Import key-value pairs from a `.env` file into the secrets pool, auto-generating aliases from key names (e.g. `DATABASE_URL` → `database-url`). Imported secrets are also assigned to the specified app.

**Signature**:

```
secrets import --from FILE --app NAME [--vault PATH]
```

| Parameter/Option | Type | Required | Default | Description |
|------------------|------|----------|---------|-------------|
| `--from` | `click.Path(exists=True)` | Yes | — | Source `.env` file path. Format: one `KEY=VALUE` per line; supports `#` comments, blank lines, and quoted values. |
| `--app` | `str` | Yes | — | Target application to assign imported secrets to |
| `--vault` | `click.Path` | No | Global default | Vault file path |

**`.env` parsing rules**:
- Blank lines and lines starting with `#` are ignored
- `KEY=VALUE` — trim whitespace from both ends of VALUE
- `KEY="VALUE"` — strip double quotes, handle `\n`/`\t`/`\\`/`\"` escape sequences
- `KEY='VALUE'` — strip single quotes, no escape processing
- `export KEY=VALUE` — ignore the `export ` prefix
- Duplicate keys: the last occurrence wins

**stdout**: None

**stderr** (normal):

```
✓ Imported 5 secrets into pool and assigned to app "backend" from .env.production
  New aliases: database-url, redis-url, jwt-secret
  Updated aliases: api-key, sentry-dsn
```

**Examples**:

```bash
secrets import --from .env.production --app backend --vault ./vault.json
```

---

#### 1.4.9 `secrets serve`

**Purpose**: Start a web management service (Axum + Tokio) providing a RESTful API and Web UI.

**Signature**:

```
secrets serve [--port PORT] [--vault PATH] [--host HOST]
```

| Parameter/Option | Type | Required | Default | Description |
|------------------|------|----------|---------|-------------|
| `--port` | `int` | No | `8080` (from global config `web.port`) | Listen port |
| `--host` | `str` | No | `127.0.0.1` (from global config `web.host`) | Listen address |
| `--vault` | `click.Path(exists=True)` | No | Global default | Vault file path |

**Behavior**:
1. Load global configuration to obtain CORS, session timeout, and rate limit parameters
2. Verify that the vault file exists and is readable
3. Start the Axum HTTP server
4. Block until `SIGINT`/`SIGTERM`

**stderr** (startup):

```
✓ Secrets Manager Web UI
  Vault:   /home/user/.secrets/vault.json
  Listen:  http://127.0.0.1:8080
  Press Ctrl+C to stop
```

**Examples**:

```bash
secrets serve --vault ./vault.json
secrets serve --port 9090 --host 0.0.0.0 --vault ./vault.json
```

---

#### 1.4.10 `secrets self-test`

**Purpose**: Verify installation integrity — check dependency availability, encryption correctness, and configuration file readability.

**Signature**:

```
secrets self-test
```

No additional parameters. Does not require `--vault` (no real vault is accessed).

**Behavior**:
1. Check Rust crypto backend (Argon2id + AES-256-GCM)
2. Perform an in-memory encrypt/decrypt round-trip test (Argon2id → AES-256-GCM → decrypt → compare)
3. Check global configuration file readability
4. Report system information (Enva version, OS, architecture)

**stdout**:

```
Secrets Manager Self-Test
─────────────────────────
Enva:          0.1.0 (x86_64-linux)
aes-gcm:       ✓ 0.10
argon2:        ✓ 0.5
clap:          ✓ 4.5
axum:          ✓ 0.8
jsonwebtoken:  ✓ 10
Encrypt/decrypt roundtrip: ✓ passed
Global config:  ✓ ~/.enva/config.yaml
─────────────────────────
All checks passed.
```

**Missing dependency**: Marked as `✗ not installed`, final exit code `1`.

---

## Part 2: Shell Hook Specification

### 2.1 Bash Hook (`secrets-hook.bash`)

**Installation path**: `~/.secrets/hooks/secrets-hook.bash` (overridable via global config `shell.hooks.bash`)

**Activation**: The user adds the following to `~/.bashrc` or `~/.bash_profile`:

```bash
source ~/.secrets/hooks/secrets-hook.bash
```

#### 2.1.1 Trigger Mechanism

Uses the `PROMPT_COMMAND` function chain:

```bash
__secrets_prompt_hook() {
    local cfg
    cfg=$(__secrets_find_config)
    if [[ -n "$cfg" && "$cfg" != "$__SECRETS_LAST_CONFIG" ]]; then
        __secrets_inject "$cfg"
        __SECRETS_LAST_CONFIG="$cfg"
    fi
}

if [[ -z "$PROMPT_COMMAND" ]]; then
    PROMPT_COMMAND="__secrets_prompt_hook"
else
    PROMPT_COMMAND="__secrets_prompt_hook;${PROMPT_COMMAND}"
fi
```

Key points:
- Appends to the `PROMPT_COMMAND` chain rather than replacing it, so existing hooks are preserved
- Re-injection is triggered only when the config file path changes (avoids decrypting after every command)

#### 2.1.2 History Protection

```bash
export HISTCONTROL="ignorespace:${HISTCONTROL}"
```

All commands involving sensitive information are automatically prefixed with a space:

```bash
__secrets_inject() {
    # Leading space prevents bash from recording the command in history
     eval "$( secrets export --app "$app" --vault "$vault" --quiet)"
}
```

#### 2.1.3 Deactivation

A `secrets-unhook` function is provided to undo injection in the current session:

```bash
secrets-unhook() {
    local key
    for key in ${__SECRETS_INJECTED_KEYS[@]}; do
        unset "$key"
    done
    __SECRETS_INJECTED_KEYS=()
    __SECRETS_LAST_CONFIG=""

    PROMPT_COMMAND="${PROMPT_COMMAND/__secrets_prompt_hook;/}"
    PROMPT_COMMAND="${PROMPT_COMMAND/__secrets_prompt_hook/}"
}
```

**Behavior**: When called, clears all injected environment variables, resets tracking state, and removes the hook from the `PROMPT_COMMAND` chain.

---

### 2.2 Zsh Hook (`secrets-hook.zsh`)

**Installation path**: `~/.secrets/hooks/secrets-hook.zsh` (overridable via global config `shell.hooks.zsh`)

**Activation**: The user adds the following to `~/.zshrc`:

```zsh
source ~/.secrets/hooks/secrets-hook.zsh
```

#### 2.2.1 Trigger Mechanism

Uses the native Zsh hook system (**not a Bash port**):

```zsh
autoload -Uz add-zsh-hook

__secrets_precmd_hook() {
    local cfg
    cfg=$(__secrets_find_config)
    if [[ -n "$cfg" && "$cfg" != "$__SECRETS_LAST_CONFIG" ]]; then
        __secrets_inject "$cfg"
        __SECRETS_LAST_CONFIG="$cfg"
    fi
}

__secrets_chpwd_hook() {
    __SECRETS_LAST_CONFIG=""
    __secrets_precmd_hook
}

add-zsh-hook precmd __secrets_precmd_hook
add-zsh-hook chpwd __secrets_chpwd_hook
```

Key points:
- `precmd`: Fires after each command execution, before the prompt is rendered — equivalent to Bash `PROMPT_COMMAND`
- `chpwd`: Fires on directory change — forces re-detection of config files and re-injection
- Uses `add-zsh-hook` instead of directly assigning `precmd()` / `chpwd()` to avoid overwriting user-defined hooks

#### 2.2.2 History Protection

```zsh
setopt HIST_IGNORE_SPACE
```

Same as the Bash hook — all sensitive commands are executed with a leading space prefix.

#### 2.2.3 Deactivation

```zsh
secrets-unhook() {
    local key
    for key in ${__SECRETS_INJECTED_KEYS[@]}; do
        unset "$key"
    done
    __SECRETS_INJECTED_KEYS=()
    __SECRETS_LAST_CONFIG=""

    add-zsh-hook -d precmd __secrets_precmd_hook
    add-zsh-hook -d chpwd __secrets_chpwd_hook
}
```

---

### 2.3 Injection Lifecycle

#### 2.3.1 Password Caching

| Property | Description |
|----------|-------------|
| Cache method | In-memory variable `__SECRETS_CACHED_PASSWORD` (exists only within the current shell process) |
| Timeout | Controlled by global config `defaults.password_timeout` (default 300 seconds, i.e. 5 minutes) |
| Expiration check | Before each injection, checks `__SECRETS_CACHE_TIMESTAMP` + `password_timeout` against the current time |
| Manual clearing | `unset __SECRETS_CACHED_PASSWORD __SECRETS_CACHE_TIMESTAMP` |
| Optional enhancement | When global config `defaults.password_cache: keyring`, uses the system keyring (macOS Keychain / Linux Secret Service) |
| CI/script scenario | The `ENVA_PASSWORD` environment variable takes priority over the cache |

Password caching pseudo-logic:

```
if ENVA_PASSWORD env var is set:
    password = $ENVA_PASSWORD
elif cached password exists AND not expired:
    password = cached
else:
    prompt user for password
    cache password with current timestamp
```

#### 2.3.2 Trigger Timing

| Trigger Event | Bash | Zsh | Behavior |
|---------------|------|-----|----------|
| Shell startup | `PROMPT_COMMAND` (first invocation) | `precmd` (first invocation) | Checks whether `.enva.yaml` exists under CWD; if so, inject |
| After command execution | `PROMPT_COMMAND` | `precmd` | Re-injects only when the config path has changed (performance safeguard) |
| Directory change | No native awareness (relies on next `PROMPT_COMMAND` invocation) | `chpwd` (immediate) | Resets state, immediately detects the new directory |
| Manual refresh | User calls `secrets-refresh` | Same | Forcibly clears the cache and re-injects |

`secrets-refresh` function (shared Bash/Zsh logic):

```bash
secrets-refresh() {
    __SECRETS_LAST_CONFIG=""
    unset __SECRETS_CACHED_PASSWORD __SECRETS_CACHE_TIMESTAMP
    __secrets_precmd_hook  # or __secrets_prompt_hook (Bash)
}
```

#### 2.3.3 Injection Priority Chain

Override order when same-named keys conflict (later entries override earlier ones):

```
[low priority]                              [high priority]
system env vars → global keys → app-specific keys
       ↑
       └── When override_system=true, reversed:
           global keys → app-specific keys → system env vars
```

Detailed rules:
1. Read `default_app` or `apps` configuration from `.enva.yaml`
2. Decrypt keys from the global scope in the vault → inject
3. Decrypt keys from the specified app in the vault → override same-named global keys
4. If the project config sets `override_system: false` (default), existing system environment variables **are not overridden**
5. If the project config sets `override_system: true`, vault values override system environment variables

### 2.4 Configuration File Auto-Discovery

Starting from CWD, traverse upward looking for `.enva.yaml`:

```
/home/user/projects/myapp/src/  ← CWD
/home/user/projects/myapp/      ← check for .enva.yaml
/home/user/projects/            ← check for .enva.yaml
/home/user/                     ← check for .enva.yaml
/home/                          ← stop (reached $HOME's parent directory)
/                               ← not checked
```

**Stop condition**: Reaches the parent directory of `$HOME` or the filesystem root.

**After finding the config file**: Reads `vault_path` (supports relative paths, resolved relative to the config file's directory) and `default_app` to determine the injection scope.

---

## Part 3: Web API Specification

### 3.1 Overview

| Property | Value |
|----------|-------|
| Framework | Axum 0.8 |
| Server | Tokio |
| Base path | `/api` |
| Content type | `application/json` (except import, which uses `multipart/form-data`) |
| Authentication | JWT Bearer Token |
| CORS | Configurable (default `http://localhost:*`) |

### 3.2 Authentication

#### 3.2.1 `POST /api/auth/login`

Authenticate and obtain a JWT token.

**Request**:

```
POST /api/auth/login
Content-Type: application/json
```

```json
{
  "password": "my-vault-password"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `password` | `string` | Yes | Vault password |

**Success response** (`200 OK`):

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YXVsdF9wYXRoIjoiL2hvbWUvdXNlci8uc2VjcmV0cy92YXVsdC5qc29uIiwiaWF0IjoxNzExNTI3MDAwLCJleHAiOjE3MTE1Mjg4MDB9.abc123signature",
  "expires_in": 1800
}
```

| Field | Type | Description |
|-------|------|-------------|
| `token` | `string` | JWT token (HS256 signature) |
| `expires_in` | `integer` | Token validity period in seconds, determined by global config `web.session_timeout`, default 1800 |

**JWT Payload structure**:

```json
{
  "vault_path": "/home/user/.secrets/vault.json",
  "iat": 1711527000,
  "exp": 1711528800
}
```

| Field | Type | Description |
|-------|------|-------------|
| `vault_path` | `string` | Path to the vault file served by this instance |
| `iat` | `integer` | Issued-at time (Unix timestamp) |
| `exp` | `integer` | Expiration time (Unix timestamp) |

**JWT signing key**: A random 32-byte value generated at server startup (`os.urandom(32)`), valid for the lifetime of the process. All tokens are invalidated when the service restarts.

**Failure response** (`401 Unauthorized`):

```json
{
  "error": "authentication_failed",
  "message": "Invalid vault password"
}
```

**Rate limit response** (`403 Forbidden`):

```json
{
  "error": "rate_limited",
  "message": "Too many failed attempts. Locked out for 300 seconds.",
  "retry_after": 300
}
```

#### 3.2.2 Rate Limiting

| Parameter | Default | Config Path | Description |
|-----------|---------|-------------|-------------|
| `max_attempts` | `5` | `web.rate_limit.max_attempts` | Maximum consecutive failed attempts |
| `lockout_seconds` | `300` | `web.rate_limit.lockout_seconds` | Lockout duration in seconds |

Implementation: in-memory counter, tracked per client IP. During lockout, all login requests return `403`.

#### 3.2.3 Authentication Middleware

Except for `POST /api/auth/login`, all `/api/*` endpoints require a JWT token in the request header:

```
Authorization: Bearer <token>
```

**Missing or invalid token**: Returns `401 Unauthorized`.

```json
{
  "error": "unauthorized",
  "message": "Missing or invalid authentication token"
}
```

**Expired token**: Returns `401 Unauthorized`.

```json
{
  "error": "token_expired",
  "message": "Authentication token has expired"
}
```

---

### 3.3 Secrets CRUD (Alias Model)

#### 3.3.1 List Secrets Pool — `GET /api/secrets`

**Request**:

```
GET /api/secrets
Authorization: Bearer <token>
```

No query parameters. Returns all secrets in the pool.

**Success response** (`200 OK`):

```json
[
  {
    "alias": "prod-db",
    "key": "DATABASE_URL",
    "value_masked": "••••••••",
    "description": "Production database",
    "tags": ["db", "backend"],
    "apps": ["backend"],
    "updated_at": "2026-03-27T11:00:00+08:00"
  },
  {
    "alias": "jwt-secret",
    "key": "JWT_SECRET",
    "value_masked": "••••••••",
    "description": "",
    "tags": [],
    "apps": ["backend", "auth"],
    "updated_at": "2026-03-27T10:30:00+08:00"
  }
]
```

| Response Field | Type | Description |
|----------------|------|-------------|
| `[].alias` | `string` | Secret alias |
| `[].key` | `string` | Environment variable name for injection |
| `[].value_masked` | `string` | Masked value `"••••••••"` |
| `[].description` | `string` | Description |
| `[].tags` | `array[string]` | Tag list |
| `[].apps` | `array[string]` | List of apps referencing this secret |
| `[].updated_at` | `string` | Last update time in ISO 8601 format |

---

#### 3.3.2 Get a Single Secret — `GET /api/secrets/:alias`

**Request**:

```
GET /api/secrets/prod-db?reveal=true
Authorization: Bearer <token>
```

| Path Parameter | Type | Required | Description |
|----------------|------|----------|-------------|
| `alias` | `string` | Yes | Secret alias |

| Query Parameter | Type | Required | Default | Description |
|-----------------|------|----------|---------|-------------|
| `reveal` | `boolean` | No | `false` | Whether to return the plaintext value |

**Success response** (`200 OK`, `reveal=false`):

```json
{
  "alias": "prod-db",
  "key": "DATABASE_URL",
  "value": "••••••••",
  "description": "Production database",
  "tags": ["db", "backend"],
  "apps": ["backend"],
  "updated_at": "2026-03-27T11:00:00+08:00"
}
```

**Success response** (`200 OK`, `reveal=true`):

```json
{
  "alias": "prod-db",
  "key": "DATABASE_URL",
  "value": "postgres://user:pass@host:5432/mydb",
  "description": "Production database",
  "tags": ["db", "backend"],
  "apps": ["backend"],
  "updated_at": "2026-03-27T11:00:00+08:00"
}
```

**Alias not found** (`404 Not Found`):

```json
{
  "error": "not_found",
  "message": "Alias \"prod-db\" not found"
}
```

---

#### 3.3.3 Create or Update a Secret — `PUT /api/secrets/:alias`

**Request**:

```
PUT /api/secrets/prod-db
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
  "key": "DATABASE_URL",
  "value": "postgres://user:newpass@host:5432/mydb",
  "description": "Production database",
  "tags": ["db", "backend"]
}
```

| Path Parameter | Type | Required | Description |
|----------------|------|----------|-------------|
| `alias` | `string` | Yes | Secret alias |

| Body Field | Type | Required | Default | Description |
|------------|------|----------|---------|-------------|
| `key` | `string` | Yes | — | Environment variable name for injection |
| `value` | `string` | Yes | — | Secret value, max 64 KB |
| `description` | `string` | No | `""` | Description |
| `tags` | `array[string]` | No | `[]` | Tag list |

**Success response** (`200 OK`, existing alias updated):

```json
{
  "alias": "prod-db",
  "created": false,
  "updated_at": "2026-03-27T12:00:00+08:00"
}
```

**Success response** (`201 Created`, new alias):

```json
{
  "alias": "prod-db",
  "created": true,
  "updated_at": "2026-03-27T12:00:00+08:00"
}
```

---

#### 3.3.4 Delete a Secret — `DELETE /api/secrets/:alias`

**Request**:

```
DELETE /api/secrets/prod-db
Authorization: Bearer <token>
```

| Path Parameter | Type | Required | Description |
|----------------|------|----------|-------------|
| `alias` | `string` | Yes | Secret alias |

**Success response** (`200 OK`):

```json
{
  "deleted": true,
  "removed_from_apps": ["backend"]
}
```

**Alias not found** (`404 Not Found`):

```json
{
  "error": "not_found",
  "message": "Alias \"prod-db\" not found"
}
```

---

### 3.3b App Secrets Management

#### 3.3b.1 Get Resolved Secrets for an App — `GET /api/apps/:app/secrets`

**Request**:

```
GET /api/apps/backend/secrets
Authorization: Bearer <token>
```

Returns the resolved secrets for the specified app (after alias resolution and overrides).

**Success response** (`200 OK`):

```json
{
  "app": "backend",
  "secrets": [
    {"alias": "prod-db", "injected_as": "DB_URL", "override": true},
    {"alias": "jwt-secret", "injected_as": "JWT_SECRET", "override": false}
  ]
}
```

#### 3.3b.2 Set App References — `PUT /api/apps/:app/secrets`

**Request**:

```
PUT /api/apps/backend/secrets
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
  "secrets": ["prod-db", "jwt-secret"],
  "overrides": {
    "prod-db": "DB_URL"
  }
}
```

**Success response** (`200 OK`):

```json
{
  "app": "backend",
  "assigned": 2
}
```

#### 3.3b.3 Remove a Single App Reference — `DELETE /api/apps/:app/secrets/:alias`

**Request**:

```
DELETE /api/apps/backend/secrets/prod-db
Authorization: Bearer <token>
```

**Success response** (`200 OK`):

```json
{
  "unassigned": true
}
```

---

### 3.4 Import & Export

#### 3.4.1 Import — `POST /api/secrets/import`

**Request**:

```
POST /api/secrets/import
Authorization: Bearer <token>
Content-Type: multipart/form-data
```

| Form Field | Type | Required | Default | Description |
|------------|------|----------|---------|-------------|
| `file` | `UploadFile` | Yes | — | A `.env` format file |
| `app` | `string` | No | `None` (global scope) | Target app name |

**Success response** (`200 OK`):

```json
{
  "imported": 5,
  "details": {
    "new": ["DATABASE_URL", "REDIS_URL", "JWT_SECRET"],
    "updated": ["API_KEY", "SENTRY_DSN"]
  }
}
```

| Response Field | Type | Description |
|----------------|------|-------------|
| `imported` | `integer` | Total number of keys imported |
| `details.new` | `array[string]` | List of newly added key names |
| `details.updated` | `array[string]` | List of updated key names |

**Empty file or no valid keys** (`422 Unprocessable Entity`):

```json
{
  "error": "validation_error",
  "message": "No valid key-value pairs found in uploaded file"
}
```

---

#### 3.4.2 Export — `GET /api/secrets/export`

**Request**:

```
GET /api/secrets/export?app=backend&format=json
Authorization: Bearer <token>
```

| Query Parameter | Type | Required | Default | Description |
|-----------------|------|----------|---------|-------------|
| `app` | `string` | No | `None` (global scope) | Application name |
| `format` | `string` (`env` \| `json`) | No | `env` | Export format |

**Success response** (`format=env`, `200 OK`, `Content-Type: text/plain`):

```
DATABASE_URL=postgres://user:pass@host:5432/mydb
REDIS_URL=redis://localhost:6379/0
JWT_SECRET=super-secret-jwt-key
```

Note: The Web API env export does **not** include the `export ` prefix (unlike the CLI `--format env` behavior), making it suitable for saving directly as a `.env` file.

**Success response** (`format=json`, `200 OK`, `Content-Type: application/json`):

```json
{
  "DATABASE_URL": "postgres://user:pass@host:5432/mydb",
  "REDIS_URL": "redis://localhost:6379/0",
  "JWT_SECRET": "super-secret-jwt-key"
}
```

---

### 3.5 App Management

#### 3.5.1 List Applications — `GET /api/apps`

**Request**:

```
GET /api/apps
Authorization: Bearer <token>
```

No query parameters.

**Success response** (`200 OK`):

```json
{
  "apps": [
    {
      "name": "global",
      "key_count": 2
    },
    {
      "name": "backend",
      "key_count": 5
    },
    {
      "name": "frontend",
      "key_count": 2
    },
    {
      "name": "worker",
      "key_count": 1
    }
  ]
}
```

| Response Field | Type | Description |
|----------------|------|-------------|
| `apps` | `array` | List of applications (always includes `"global"` as the first entry) |
| `apps[].name` | `string` | Application name (`"global"` represents the global scope) |
| `apps[].key_count` | `integer` | Total number of keys in this application |

---

### 3.6 Error Responses

#### 3.6.1 Error JSON Format

All error responses follow a uniform format:

```json
{
  "error": "<error_code>",
  "message": "<human_readable_message>",
  "details": []
}
```

| Field | Type | Always Present | Description |
|-------|------|----------------|-------------|
| `error` | `string` | Yes | Machine-readable error code |
| `message` | `string` | Yes | Human-readable message |
| `details` | `array` | Only for `422` | Field-level validation error details |

#### 3.6.2 HTTP Status Code to Error Code Mapping

| HTTP Status | Error Code | Trigger Condition | Example Response |
|-------------|------------|-------------------|------------------|
| `401` | `authentication_failed` | Incorrect login password | `{"error":"authentication_failed","message":"Invalid vault password"}` |
| `401` | `unauthorized` | Token missing or malformed | `{"error":"unauthorized","message":"Missing or invalid authentication token"}` |
| `401` | `token_expired` | Token has expired | `{"error":"token_expired","message":"Authentication token has expired"}` |
| `403` | `rate_limited` | Exceeded login attempt limit | `{"error":"rate_limited","message":"Too many failed attempts. Locked out for 300 seconds.","retry_after":300}` |
| `404` | `not_found` | Key or app does not exist | `{"error":"not_found","message":"Key \"X\" not found in app \"Y\""}` |
| `409` | `conflict` | Reserved — for future strict create-only semantics | `{"error":"conflict","message":"Key \"X\" already exists in app \"Y\""}` |
| `422` | `validation_error` | Request body field validation failure | See example below |

**422 detailed example**:

```json
{
  "error": "validation_error",
  "message": "Validation failed",
  "details": [
    {
      "field": "value",
      "message": "Value must not be empty"
    },
    {
      "field": "app",
      "message": "App name must match ^[A-Za-z_][A-Za-z0-9_]*$ and be at most 64 characters"
    }
  ]
}
```

#### 3.6.3 CORS Configuration

| Parameter | Default | Config Path | Description |
|-----------|---------|-------------|-------------|
| `allow_origins` | `["http://localhost:*"]` | `web.cors_origins` | List of allowed origin domains |
| `allow_methods` | `["GET", "PUT", "POST", "DELETE"]` | Not configurable | Allowed HTTP methods |
| `allow_headers` | `["Authorization", "Content-Type"]` | Not configurable | Allowed request headers |
| `allow_credentials` | `true` | Not configurable | Allow credentials |

### 3.7 Web UI Page Components

The web management interface is a static SPA (Single-Page Application) served directly from the Axum process. No separate frontend build or deployment pipeline is required.

| Page | Route | Description |
|------|-------|-------------|
| Login | `/` | Enter the vault password to authenticate and obtain a JWT token |
| Dashboard | `/dashboard` | Displays all apps and their key names (values hidden) in a list/group view with search and filtering |
| Add/Edit Modal | — (modal component) | Create a new key or edit an existing key's value; select the target app |
| Import/Export | `/import-export` | Upload a `.env` file for bulk import, or export by app in `.env` / JSON format |

> For detailed wireframes and interaction design, see the architecture document (`architecture.md`).

---

## Appendix A: Endpoint Summary Table

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/auth/login` | No | Authenticate and obtain JWT token |
| `GET` | `/api/secrets` | Yes | List all secrets in the pool |
| `GET` | `/api/secrets/:alias` | Yes | Get a single secret (optional reveal) |
| `PUT` | `/api/secrets/:alias` | Yes | Create or update a secret (by alias) |
| `DELETE` | `/api/secrets/:alias` | Yes | Delete from pool (cascade-removes app references) |
| `GET` | `/api/apps/:app/secrets` | Yes | Get resolved secrets for an app |
| `PUT` | `/api/apps/:app/secrets` | Yes | Set app secret references and overrides |
| `DELETE` | `/api/apps/:app/secrets/:alias` | Yes | Remove a single secret reference from app |
| `POST` | `/api/secrets/import` | Yes | Import a .env file |
| `GET` | `/api/secrets/export` | Yes | Export secrets |
| `GET` | `/api/apps` | Yes | List applications |

## Appendix B: CLI Command Summary Table

| Command | Required Arguments | Optional Arguments | Exit Codes |
|---------|--------------------|--------------------|------------|
| `init` | — | `--vault` | 0, 1 |
| `set` | `ALIAS`, `--key`, `--value` | `--description`, `--tags`, `--vault` | 0, 1, 2 |
| `get` | `ALIAS` | `--vault` | 0, 1, 2, 3 |
| `list` | — | `--app`, `--vault` | 0, 1, 2 |
| `delete` | `ALIAS` | `--vault` | 0, 1, 2, 3 |
| `assign` | `ALIAS`, `--app` | `--as`, `--vault` | 0, 1, 2, 3 |
| `unassign` | `ALIAS`, `--app` | `--vault` | 0, 1, 2, 3 |
| `run` | `COMMAND [ARGS]`, `--app` | `--vault` | 0, 1, 2, subprocess exit code |
| `export` | `--app` | `--vault`, `--format` | 0, 1, 2 |
| `import` | `--from FILE`, `--app` | `--vault` | 0, 1, 2 |
| `serve` | — | `--port`, `--host`, `--vault` | 0, 1 |
| `self-test` | — | — | 0, 1 |

## Appendix C: Validation Rules Summary

| Field | Regex/Rule | Max Length | Description |
|-------|-----------|-----------|-------------|
| Alias | `^[a-z0-9][a-z0-9-]*$` | 128 characters | Unique identifier in the secrets pool; lowercase alphanumeric and hyphens |
| Key name (env var) | `^[A-Za-z_][A-Za-z0-9_]*$` | 128 characters | Follows environment variable naming conventions |
| App name | `^[A-Za-z_][A-Za-z0-9_]*$` | 64 characters | Same constraint as key names |
| Value | Non-empty | 64 KB | Supports arbitrary UTF-8 strings |
| Vault password | No regex constraint | No limit | Recommended >= 12 characters (advisory only at UI/docs level, not enforced) |

---

*Document version: 4.0 | Updated: 2026-03-28 | Data model: alias-based | Related decision: Pure Rust + clap CLI ([`tech_decision.md`](./tech_decision.md))*
