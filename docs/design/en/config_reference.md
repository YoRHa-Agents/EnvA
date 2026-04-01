# Configuration Reference

> **摘要 (Chinese Summary):** 秘钥管理器五层配置体系的完整参考文档。涵盖全局配置 (`~/.enva/config.yaml`)、项目配置 (`.enva.yaml`)、环境覆盖 (`.enva.{env}.yaml`)、CLI flags/环境变量以及内置默认值。每个字段均定义了路径、类型、默认值、说明、校验规则、示例和可设定层级。合并优先级：CLI > 环境覆盖 > 项目配置 > 全局配置 > 内置默认值。

---

## 1. Five-Layer Configuration Overview

Configuration is organized into five layers ordered by priority from highest to lowest. Higher layers override same-named fields in lower layers.

| Layer | Name | Path / Source | Scope | Format |
|-------|------|---------------|-------|--------|
| **Layer 5** (highest) | CLI flags / environment variables | Command-line arguments, `ENVA_*` environment variables | Single execution | N/A |
| **Layer 4** | Environment override | `.enva.{env}.yaml` | Project + specific environment | YAML |
| **Layer 3** | Project config | `.enva.yaml` | Project directory | YAML |
| **Layer 2** | Global config | `~/.enva/config.yaml` | User-level, cross-project | YAML |
| **Layer 1** (lowest) | Built-in defaults | Hard-coded in the program | Global | N/A |

---

## 2. CLI Flags and Environment Variables (Layer 5)

| Flag | Environment Variable | Type | Description | Overrides Config Field |
|------|---------------------|------|-------------|----------------------|
| `--vault PATH` | `ENVA_VAULT_PATH` | string | Vault file path | `defaults.vault_path` / `vault_path` |
| `--app NAME` | `ENVA_APP` | string | Target app name | `default_app` |
| `--password-stdin` | — | bool | Read password from stdin | — |
| `--config PATH` | `ENVA_CONFIG` | string | Specify the global config file path | — |
| `--env ENV` | — | string | Activate environment override file `.enva.{ENV}.yaml` | — |
| `--quiet` | — | bool | Quiet mode — output results only | — |
| `--verbose` | — | bool | Verbose output (includes debug information) | `logging.level` → debug |
| — | `ENVA_PASSWORD` | string | Vault password (for CI/automation only; not recommended in production) | — |

**Priority rules**: CLI flag > environment variable > config file field. `--quiet` and `--verbose` are mutually exclusive; when both are specified, `--verbose` takes precedence.

---

## 3. Global Configuration Field Reference (Layer 2)

File path: `~/.enva/config.yaml`

### 3.1 Top-Level Fields

| Field Path | Type | Default | Description | Validation | Example | Applicable Layers |
|------------|------|---------|-------------|------------|---------|-------------------|
| `version` | string | `"1"` | Config file format version number for future forward-compatible migration | Required; currently only `"1"` is allowed | `"1"` | L2 |

### 3.2 defaults — Default Behavior

| Field Path | Type | Default | Description | Validation | Example | Applicable Layers |
|------------|------|---------|-------------|------------|---------|-------------------|
| `defaults.vault_path` | string | `"~/.enva/vault.json"` | Default vault file path; can be overridden by project config or `--vault` | Optional; path string, supports `~` expansion and relative paths resolved from the current working directory | `"~/.enva/vault.json"` | L2, L3, L4, L5 |
| `defaults.password_timeout` | int | `300` | Seconds to cache the password in memory; `0` means prompt for every operation | Optional; `>= 0` | `300` | L2 |
| `defaults.password_cache` | enum | `"memory"` | Password caching mode | Optional; one of `memory` \| `keyring` \| `none` | `"memory"` | L2 |

**`password_cache` enum values**:

| Value | Behavior |
|-------|----------|
| `memory` | Password is cached in process memory for `password_timeout` seconds; cleared when the process exits |
| `keyring` | Uses the OS keyring (macOS Keychain / Linux Secret Service) for persistent caching |
| `none` | No caching; password is required for every operation |

### 3.3 defaults.kdf — Key Derivation Function Parameters

| Field Path | Type | Default | Description | Validation | Example | Applicable Layers |
|------------|------|---------|-------------|------------|---------|-------------------|
| `defaults.kdf.algorithm` | enum | `"argon2id"` | KDF algorithm; Argon2id is the password hashing algorithm recommended by RFC 9106 | Optional; one of `argon2id` \| `scrypt` | `"argon2id"` | L2 |
| `defaults.kdf.memory_cost` | int | `65536` | Memory cost in KiB; `65536` = 64 MB | Optional; `>= 8192` (8 MB minimum security threshold) | `65536` | L2 |
| `defaults.kdf.time_cost` | int | `3` | Iteration count; higher values are slower but more secure | Optional; `>= 1` | `3` | L2 |
| `defaults.kdf.parallelism` | int | `4` | Number of parallel threads | Optional; `>= 1`, `<= 256` | `4` | L2 |

> **Note**: KDF parameters are written to `_meta.kdf` at vault creation time. Subsequent decryption operations use the parameters embedded in the vault itself. The KDF parameters in global config only affect the default values used when **creating a new vault**.

### 3.4 shell — Shell Integration

| Field Path | Type | Default | Description | Validation | Example | Applicable Layers |
|------------|------|---------|-------------|------------|---------|-------------------|
| `shell.default_mode` | enum | `"exec"` | Default injection mode | Optional; one of `exec` \| `export` | `"exec"` | L2 |
| `shell.auto_inject` | bool | `false` | Whether to automatically inject secrets into the environment when a shell hook fires | Optional | `false` | L2 |
| `shell.history_protection` | bool | `true` | Prevent secrets from appearing in shell history (bash: `HISTCONTROL=ignorespace`; zsh: `setopt HIST_IGNORE_SPACE`) | Optional | `true` | L2 |
| `shell.hooks.bash` | string | `"~/.secrets/hooks/secrets-hook.bash"` | Path to the bash hook script | Optional; path string | `"~/.secrets/hooks/secrets-hook.bash"` | L2 |
| `shell.hooks.zsh` | string | `"~/.secrets/hooks/secrets-hook.zsh"` | Path to the zsh hook script | Optional; path string | `"~/.secrets/hooks/secrets-hook.zsh"` | L2 |

**Injection mode descriptions**:

| Mode | Behavior | Security |
|------|----------|----------|
| `exec` | Injects via a subprocess: `enva --cmd "<command>" <app>`; secrets exist only in the child process environment | High — secrets do not persist in the parent shell |
| `export` | Injects into the current shell via `eval "$(enva vault export --app <app> --format env)"`  | Medium — should be paired with `history_protection` |

### 3.5 web — Web Management Interface

| Field Path | Type | Default | Description | Validation | Example | Applicable Layers |
|------------|------|---------|-------------|------------|---------|-------------------|
| `web.host` | string | `"127.0.0.1"` | Web server listen address | Optional; valid IP address or `"0.0.0.0"` | `"127.0.0.1"` | L2, L5 |
| `web.port` | int | `8080` | Web server listen port | Optional; `1024–65535` | `8080` | L2, L5 |
| `web.cors_origins` | list\[string\] | `["http://localhost:*"]` | CORS allowlist; supports wildcard `*` | Optional; list of strings | `["http://localhost:*"]` | L2 |
| `web.session_timeout` | int | `1800` | Web session timeout in seconds; re-authentication is required after timeout | Optional; `>= 60` | `1800` | L2 |
| `web.rate_limit.max_attempts` | int | `5` | Maximum failed password attempts before lockout | Optional; `>= 1` | `5` | L2 |
| `web.rate_limit.lockout_seconds` | int | `300` | Lockout duration in seconds | Optional; `>= 0`; `0` disables lockout | `300` | L2 |

### 3.6 logging — Logging and Auditing

| Field Path | Type | Default | Description | Validation | Example | Applicable Layers |
|------------|------|---------|-------------|------------|---------|-------------------|
| `logging.level` | enum | `"warning"` | Log level | Optional; one of `debug` \| `info` \| `warning` \| `error` | `"warning"` | L2, L5 |
| `logging.audit_file` | string \| null | `"~/.secrets/audit.log"` | Audit log file path; set to `null` to disable audit logging | Optional; path string or `null` | `"~/.secrets/audit.log"` | L2 |
| `logging.redact_values` | bool | `true` | Redact secret values in log output (uses the `redact_secret()` logic in `enva-core`, `audit.rs`) | Optional | `true` | L2 |

> **Note**: `logging.audit_file` uses a simple file logger. The log format is straightforward and suitable for consumption by external log aggregation systems.

---

## 4. Project Configuration Field Reference (Layer 3)

File path: `.enva.yaml` (project root directory)

### 4.1 Top-Level Fields

| Field Path | Type | Default | Description | Validation | Example | Applicable Layers |
|------------|------|---------|-------------|------------|---------|-------------------|
| `vault_path` | string | Inherited from global `defaults.vault_path` | Project-specific vault file path | Optional; path string, supports `~` and relative paths resolved from the current working directory | `"./secrets/project.vault.json"` | L3, L4, L5 |
| `default_app` | string | `""` | Default `--app` value; used when CLI does not specify `--app` | Optional; must match an app name defined under `apps` | `"backend"` | L3, L4, L5 |

### 4.2 apps.\<name\> — Application Definitions (Alias Reference Model)

`apps` is a map where each key is an application name (used with the `--app` option) and each value is an application configuration object. Apps reference secrets in the global pool by alias rather than owning them directly.

| Field Path | Type | Default | Description | Validation | Example | Applicable Layers |
|------------|------|---------|-------------|------------|---------|-------------------|
| `apps.<name>.description` | string | `""` | Human-readable description of the application; displayed in `enva vault list` output | Optional | `"Backend API service"` | L3, L4 |
| `apps.<name>.secrets` | list\[string\] | `[]` | List of secret aliases referenced by this app; each alias points to a secret in the pool | Optional; list of strings, each must be a defined alias in the secrets pool | `["prod-db", "jwt-secret", "shared-sentry"]` | L3, L4 |
| `apps.<name>.overrides` | map\[string, string\] | `{}` | Map of alias → custom env var name for injection override; aliases not in this map use the secret's own `key` value for injection | Optional; keys are aliases, values are valid env var names | `{"prod-db": "DB_URL"}` | L3, L4 |
| `apps.<name>.app_path` | string | `""` | Local executable path used when running `enva <APP> [ARGS...]` | Optional; supports `~`, relative paths resolved from the current working directory at launch time, and absolute paths. If the vault entry for the app has a non-empty `app_path`, that value wins; otherwise this config value is used as a fallback | `"./bin/backend"` | L3, L4 |
| `apps.<name>.override_system` | bool | `false` | Whether to override existing system environment variables with vault values when a name conflict occurs | Optional | `false` | L3, L4 |

**Alias resolution injection logic**:

```
for alias in app.secrets:
    if alias in app.overrides:
        env_var_name = app.overrides[alias]
    else:
        env_var_name = secrets_pool[alias].key
    env[env_var_name] = decrypt(secrets_pool[alias].value)
```

**Configuration example**:

```yaml
apps:
  backend:
    description: "Backend API"
    app_path: "./bin/backend"
    secrets: ["prod-db", "jwt-secret", "shared-sentry"]
    overrides:
      prod-db: "DB_URL"
    override_system: false
  frontend:
    secrets: ["shared-sentry"]
    overrides:
      shared-sentry: "NEXT_PUBLIC_SENTRY_DSN"
```

In this example:
- `backend` references 3 secrets; `prod-db` is injected as `DB_URL` (instead of the default `DATABASE_URL`)
- `backend` can also be launched directly with `enva backend --port 3000`, resolving `./bin/backend` from the current working directory and forwarding `--port 3000`
- `frontend` references 1 secret; injected as `NEXT_PUBLIC_SENTRY_DSN` (instead of the default `SENTRY_DSN`)
- `shared-sentry` is shared across multiple apps without duplication

---

## 5. Environment Override Configuration (Layer 4)

File path: `.enva.{env}.yaml` (e.g. `.enva.staging.yaml`, `.enva.production.yaml`)

The environment override file has the same field structure as the project configuration (Layer 3); all fields may appear. Activation:

```bash
enva --env staging backend --port 3000
```

Fields in the environment override file are **deep-merged** on top of the project configuration. Same-named apps under `apps` have their fields overridden one by one; differently named apps retain their definitions from the project configuration.

---

## 6. Built-in Defaults (Layer 1)

When no layer has set a given field, the following built-in defaults are used:

| Field Path | Built-in Default |
|------------|------------------|
| `version` | `"1"` |
| `defaults.vault_path` | `"~/.enva/vault.json"` |
| `defaults.password_timeout` | `300` |
| `defaults.password_cache` | `"memory"` |
| `defaults.kdf.algorithm` | `"argon2id"` |
| `defaults.kdf.memory_cost` | `65536` |
| `defaults.kdf.time_cost` | `3` |
| `defaults.kdf.parallelism` | `4` |
| `shell.default_mode` | `"exec"` |
| `shell.auto_inject` | `false` |
| `shell.history_protection` | `true` |
| `shell.hooks.bash` | `"~/.secrets/hooks/secrets-hook.bash"` |
| `shell.hooks.zsh` | `"~/.secrets/hooks/secrets-hook.zsh"` |
| `web.host` | `"127.0.0.1"` |
| `web.port` | `8080` |
| `web.cors_origins` | `["http://localhost:*"]` |
| `web.session_timeout` | `1800` |
| `web.rate_limit.max_attempts` | `5` |
| `web.rate_limit.lockout_seconds` | `300` |
| `logging.level` | `"warning"` |
| `logging.audit_file` | `"~/.secrets/audit.log"` |
| `logging.redact_values` | `true` |
| `vault_path` | Inherited from `defaults.vault_path` |
| `default_app` | `""` |
| `apps.<name>.description` | `""` |
| `apps.<name>.secrets` | `[]` |
| `apps.<name>.overrides` | `{}` |
| `apps.<name>.app_path` | `""` |
| `apps.<name>.override_system` | `false` |

---

## 7. Merge Rules

### 7.1 Configuration Merge Priority

```
CLI flags / env vars        (Layer 5, highest)
       ↓ overrides
.enva.{env}.yaml         (Layer 4, environment override)
       ↓ overrides
.enva.yaml               (Layer 3, project config)
       ↓ overrides
~/.enva/config.yaml         (Layer 2, global config)
       ↓ overrides
Built-in defaults           (Layer 1, lowest)
```

**Merge strategy**:

| Field Type | Merge Behavior |
|------------|----------------|
| Scalar (string, int, bool, enum) | Higher layer directly overrides lower layer |
| Map (e.g. `apps`, `kdf`) | Deep merge — recursive per-key; same key overridden by higher layer |
| List (e.g. `inject_keys`, `cors_origins`) | Higher layer replaces lower layer entirely (no element-level merge) |

### 7.2 Injection Priority (Alias Resolution Model)

When multiple sources provide an environment variable with the same name, the following priority determines the final value:

```
1. Value from CLI --env override file                        (highest)
2. Alias-resolved results for the app (with overrides applied)
3. Existing system environment variable                      (lowest)
```

When `override_system: true`, alias-resolved results override system environment variables. When `override_system: false` (default), existing system environment variables with the same name are not overridden.

### 7.3 Alias Resolution Injection Logic

```
for alias in apps[NAME].secrets:
    env_var = overrides.get(alias, secrets_pool[alias].key)
    value = decrypt(secrets_pool[alias].value)
    if override_system or env_var not in os.environ:
        env[env_var] = value
```

If the `secrets` list references an alias that does not exist in the pool, an error is raised and the process exits.

---

## 8. Configuration Directory Discovery

At startup, the program searches for the global configuration directory in the following order:

| Priority | Platform | Path | Condition |
|----------|----------|------|-----------|
| 1 | All platforms | Path specified by `$ENVA_CONFIG` | `--config` or `ENVA_CONFIG` environment variable is set |
| 2 | Linux | `$XDG_CONFIG_HOME/secrets/config.yaml` | `$XDG_CONFIG_HOME` is set |
| 3 | macOS | `~/Library/Application Support/secrets/config.yaml` | macOS detected (`sys.platform == "darwin"`) |
| 4 | All platforms | `~/.enva/config.yaml` | Universal fallback |

**Project configuration discovery**: Starting from the current working directory, traverse upward through parent directories searching for `.enva.yaml` until the filesystem root is reached. The first file found is used as the project configuration; `.enva.{env}.yaml` files in the same directory serve as environment override candidates.

### 8.1 Standalone Mode Config Discovery

Config discovery uses the following two sources:

| Priority | Path | Description |
|----------|------|-------------|
| 1 | `~/.enva/config.yaml` | User-level global configuration |
| 2 | `.enva.yaml` in the current directory | Current project configuration |

In standalone mode, host-framework integration fields in the config (if present) are ignored (no error is raised; they are silently skipped).

---

## 9. Validation Rules Summary

### 9.1 Type Constraints

| Type | Constraints |
|------|-------------|
| string | UTF-8 string; path-type fields support `~` expansion. Relative paths are joined to the current working directory. Environment-variable interpolation is not applied. |
| int | 64-bit signed integer |
| bool | `true` / `false` (native YAML booleans) |
| enum | Only the values listed in this document are allowed; case-sensitive |
| list\[string\] | YAML sequence where each element is a string |
| map | YAML mapping |

### 9.2 Value Range Constraints

| Field | Constraint | Behavior on Violation |
|-------|------------|----------------------|
| `defaults.password_timeout` | `>= 0` | Error and exit |
| `defaults.kdf.memory_cost` | `>= 8192` | Error: below security threshold |
| `defaults.kdf.time_cost` | `>= 1` | Error |
| `defaults.kdf.parallelism` | `1–256` | Error |
| `web.port` | `1024–65535` | Error |
| `web.session_timeout` | `>= 60` | Error |
| `web.rate_limit.max_attempts` | `>= 1` | Error |
| `web.rate_limit.lockout_seconds` | `>= 0` | — |
| `apps.<name>.secrets` aliases | Must exist in secrets pool | Error: alias not defined |

### 9.3 Validation Flow on Load

```
1. Parse YAML → raw dict
2. Check that the version field is a known version
3. Per-field type validation (type + enum value + value range)
4. Cross-field reference validation:
   - Aliases in the secrets list must be defined in the secrets pool
   - Keys in the overrides map must appear in the secrets list
   - default_app must be defined under apps (or be empty)
5. Merge all config layers (Layer 1 → Layer 5)
6. Path expansion (`~` → `$HOME`, relative paths → joined against the current working directory)
7. Return a frozen configuration object
```

---

## 10. Cross-References to Other Documents

| Referenced Content | Reference Document |
|-------------------|--------------------|
| Vault file format (`_meta.kdf` parameter definitions) | `secrets_manager_vault_spec.md` |
| CLI command signatures and `--vault`/`--app` options | `secrets_manager_api_spec.md` |
| Shell hook injection mechanism and history protection implementation | `secrets_manager_api_spec.md` |
| Encryption scheme (Argon2id + AES-256-GCM) technical decisions | `secrets_manager_tech_decision.md` |
| Cross-platform configuration directory differences | `secrets_manager_deployment.md` |
| Audit log `redact_secret()` reuse | `secrets_manager_codebase_analysis.md` |

---

## 11. Example Configuration Files

- Global config example: [`config/enva.example.yaml`](../../config/enva.example.yaml)
- Project config example: [`config/enva.project.example.yaml`](../../config/enva.project.example.yaml)

---

*Document version: 3.0 | Updated: 2026-04-01 | Data model: alias-based | Config format version: 1*
