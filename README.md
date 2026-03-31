<p align="center">
  <img src="docs/assets/branding/logo.svg" alt="Enva logo" width="320">
</p>

<h1 align="center">Enva</h1>

<p align="center">
  Encrypted environment variable manager with per-app injection and a built-in web UI.
</p>

<p align="center">
  <a href="https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.3.0"><img src="https://img.shields.io/github/v/release/YoRHa-Agents/EnvA?label=release" alt="Latest release"></a>
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/changelog-v0.3.0-6366f1" alt="Changelog"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-22c55e" alt="MIT license"></a>
</p>

<p align="center">
  <a href="#spotlight">Spotlight</a>
  ·
  <a href="#demo-snapshots">Demo Snapshots</a>
  ·
  <a href="#installation">Installation</a>
  ·
  <a href="#quick-start">Quick Start</a>
  ·
  <a href="https://github.com/YoRHa-Agents/EnvA/releases">Releases</a>
</p>

Enva stores secrets in a local AES-256-GCM encrypted vault, derives keys with Argon2id,
verifies integrity with HMAC-SHA256, and injects resolved values into the exact app
process that needs them. It is designed for teams that want a local-first workflow,
strong crypto defaults, a fast CLI, and a clean web UI instead of passing `.env` files
around by hand.

## Spotlight

- Local-first encrypted vault with AES-256-GCM at rest, Argon2id key derivation, and
  HMAC-SHA256 integrity checks.
- App-aware secret injection so each application receives only the aliases assigned to it.
- Built-in web UI for browsing, editing, renaming, assigning, importing, and exporting secrets.
- Built-in self-update via `enva update` so installed binaries can track GitHub Releases
  without rerunning the install script.
- Web SSH management can read `~/.ssh/config`, persist additional web-managed hosts under
  `~/.enva/ssh_hosts.json`, preview remote vault contents, and run full or selective
  `deploy` / `sync-from` actions without leaving the UI.
- Cross-platform release binaries plus `build.sh` for parallel multi-target packaging
  under `release/`.

## New In v0.3.0

- `enva update [--version <tag>] [--force]` fetches the matching binary from GitHub Releases,
  verifies its size / SHA256 digest, and atomically replaces the current executable.
- The web `Remote` modal can preview remote vault metadata, select specific secrets/apps for
  sync or deploy, and manage additional SSH hosts stored in `~/.enva/ssh_hosts.json`.
- The web settings modal can check whether a newer GitHub Release is available for the current
  platform and point operators to the CLI update flow.

## Demo Snapshots

<table>
  <tr>
    <td width="50%">
      <img src="docs/assets/screenshots/login-dark.png" alt="Enva login screen in dark theme" width="100%">
      <br>
      <sub>Unlock or initialize the local vault from a focused, single-screen login flow.</sub>
    </td>
    <td width="50%">
      <img src="docs/assets/screenshots/secrets-overview-dark.png" alt="Enva secrets overview in dark theme" width="100%">
      <br>
      <sub>Browse the shared secrets pool, app assignments, tags, and usage state at a glance.</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <img src="docs/assets/screenshots/secret-editor-dark.png" alt="Enva secret editor modal in dark theme" width="100%">
      <br>
      <sub>Edit keys, values, tags, and app bindings without leaving the dashboard.</sub>
    </td>
    <td width="50%">
      <img src="docs/assets/screenshots/secrets-overview-light.png" alt="Enva secrets overview in light theme" width="100%">
      <br>
      <sub>Built-in light mode keeps the same structure for teams that prefer a brighter workspace.</sub>
    </td>
  </tr>
</table>

## Supported Platforms

| Platform | Architecture | Binary Name |
|----------|-------------|-------------|
| Linux | x86_64 | `enva-linux-x86_64` |
| Linux | aarch64 | `enva-linux-aarch64` |
| macOS | Apple Silicon (aarch64) | `enva-macos-aarch64` |

## Installation

### Option A: Install Script (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/YoRHa-Agents/EnvA/main/scripts/install.sh | bash
```

The binary is installed to `~/.local/bin/enva` by default. Override with:

```bash
INSTALL_DIR=/usr/local/bin bash install.sh
```

### Option B: Build from Source

Requires [Rust](https://rustup.rs/) 1.85 or later.

```bash
git clone https://github.com/YoRHa-Agents/EnvA.git && cd EnvA
cargo build --release
sudo cp target/release/enva /usr/local/bin/
```

### Option C: Build Release Packages

Generate one or more release artifacts under `release/`:

```bash
./build.sh linux-x86_64
./build.sh all
```

### Verify Installation

```bash
enva vault self-test
enva update --help
```

## Quick Start

```bash
# 1. Create a vault
enva vault init --vault ./my.vault.json

# 2. Store a secret
enva vault set db-url -k DATABASE_URL -V "postgres://user:pass@host/db"

# 3. Assign the secret to an app
enva vault assign db-url --app backend

# 4. Run a command with secrets injected
enva backend -- printenv DATABASE_URL

# 5. Dry-run: see what would be injected
enva backend
```

## Usage

### Default: Web UI

Running `enva` with no arguments starts the built-in web configuration UI:

```bash
enva                                     # http://127.0.0.1:8080
enva serve --port 3000 --host 0.0.0.0   # custom bind
```

The web UI now includes a `Remote` flow that reads SSH hosts from `~/.ssh/config`,
merges them with editable web-managed hosts stored in `~/.enva/ssh_hosts.json`,
supports remote vault preview, selective sync/deploy, full diff/merge review, and
legacy whole-vault `deploy` / `sync-from` actions. When an `IdentityFile` is
present it is reused automatically; otherwise the web flow falls back to password
auth for preview or the local SSH agent for full sync/deploy operations.

### Self Update

Use the built-in updater to fetch the latest compatible release asset from GitHub:

```bash
enva update
enva update --version v0.3.0
enva update --force
```

The updater matches the current platform against the published release assets
(`enva-linux-x86_64`, `enva-linux-aarch64`, `enva-macos-aarch64`), verifies the
downloaded binary, and atomically replaces the installed executable in place.

### App Injection

Inject all secrets assigned to an app as environment variables, then exec a command:

```bash
enva backend -- ./start-server
enva worker  -- node worker.js
```

Dry-run (list what would be injected without running anything):

```bash
enva backend
```

For CI and scripting, pipe the password via stdin:

```bash
echo "$VAULT_PASSWORD" | enva --password-stdin backend -- ./start-server
```

### Global Options

| Flag | Env Var | Description |
|------|---------|-------------|
| `--vault <PATH>` | `ENVA_VAULT_PATH` | Path to vault file; supports `~` and relative paths resolved from the current working directory |
| `--config <PATH>` | `ENVA_CONFIG` | Path to config file |
| `--password-stdin` | | Read password from stdin |
| `-q, --quiet` | | Suppress non-essential output |
| `-v, --verbose` | | Enable debug-level logging |

### Vault Management

All vault operations live under `enva vault`:

```bash
enva vault init --vault ./project.vault.json
enva vault set <alias> -k <KEY> -V <value> [-d <desc>] [-t <tags>]
enva vault edit <alias> [--key <KEY>] [--value <val>] [--description <d>] [--tags <t>]
enva vault get <alias>
enva vault list [--app <name>]
enva vault delete <alias> [--yes]
enva vault assign <alias> --app <name> [--as <OVERRIDE_KEY>]
enva vault unassign <alias> --app <name>
enva vault export --app <name> [--format json]
enva vault import-env --from .env --app <name>
enva vault deploy --to user@host:/path/to/vault.json [--ssh-port 22] [--ssh-key ~/.ssh/id_ed25519] [--overwrite]
enva vault sync-from --from user@host:/path/to/vault.json [--ssh-port 22] [--ssh-password ...] [--overwrite]
enva vault self-test
```

Vault and application paths accept `~`, relative, or absolute input. Relative paths are resolved from the current working directory at the moment `enva` runs. For direct `enva <APP>` launches, the vault-stored `app_path` takes precedence; if it is blank, `.enva.yaml` `apps.<name>.app_path` is used as a fallback.

Each secret and application is also assigned an internal immutable id in the vault
file so web-based alias or app-name renames preserve assignments, overrides, and
runtime injection behavior across saves.

## Configuration

Enva loads configuration from two levels:

### Global Config (`~/.enva/config.yaml`)

User-wide defaults for vault path, password caching, KDF parameters, shell
integration, web UI settings, and logging. See
[`config/enva.example.yaml`](config/enva.example.yaml) for all options.

### Project Config (`.enva.yaml` in project root)

Per-project app definitions and vault path override. Committed to version
control (contains no secret values). See
[`config/enva.project.example.yaml`](config/enva.project.example.yaml).

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ENVA_VAULT_PATH` | Override vault file path |
| `ENVA_CONFIG` | Override config file path |
| `ENVA_APP` | Override default app name |

## Architecture

| Crate | Description |
|-------|-------------|
| `enva-core` | Core library: AES-256-GCM, HKDF, Argon2id KDF, HMAC-SHA256, vault crypto, secret types, resolution |
| `enva` | CLI binary (clap) plus embedded Axum web UI |

## Development

```bash
cargo test --workspace
cargo bench
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
```

## Documentation

Design docs, API specs, vault format, and deployment guides are in [`docs/`](docs/).

Last updated: `2026-03-31`

For AI agents, see [`docs/agent-index.md`](docs/agent-index.md) for a structured
command reference and workflow examples optimized for LLM consumption.

## License

MIT
