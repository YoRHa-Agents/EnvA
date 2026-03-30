<p align="center">
  <img src="docs/assets/branding/logo.svg" alt="Enva logo" width="320">
</p>

<h1 align="center">Enva</h1>

<p align="center">
  Encrypted environment variable manager with per-app injection and a built-in web UI.
</p>

<p align="center">
  <a href="https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.1.0"><img src="https://img.shields.io/github/v/release/YoRHa-Agents/EnvA?label=release" alt="Latest release"></a>
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/changelog-v0.1.0-6366f1" alt="Changelog"></a>
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
- Built-in web UI for browsing, editing, assigning, importing, and exporting secrets.
- Cross-platform release binaries plus `build.sh` for parallel multi-target packaging
  under `release/`.

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
| `--vault <PATH>` | `ENVA_VAULT_PATH` | Path to vault file |
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
enva vault self-test
```

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

For AI agents, see [`docs/agent-index.md`](docs/agent-index.md) for a structured
command reference and workflow examples optimized for LLM consumption.

## License

MIT
