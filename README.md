<p align="center">
  <img src="docs/assets/branding/banner.svg" alt="Enva banner" width="720">
</p>

<p align="center">
  <a href="https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.5.0"><img src="https://img.shields.io/github/v/release/YoRHa-Agents/EnvA?label=release&color=c4a35a" alt="Latest release"></a>
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/changelog-v0.5.0-8b7355" alt="Changelog"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-e8e6e3" alt="MIT license"></a>
  <a href="https://yorha-agents.github.io/EnvA/"><img src="https://img.shields.io/badge/docs-GitHub%20Pages-c4a35a" alt="Documentation"></a>
</p>

<p align="center">
  <a href="#-system-capabilities">Features</a>
  ·
  <a href="#-demo">Demo</a>
  ·
  <a href="#-deployment-protocol">Installation</a>
  ·
  <a href="#-operational-guide">Quick Start</a>
  ·
  <a href="https://yorha-agents.github.io/EnvA/">Documentation</a>
  ·
  <a href="https://yorha-agents.github.io/EnvA/demo.html">Live Demo</a>
</p>

---

> **Pod 042 — Status Report:** Enva stores secrets in a local AES-256-GCM encrypted vault,
> derives keys with Argon2id, verifies integrity with HMAC-SHA256, and injects resolved values
> into the exact application process that needs them. Designed for operators who prefer a
> local-first workflow, strong crypto defaults, a fast CLI, and a clean web UI over passing
> `.env` files by hand.

## 「 System Capabilities 」

- **Encrypted Vault** — AES-256-GCM at rest, Argon2id key derivation, HMAC-SHA256 integrity
  checks on every load.
- **App-Aware Injection** — Each application receives only the secret aliases assigned to it.
  Override env var names per-app without modifying the secret itself.
- **Built-in Web UI** — Browse, edit, rename, assign, import, and export secrets through an
  embedded web interface. No external dependencies.
- **Self-Update** — `enva update` fetches the latest compatible binary from GitHub Releases,
  verifies its SHA256 digest, and atomically replaces the installed executable.
- **SSH Remote Sync** — Read `~/.ssh/config`, preview remote vault contents, and run selective
  deploy/sync operations from the web UI.
- **Cross-Platform** — Pre-built binaries for Linux x86_64, Linux aarch64, and macOS Apple
  Silicon. Single static binary, zero runtime dependencies.

## 「 Demo 」

**[Try the interactive demo →](https://yorha-agents.github.io/EnvA/demo.html)**

Experience the full vault workflow in your browser — unlock, browse secrets, edit, assign to
apps, import/export — all running client-side with no backend required.

<table>
  <tr>
    <td width="50%">
      <img src="docs/assets/screenshots/demo-login.svg" alt="Enva demo login" width="100%">
      <br>
      <sub>Vault unlock screen — enter any password to access the simulation.</sub>
    </td>
    <td width="50%">
      <img src="docs/assets/screenshots/demo-secrets.svg" alt="Enva demo secrets" width="100%">
      <br>
      <sub>Secrets overview — browse aliases, keys, tags, and app assignments.</sub>
    </td>
  </tr>
</table>

## 「 Supported Platforms 」

| Platform | Architecture | Binary Name |
|----------|-------------|-------------|
| Linux | x86_64 | `enva-linux-x86_64` |
| Linux | aarch64 | `enva-linux-aarch64` |
| macOS | Apple Silicon | `enva-macos-aarch64` |

## 「 Deployment Protocol 」

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

```bash
./build.sh linux-x86_64
./build.sh all
```

### Verify Installation

```bash
enva vault self-test
enva update --help
```

## 「 Operational Guide 」

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

### Web UI

```bash
enva                                     # http://127.0.0.1:8080
enva serve --port 3000 --host 0.0.0.0   # custom bind
```

The web UI includes SSH remote management: reads `~/.ssh/config`, supports web-managed hosts
via `~/.enva/ssh_hosts.json`, remote vault preview, selective sync/deploy, diff/merge review,
and legacy whole-vault deploy/sync-from actions.

### Self Update

```bash
enva update
enva update --version v0.5.0
enva update --force
```

### App Injection

```bash
enva backend -- ./start-server
enva worker  -- node worker.js
```

Dry-run:

```bash
enva backend
```

For CI/scripting:

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

```bash
enva vault init --vault ./project.vault.json
enva vault set <alias> -k <KEY> -V <value> [-d <desc>] [-t <tags>]
enva vault edit <alias> [--key <KEY>] [--value <val>] [--description <d>] [--tags <t>]
enva vault get <alias>
enva vault list [--app <name>]
enva vault delete <alias> [--yes]
enva vault assign <alias> --app <name> [--as <OVERRIDE_KEY>]
enva vault unassign <alias> --app <name>
enva vault export [--app <name>] [--format env|json|enva-json|yaml]
enva vault import --from <file> [--format env|json|enva-json|yaml] [--app <name>]
enva vault deploy --to user@host:/path/to/vault.json [--ssh-port 22] [--ssh-key ~/.ssh/id_ed25519] [--overwrite]
enva vault sync-from --from user@host:/path/to/vault.json [--ssh-port 22] [--ssh-password ...] [--overwrite]
enva vault self-test
```

`json` keeps the existing resolved key/value export. `enva-json` and `yaml` export portable Enva bundles that can be re-imported with `enva vault import`. `enva vault import-env` remains available as a compatibility alias for `.env`-style workflows.

## 「 Configuration 」

### Global Config (`~/.enva/config.yaml`)

User-wide defaults for vault path, password caching, KDF parameters, shell integration, web UI
settings, and logging. See [`config/enva.example.yaml`](config/enva.example.yaml).

### Project Config (`.enva.yaml`)

Per-project app definitions and vault path override. Committed to version control (no secrets).
See [`config/enva.project.example.yaml`](config/enva.project.example.yaml).

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ENVA_VAULT_PATH` | Override vault file path |
| `ENVA_CONFIG` | Override config file path |
| `ENVA_APP` | Override default app name |

## 「 Architecture 」

| Crate | Description |
|-------|-------------|
| `enva-core` | Core library: AES-256-GCM, HKDF, Argon2id KDF, HMAC-SHA256, vault crypto, secret types, resolution |
| `enva` | CLI binary (clap) plus embedded Axum web UI |

## 「 Development 」

```bash
cargo test --workspace
cargo bench
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contribution guide.

## 「 Documentation 」

- **[GitHub Pages](https://yorha-agents.github.io/EnvA/)** — Project site with interactive demo
- **[docs/](docs/)** — Design docs, API specs, vault format, deployment guides
- **[docs/agent-index.md](docs/agent-index.md)** — Structured command reference for LLM consumption

Last updated: `2026-03-31`

## 「 License 」

MIT

---

<p align="center">
  <i>Glory to Mankind.</i>
</p>
