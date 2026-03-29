# Enva

Encrypted environment variable manager with per-app injection and a built-in web UI.

Enva stores secrets in a local AES-256-GCM encrypted vault (Argon2id KDF, HMAC-SHA256 integrity)
and injects them as environment variables when launching applications.

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

### Cross-compilation

To build the macOS aarch64 binary from a Linux host:

```bash
cargo install cargo-zigbuild
rustup target add aarch64-apple-darwin
cargo zigbuild --release --target aarch64-apple-darwin
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

For CI/scripting, pipe the password via stdin:

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
| `enva` | CLI binary (clap) + embedded Axum web UI |

## Development

```bash
cargo test --workspace           # run tests
cargo bench                      # run benchmarks
cargo fmt --all -- --check       # check formatting
cargo clippy --workspace -- -D warnings  # lint
```

## Documentation

Design docs, API specs, vault format, and deployment guides are in [`docs/`](docs/).

For AI agents: see [`docs/agent-index.md`](docs/agent-index.md) for a structured
command reference and workflow examples optimized for LLM consumption.

## License

MIT
