# Cross-Platform Deployment Design

> **摘要:** Enva 的跨平台部署方案英文版。涵盖 x86_64 Linux 和 aarch64 macOS (Apple Silicon) 双平台支持。Enva 是一个纯 Rust CLI 应用，编译为单一静态二进制文件。CI 在 `ubuntu-latest` (x86_64) 和 `macos-14` (aarch64) 上预编译发布二进制，最终用户通过安装脚本或直接下载获取。开发贡献者需要 Rust 工具链用于 `cargo build`。文档涵盖平台矩阵、构建流程、二进制分发策略、各平台安装流程、幂等安装脚本和 CI 矩阵。

---

## Table of Contents

1. [Target Platform Matrix](#1-target-platform-matrix)
2. [Build and Distribution Strategy](#2-build-and-distribution-strategy)
3. [Linux x86_64 Installation Flow Design](#3-linux-x86_64-installation-flow-design)
4. [macOS aarch64 Installation Flow Design](#4-macos-aarch64-installation-flow-design)
5. [Install Script Design](#5-install-script-design)
6. [CI Matrix Design](#6-ci-matrix-design)

---

## 1. Target Platform Matrix

| Platform | Architecture | Rust Target | Status | Notes |
|----------|-------------|-------------|--------|-------|
| Linux | x86_64 | `x86_64-unknown-linux-gnu` | **Primary dev platform** | CI primary runner: `ubuntu-latest` |
| macOS | aarch64 (Apple Silicon) | `aarch64-apple-darwin` | **Must support** | CI runner: `macos-14` (M1) |

### Key Constraints

- **Enva is a pure Rust CLI application**: the `enva-core` library crate provides cryptographic operations (AES-256-GCM, Argon2id KDF) and vault management; the `enva` binary crate provides the CLI, web server, and shell hooks.
- **Single static binary**: `cargo build --release` produces a single binary with no runtime dependencies.
- **End users do not need a Rust toolchain**: CI pre-compiles binaries on both target platforms; users download the appropriate binary for their platform.
- **Development contributors need a Rust toolchain**: Local development uses `cargo build` to compile from source.

---

## 2. Build and Distribution Strategy

### 2.1 Build Process

```bash
cargo build --release
```

Cargo automatically handles:
- Rust compilation with release optimizations
- Static linking of all dependencies
- Platform-specific binary generation

The output binary is located at `target/release/enva`.

### 2.2 CI Build Matrix

| CI Runner | Rust Target | Artifact |
|-----------|-------------|----------|
| `ubuntu-latest` | `x86_64-unknown-linux-gnu` | `enva-linux-x86_64` |
| `macos-14` | `aarch64-apple-darwin` | `enva-macos-aarch64` |

A total of **2 binary artifacts** (one per platform).

### 2.3 Distribution Channels

| Channel | Use Case | Description |
|---------|----------|-------------|
| **GitHub Releases** (recommended) | Public distribution | CI automatically uploads binaries as Release assets; users download from the Release page |
| **Install script** | Automated installation | `scripts/install-secrets.sh` detects platform and downloads the correct binary |
| **Build from source** | Developers / custom builds | `cargo build --release` for users with a Rust toolchain |

### 2.4 User Installation Experience

**End users** (no Rust environment):

```bash
curl -fsSL https://raw.githubusercontent.com/YoRHa-Agents/EnvA/main/scripts/install.sh | bash
```

The install script automatically detects the current platform and architecture, downloads the pre-compiled binary, and installs it to `~/.local/bin/` or `/usr/local/bin/`.

**Development contributors** (Rust environment required):

```bash
rustup default stable
cargo build --release
# Or install directly:
cargo install --path crates/enva
```

---

## 3. Linux x86_64 Installation Flow Design

### 3.1 Prerequisites

| Condition | Minimum Requirement | Detection Command | Notes |
|-----------|---------------------|-------------------|-------|
| Rust toolchain | Developers only | `rustc --version` | End users install via pre-compiled binary — no Rust needed |
| curl or wget | For install script | `command -v curl` | Used to download the binary |

### 3.2 Installation Steps

```bash
# Option A: Install script (recommended for end users)
curl -fsSL https://example.com/install.sh | bash

# Option B: Build from source (developers)
cargo build --release
cp target/release/enva ~/.local/bin/

# Step 2: Initialize the configuration directory
enva init
# Automatically performs:
#   - Creates ~/.enva/ directory
#   - Creates ~/.enva/config.yaml (default configuration)
#   - Creates ~/.enva/hooks/ directory
#   - Generates enva-hook.bash and enva-hook.zsh

# Step 3: Install shell hooks
enva hook install
# Automatically performs:
#   - Detects the current shell (bash/zsh)
#   - Appends a source line to ~/.bashrc or ~/.zshrc
#   - Will not duplicate (idempotent)

# Step 4: Verify installation
enva self-test
```

### 3.3 Shell Hook Installation Details (Linux)

**bash** (primary shell on Linux):

Append to the end of `~/.bashrc`:

```bash
# Enva secrets manager hook
[ -f "$HOME/.enva/hooks/enva-hook.bash" ] && source "$HOME/.enva/hooks/enva-hook.bash"
```

**zsh** (if the user uses zsh):

Append to the end of `~/.zshrc`:

```zsh
# Enva secrets manager hook
[ -f "$HOME/.enva/hooks/enva-hook.zsh" ] && source "$HOME/.enva/hooks/enva-hook.zsh"
```

### 3.4 Configuration Directory Structure (Linux)

```
~/.enva/
├── config.yaml          # Global configuration
├── vault.json           # Default vault file (created after init --vault)
├── hooks/
│   ├── enva-hook.bash
│   └── enva-hook.zsh
└── audit.log            # Audit log (created automatically at runtime)
```

---

## 4. macOS aarch64 Installation Flow Design

### 4.1 Prerequisites

| Condition | Minimum Requirement | Detection Command | Notes |
|-----------|---------------------|-------------------|-------|
| Rust toolchain | Developers only | `rustc --version` | End users install via pre-compiled binary — no Rust needed |
| curl | For install script | `command -v curl` | Included in macOS |

### 4.2 Installation Steps

```bash
# Option A: Install script (recommended for end users)
curl -fsSL https://example.com/install.sh | bash

# Option B: Build from source (developers)
cargo build --release
cp target/release/enva /usr/local/bin/

# Step 2: Initialize the configuration directory
enva init
# Automatically performs:
#   - Creates ~/.enva/ directory (unified path, not ~/Library/Application Support/)
#   - Creates ~/.enva/config.yaml (default configuration)
#   - Creates ~/.enva/hooks/ directory

# Step 3: Install shell hooks
enva hook install
# Automatically performs:
#   - Detects zsh (default shell on macOS)
#   - Appends a source line to ~/.zshrc

# Step 4: Verify installation
enva self-test
```

### 4.3 macOS-Specific Considerations

#### Configuration Directory Path

**Uses `~/.enva/` uniformly** — does not use `~/Library/Application Support/enva/`.

Rationale:
- Consistent with Linux behavior, reducing documentation and script maintenance cost
- Developers are more accustomed to dotfile directories
- Vault files may be synced cross-platform (e.g. via git); a unified path avoids path-mapping issues
- `~/Library/Application Support/` contains spaces in the path, adding script complexity

#### Shell Hook (macOS)

Since macOS Catalina (10.15), the default shell is **zsh**. The install script handles zsh only:

Append to the end of `~/.zshrc`:

```zsh
# Enva secrets manager hook
[ -f "$HOME/.enva/hooks/enva-hook.zsh" ] && source "$HOME/.enva/hooks/enva-hook.zsh"
```

### 4.4 Configuration Directory Structure (macOS)

Identical to Linux:

```
~/.enva/
├── config.yaml
├── vault.json
├── hooks/
│   └── enva-hook.zsh
└── audit.log
```

---

## 5. Install Script Design

### 5.1 Script Location

`scripts/install-secrets.sh`

### 5.2 Design Principles

| Principle | Description |
|-----------|-------------|
| **Idempotent** | Repeated execution has no side effects; already-installed components are skipped, existing configs are not overwritten |
| **Cross-platform** | Automatically detects platform via `uname -s` + `uname -m` |
| **Resumable** | Each step is independent; after a failure, re-execution resumes from the breakpoint |
| **Transparent** | Each step outputs a description of the operation; nothing that might affect the user's environment is executed silently |

### 5.3 Script Flow

```
┌──────────────┐
│ detect_platform │  uname -s / uname -m
└──────┬───────┘
       ▼
┌──────────────┐
│ check_rust   │  rustc --version (optional, for source builds)
└──────┬───────┘
       ▼
┌──────────────┐
│ install_bin  │  Download pre-compiled binary or cargo build --release
└──────┬───────┘
       ▼ FAIL → output diagnostics (exit 20)
┌──────────────┐
│ init_config   │  enva init (skip if already exists)
└──────┬───────┘
       ▼
┌──────────────┐
│ install_hooks │  enva hook install (idempotent)
└──────┬───────┘
       ▼
┌──────────────┐
│ run_self_test │  enva self-test
└──────┬───────┘
       ▼ PASS → exit 0 / FAIL → exit 30
```

### 5.4 Exit Code Specification

| Exit Code | Meaning |
|-----------|---------|
| `0` | Installation successful, self-test passed |
| `10` | Unsupported platform or architecture |
| `20` | Binary download or build failed |
| `21` | Configuration initialization failed (permission issues, etc.) |
| `22` | Shell hook installation failed |
| `30` | self-test failed (incomplete installation) |

### 5.5 Script Pseudocode

```bash
#!/usr/bin/env bash
set -euo pipefail

ENVA_DIR="$HOME/.enva"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# ── Platform Detection ─────────────────────────────
detect_platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Linux)  PLATFORM="linux" ;;
        Darwin) PLATFORM="macos" ;;
        *)      echo "ERROR: Unsupported OS: $os"; exit 10 ;;
    esac
    case "$arch" in
        x86_64)          ARCH="x86_64" ;;
        arm64|aarch64)   ARCH="aarch64" ;;
        *)               echo "ERROR: Unsupported arch: $arch"; exit 10 ;;
    esac
    echo "Platform: $PLATFORM/$ARCH"
}

# ── Binary Installation ───────────────────────────
install_binary() {
    if command -v enva &>/dev/null; then
        echo "enva already installed: $(enva --version)"
        return 0
    fi

    if command -v cargo &>/dev/null; then
        echo "Rust toolchain found, building from source..."
        cargo build --release || { echo "ERROR: cargo build failed"; exit 20; }
        mkdir -p "$INSTALL_DIR"
        cp target/release/enva "$INSTALL_DIR/"
    else
        echo "Downloading pre-compiled binary for $PLATFORM/$ARCH..."
        local url="https://github.com/YoRHa-Agents/EnvA/releases/latest/download/enva-${PLATFORM}-${ARCH}"
        curl -fsSL "$url" -o "$INSTALL_DIR/enva" || { echo "ERROR: download failed"; exit 20; }
        chmod +x "$INSTALL_DIR/enva"
    fi
    echo "Installed: $INSTALL_DIR/enva"
}

# ── Configuration Initialization (idempotent) ─────
init_config() {
    if [ -d "$ENVA_DIR" ] && [ -f "$ENVA_DIR/config.yaml" ]; then
        echo "Config already exists at $ENVA_DIR, skipping init."
        return 0
    fi
    enva init || { echo "ERROR: config init failed"; exit 21; }
}

# ── Shell Hook Installation (idempotent) ──────────
install_hooks() {
    enva hook install || { echo "ERROR: hook install failed"; exit 22; }
}

# ── Self-test ─────────────────────────────────────
run_self_test() {
    echo "Running self-test..."
    enva self-test || { echo "ERROR: self-test failed"; exit 30; }
    echo "Installation complete."
}

# ── Main ──────────────────────────────────────────
detect_platform
install_binary
init_config
install_hooks
run_self_test
```

### 5.6 Idempotency Guarantees

| Step | Idempotency Mechanism |
|------|----------------------|
| Platform detection | Read-only checks, no system modification |
| Binary installation | Checks whether `enva` is already on PATH; skips if present |
| `enva init` | Checks whether `~/.enva/config.yaml` already exists; skips if present |
| `enva hook install` | `grep -q` checks whether the source line already exists in the rc file; skips if present |
| `enva self-test` | Read-only verification, no state modification |

---

## 6. CI Matrix Design

### 6.1 Design Rationale

Enva is a pure Rust application. The CI pipeline builds and tests on both target platforms:

```
rust-build (ubuntu-latest) → test + build release binary
rust-build (macos-14)      → test + build release binary
```

### 6.2 Build and Test Job

```yaml
  rust:
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-14]
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Cache cargo registry
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

      - name: Run tests
        run: cargo test --workspace --verbose

      - name: Build release binary
        run: cargo build --release

      - name: CLI smoke test
        run: |
          ./target/release/enva --help
          ./target/release/enva self-test

      - name: Upload binary artifact
        uses: actions/upload-artifact@v4
        with:
          name: enva-${{ matrix.os }}
          path: target/release/enva
          retention-days: 7
```

### 6.3 Matrix Coverage

| Job | OS | Arch | Description |
|-----|-----|------|-------------|
| `rust` | `ubuntu-latest` | x86_64 | Build + test + release binary for Linux |
| `rust` | `macos-14` | aarch64 (M1) | Build + test + release binary for macOS |

**Total: 2 matrix combinations**.

### 6.4 macos-14 Runner Notes

- `macos-14` is the **Apple Silicon (M1)** runner provided by GitHub Actions
- Pre-installed with Homebrew and Xcode CLI Tools
- The `dtolnay/rust-toolchain` action supports Rust stable on aarch64 macOS

---

## Appendix A: Platform Differences Summary

| Dimension | Linux x86_64 | macOS aarch64 |
|-----------|-------------|---------------|
| Package manager | apt / dnf / pacman | Homebrew |
| Default shell | bash | zsh (Catalina+) |
| Config directory | `~/.enva/` | `~/.enva/` (unified) |
| CI runner | `ubuntu-latest` | `macos-14` |
| Rust target | `x86_64-unknown-linux-gnu` | `aarch64-apple-darwin` |
| End user needs Rust? | No (pre-compiled binary) | No (pre-compiled binary) |

## Appendix B: Cross-References

| Referenced Document | Related Section |
|---------------------|-----------------|
| [Technology Decision](./tech_decision.md) | Architecture decisions — the premise of this document |
| [Configuration Reference](./config_reference.md) | `~/.enva/config.yaml` field definitions — config directories |
| [Interface Specification](./api_spec.md) | CLI command definitions — commands referenced in installation steps |
| [Vault Format Specification](./vault_spec.md) | vault.json format — files referenced in directory structure |

---

*Document version: 3.0 | Updated: 2026-03-28 | Architecture: Pure Rust CLI (enva-core lib + enva binary)*
