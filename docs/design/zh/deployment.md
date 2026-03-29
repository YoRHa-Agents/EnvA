# 跨平台部署方案 (Cross-Platform Deployment Design)

> **Summary (EN):** Deployment design for Enva across x86_64 Linux and aarch64 macOS (Apple Silicon). Enva is a pure Rust CLI application compiled into a single static binary. CI produces pre-compiled binaries on `ubuntu-latest` (x86_64) and `macos-14` (aarch64) so end users can download the appropriate binary for their platform — **no Rust toolchain needed**. Development contributors need Rust for `cargo build`. The document covers platform matrix, build and distribution strategy, per-platform installation flows, an idempotent install script, and CI matrix.

---

## 目录

1. [目标平台矩阵](#1-目标平台矩阵)
2. [构建与分发策略](#2-构建与分发策略)
3. [Linux x86_64 安装流程设计](#3-linux-x86_64-安装流程设计)
4. [macOS aarch64 安装流程设计](#4-macos-aarch64-安装流程设计)
5. [安装脚本设计](#5-安装脚本设计)
6. [CI Matrix 设计](#6-ci-matrix-设计)

---

## 1. 目标平台矩阵

| 平台 | 架构 | Rust Target | 状态 | 备注 |
|------|------|-------------|------|------|
| Linux | x86_64 | `x86_64-unknown-linux-gnu` | **主开发平台** | CI 主 runner: `ubuntu-latest` |
| macOS | aarch64 (Apple Silicon) | `aarch64-apple-darwin` | **必须支持** | CI runner: `macos-14` (M1) |

### 关键约束

- **Enva 是纯 Rust CLI 应用**：`enva-core` 库 crate 提供加密操作（AES-256-GCM、Argon2id KDF）和 vault 管理；`enva` 二进制 crate 提供 CLI、Web 服务器和 Shell hooks。
- **单一静态二进制**：`cargo build --release` 生成无运行时依赖的单一二进制文件。
- **最终用户无需 Rust 工具链**：CI 在两个目标平台上预编译二进制，用户下载对应平台的二进制文件即可。
- **开发贡献者需要 Rust 工具链**：本地开发使用 `cargo build` 从源码编译。

---

## 2. 构建与分发策略

### 2.1 构建流程

```bash
cargo build --release
```

Cargo 自动处理：
- Rust 编译（release 优化）
- 静态链接所有依赖
- 平台特定二进制生成

输出二进制位于 `target/release/enva`。

### 2.2 CI 构建矩阵

| CI Runner | Rust Target | 产物 |
|-----------|-------------|------|
| `ubuntu-latest` | `x86_64-unknown-linux-gnu` | `enva-linux-x86_64` |
| `macos-14` | `aarch64-apple-darwin` | `enva-macos-aarch64` |

共计 **2 个二进制产物**（每个平台一个）。

### 2.3 分发渠道

| 渠道 | 适用场景 | 说明 |
|------|---------|------|
| **GitHub Releases** (推荐) | 公开分发 | CI 自动将二进制上传为 Release asset，用户从 Release 页面下载 |
| **安装脚本** | 自动化安装 | `scripts/install-secrets.sh` 检测平台并下载正确的二进制 |
| **源码编译** | 开发者 / 自定义构建 | 有 Rust 工具链的用户执行 `cargo build --release` |

### 2.4 用户安装体验

**最终用户**（无 Rust 环境）：

```bash
curl -fsSL https://raw.githubusercontent.com/YoRHa-Agents/EnvA/main/scripts/install.sh | bash
```

安装脚本自动检测当前平台和架构，下载预编译二进制，安装到 `~/.local/bin/` 或 `/usr/local/bin/`。

**开发贡献者**（需要 Rust 环境）：

```bash
rustup default stable
cargo build --release
# 或直接安装:
cargo install --path crates/enva
```

---

## 3. Linux x86_64 安装流程设计

### 3.1 前置条件

| 条件 | 最低要求 | 检测命令 | 说明 |
|------|---------|---------|------|
| Rust 工具链 | 仅开发者需要 | `rustc --version` | 最终用户通过预编译二进制安装，无需 Rust |
| curl 或 wget | 用于安装脚本 | `command -v curl` | 用于下载二进制 |

### 3.2 安装步骤

```bash
# 选项 A: 安装脚本（推荐最终用户使用）
curl -fsSL https://example.com/install.sh | bash

# 选项 B: 从源码编译（开发者）
cargo build --release
cp target/release/enva ~/.local/bin/

# 步骤 2: 初始化配置目录
enva init
# 自动执行:
#   - 创建 ~/.enva/ 目录
#   - 创建 ~/.enva/config.yaml (默认配置)
#   - 创建 ~/.enva/hooks/ 目录
#   - 生成 enva-hook.bash 和 enva-hook.zsh

# 步骤 3: 安装 Shell hook
enva hook install
# 自动执行:
#   - 检测当前 shell (bash/zsh)
#   - 在 ~/.bashrc 或 ~/.zshrc 末尾追加 source 行
#   - 不会重复添加 (幂等)

# 步骤 4: 验证安装
enva self-test
```

### 3.3 Shell Hook 安装细节 (Linux)

**bash** (Linux 主要 shell):

在 `~/.bashrc` 末尾追加:

```bash
# Enva secrets manager hook
[ -f "$HOME/.enva/hooks/enva-hook.bash" ] && source "$HOME/.enva/hooks/enva-hook.bash"
```

**zsh** (若用户使用 zsh):

在 `~/.zshrc` 末尾追加:

```zsh
# Enva secrets manager hook
[ -f "$HOME/.enva/hooks/enva-hook.zsh" ] && source "$HOME/.enva/hooks/enva-hook.zsh"
```

### 3.4 配置目录结构 (Linux)

```
~/.enva/
├── config.yaml          # 全局配置
├── vault.json           # 默认 vault 文件 (init --vault 后创建)
├── hooks/
│   ├── enva-hook.bash
│   └── enva-hook.zsh
└── audit.log            # 审计日志 (运行时自动创建)
```

---

## 4. macOS aarch64 安装流程设计

### 4.1 前置条件

| 条件 | 最低要求 | 检测命令 | 说明 |
|------|---------|---------|------|
| Rust 工具链 | 仅开发者需要 | `rustc --version` | 最终用户通过预编译二进制安装，无需 Rust |
| curl | 用于安装脚本 | `command -v curl` | macOS 自带 |

### 4.2 安装步骤

```bash
# 选项 A: 安装脚本（推荐最终用户使用）
curl -fsSL https://example.com/install.sh | bash

# 选项 B: 从源码编译（开发者）
cargo build --release
cp target/release/enva /usr/local/bin/

# 步骤 2: 初始化配置目录
enva init
# 自动执行:
#   - 创建 ~/.enva/ 目录 (统一路径，非 ~/Library/Application Support/)
#   - 创建 ~/.enva/config.yaml (默认配置)
#   - 创建 ~/.enva/hooks/ 目录

# 步骤 3: 安装 Shell hook
enva hook install
# 自动执行:
#   - 检测 zsh (macOS 默认 shell)
#   - 在 ~/.zshrc 末尾追加 source 行

# 步骤 4: 验证安装
enva self-test
```

### 4.3 macOS 特殊处理

#### 配置目录路径

**统一使用 `~/.enva/`**，不使用 `~/Library/Application Support/enva/`。

理由:
- 与 Linux 行为一致，降低文档和脚本维护成本
- 开发者更习惯 dotfile 目录
- vault 文件需跨平台同步（如 git），统一路径避免路径映射问题
- `~/Library/Application Support/` 路径含空格，增加脚本复杂度

#### Shell Hook (macOS)

macOS 自 Catalina (10.15) 起默认 shell 为 **zsh**。安装脚本仅处理 zsh:

在 `~/.zshrc` 末尾追加:

```zsh
# Enva secrets manager hook
[ -f "$HOME/.enva/hooks/enva-hook.zsh" ] && source "$HOME/.enva/hooks/enva-hook.zsh"
```

### 4.4 配置目录结构 (macOS)

与 Linux 完全一致:

```
~/.enva/
├── config.yaml
├── vault.json
├── hooks/
│   └── enva-hook.zsh
└── audit.log
```

---

## 5. 安装脚本设计

### 5.1 脚本位置

`scripts/install-secrets.sh`

### 5.2 设计原则

| 原则 | 说明 |
|------|------|
| **幂等** | 重复执行无副作用；已安装组件跳过，已存在配置不覆盖 |
| **跨平台** | 通过 `uname -s` + `uname -m` 自动检测平台 |
| **可中断** | 每步独立，失败后可从断点重新执行 |
| **透明** | 每步输出操作说明，不静默执行可能影响用户环境的操作 |

### 5.3 脚本流程

```
┌──────────────┐
│ detect_platform │  uname -s / uname -m
└──────┬───────┘
       ▼
┌──────────────┐
│ check_rust   │  rustc --version (可选, 源码编译用)
└──────┬───────┘
       ▼
┌──────────────┐
│ install_bin  │  下载预编译二进制或 cargo build --release
└──────┬───────┘
       ▼ FAIL → 输出诊断信息 (exit 20)
┌──────────────┐
│ init_config   │  enva init (如已存在则跳过)
└──────┬───────┘
       ▼
┌──────────────┐
│ install_hooks │  enva hook install (幂等)
└──────┬───────┘
       ▼
┌──────────────┐
│ run_self_test │  enva self-test
└──────┬───────┘
       ▼ PASS → exit 0 / FAIL → exit 30
```

### 5.4 退出码规范

| 退出码 | 含义 |
|--------|------|
| `0` | 安装成功，self-test 通过 |
| `10` | 不支持的平台或架构 |
| `20` | 二进制下载或编译失败 |
| `21` | 配置初始化失败 (权限问题等) |
| `22` | Shell hook 安装失败 |
| `30` | self-test 失败 (安装不完整) |

### 5.5 脚本伪代码

```bash
#!/usr/bin/env bash
set -euo pipefail

ENVA_DIR="$HOME/.enva"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# ── 平台检测 ──────────────────────────────────────
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

# ── 二进制安装 ─────────────────────────────────────
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

# ── 配置初始化 (幂等) ─────────────────────────────
init_config() {
    if [ -d "$ENVA_DIR" ] && [ -f "$ENVA_DIR/config.yaml" ]; then
        echo "Config already exists at $ENVA_DIR, skipping init."
        return 0
    fi
    enva init || { echo "ERROR: config init failed"; exit 21; }
}

# ── Shell Hook 安装 (幂等) ────────────────────────
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

### 5.6 幂等保证

| 步骤 | 幂等机制 |
|------|---------|
| 平台检测 | 只读检测，不修改系统 |
| 二进制安装 | 检测 `enva` 是否已在 PATH 中；已有则跳过 |
| `enva init` | 检测 `~/.enva/config.yaml` 是否已存在，存在则跳过 |
| `enva hook install` | `grep -q` 检测 rc 文件中是否已有 source 行，已有则跳过 |
| `enva self-test` | 只读验证，不修改任何状态 |

---

## 6. CI Matrix 设计

### 6.1 设计思路

Enva 是纯 Rust 应用。CI 流水线在两个目标平台上构建和测试：

```
rust-build (ubuntu-latest) → 测试 + 构建 release 二进制
rust-build (macos-14)      → 测试 + 构建 release 二进制
```

### 6.2 构建和测试 Job

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

### 6.3 Matrix 覆盖说明

| Job | OS | Arch | 说明 |
|-----|-----|------|------|
| `rust` | `ubuntu-latest` | x86_64 | 构建 + 测试 + Linux release 二进制 |
| `rust` | `macos-14` | aarch64 (M1) | 构建 + 测试 + macOS release 二进制 |

**共计 2 个 matrix 组合**。

### 6.4 macos-14 Runner 注意事项

- `macos-14` 是 GitHub Actions 提供的 **Apple Silicon (M1)** runner
- 预装 Homebrew、Xcode CLI Tools
- `dtolnay/rust-toolchain` action 支持 aarch64 macOS 上的 Rust stable

---

## 附录 A: 平台差异汇总

| 维度 | Linux x86_64 | macOS aarch64 |
|------|-------------|---------------|
| 包管理器 | apt / dnf / pacman | Homebrew |
| 默认 shell | bash | zsh (Catalina+) |
| 配置目录 | `~/.enva/` | `~/.enva/` (统一) |
| CI runner | `ubuntu-latest` | `macos-14` |
| Rust target | `x86_64-unknown-linux-gnu` | `aarch64-apple-darwin` |
| 最终用户需 Rust? | 否 (预编译二进制) | 否 (预编译二进制) |

## 附录 B: 交叉引用

| 引用文档 | 关联章节 |
|---------|---------|
| [技术选型决策](./tech_decision.md) | 架构决策 — 本文档的前提 |
| [配置参考](./config_reference.md) | `~/.enva/config.yaml` 字段定义 — 配置目录 |
| [接口规范](./api_spec.md) | CLI 命令定义 — 安装步骤中引用的命令 |
| [Vault 格式规范](./vault_spec.md) | vault.json 格式 — 目录结构中引用的文件 |

---

*文档版本: 3.0 | 更新时间: 2026-03-28 | 架构: 纯 Rust CLI (enva-core lib + enva binary)*
