# Enva -- 用户指南

> 安装、配置和使用 Enva CLI、Shell 钩子及 Web 管理界面的完整指南。

---

## 目录

1. [安装](#1-安装)
2. [快速上手](#2-快速上手)
3. [核心概念](#3-核心概念)
4. [CLI 命令参考](#4-cli-命令参考)
5. [配置](#5-配置)
6. [Shell 钩子](#6-shell-钩子)
7. [Web 管理界面](#7-web-管理界面)
8. [安全性](#8-安全性)
9. [跨平台说明](#9-跨平台说明)
10. [常见问题排查](#10-常见问题排查)

---

## 1. 安装

### 前置条件

- Linux x86_64 或 macOS aarch64 (Apple Silicon)
- 从源码编译需要: Rust 工具链 (stable)

### 通过安装脚本安装

```bash
curl -fsSL https://example.com/install.sh | bash
```

安装脚本自动检测平台并下载预编译二进制。

### 从源码编译

```bash
cargo build --release
cp target/release/enva ~/.local/bin/
```

### 验证安装

```bash
enva self-test
```

预期输出：

```
  [PASS] Crypto backend (Rust)
  [PASS] Encrypt/decrypt round-trip
  [PASS] CLI framework
```

---

## 2. 快速上手

### 第一步：创建 vault

```bash
enva init --vault ~/.enva/vault.json
```

系统会要求输入并确认主密码。vault 文件将以空的密钥池创建，Argon2id KDF 参数嵌入在元数据中。

### 第二步：添加密钥

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

每次 `set` 命令都会用 AES-256-GCM 加密值、以指定别名存入 vault，并更新文件的 HMAC。

### 第三步：创建应用并分配密钥

```bash
enva assign prod-db --app backend --vault ~/.enva/vault.json
enva assign jwt-secret --app backend --vault ~/.enva/vault.json
enva assign shared-sentry --app backend --vault ~/.enva/vault.json
```

### 第四步：注入运行

```bash
enva run --app backend --vault ~/.enva/vault.json -- ./my-app
```

子进程会收到三个环境变量：`DATABASE_URL`、`JWT_SECRET` 和 `SENTRY_DSN`。密钥不会出现在 shell 历史记录中。

### 第五步：检查确认

```bash
enva list --vault ~/.enva/vault.json
```

---

## 3. 核心概念

### 别名（Alias）与键（Key）

每个密钥有两个名称：

- **别名（Alias）**：vault 中的唯一标识符。例如：`prod-db`、`staging-redis`。
- **键（Key）**：运行时注入的环境变量名。例如：`DATABASE_URL`、`JWT_SECRET`。

### 密钥池（Secrets Pool）

Vault 维护一个以别名为键的扁平密钥池。密钥不属于任何应用，独立存在。

### 应用引用（App References）

每个应用持有别名引用列表和覆盖映射。

### 注入覆盖（Overrides）

当应用需要以不同名称注入密钥时使用覆盖映射。

---

## 4. CLI 命令参考

所有命令接受以下全局选项：

| 选项 | 环境变量 | 说明 |
|------|---------|------|
| `--vault PATH` | `ENVA_VAULT_PATH` | Vault 文件路径 |
| `--config PATH` | `ENVA_CONFIG` | 配置文件路径 |
| `--password-stdin` | -- | 从标准输入读取密码 |
| `--quiet` / `-q` | -- | 抑制非必要输出 |
| `--verbose` / `-v` | -- | 启用详细输出 |

### `enva init` / `enva set` / `enva get` / `enva list` / `enva delete`

基本 vault 操作命令。

### `enva edit`

编辑已有密钥的单个字段，不影响其他未指定字段。适用于迁移场景——将 vault 迁移到新设备后仅更新连接地址等字段。

```bash
enva edit <ALIAS> [--key <NEW_KEY>] [--value <NEW_VALUE>] [--description <DESC>] [--tags <TAGS>]
```

至少需要提供一个标志。未指定的字段保持不变。

### `enva assign` / `enva unassign`

应用密钥分配命令。

### `enva run`

以注入密钥的方式运行子进程。

```bash
enva run --app backend --vault vault.json -- ./my-server
```

### `enva vault export` / `enva vault import`

导出/导入密钥。

```bash
enva vault export --app backend --vault vault.json --format json
enva vault import --from .env.production --app backend --vault vault.json
enva vault import --from bundle.yaml --vault vault.json
```

### `enva serve`

启动 Web 管理服务器。

### `enva self-test`

验证安装完整性。

---

## 5. 配置

Enva 使用五层配置合并机制：

```
内置默认值  <  全局配置  <  项目配置  <  环境覆盖  <  CLI 参数
```

### 全局配置（`~/.enva/config.yaml`）

用户级设置，跨项目共享。

### 项目配置（`.enva.yaml`）

项目级配置。可以安全提交到版本控制。

### CLI 参数和环境变量

| 环境变量 | 等价 CLI 参数 | 说明 |
|---------|-------------|------|
| `ENVA_VAULT_PATH` | `--vault` | Vault 文件路径 |
| `ENVA_CONFIG` | `--config` | 配置文件路径 |
| `ENVA_APP` | 无 | 默认应用名 |

---

## 6. Shell 钩子

Shell 钩子实现了当你 `cd` 进入包含 `.enva.yaml` 的项目目录时自动注入密钥。

### Bash 配置

在 `~/.bashrc` 中添加：

```bash
source ~/.enva/hooks/enva-hook.bash
```

### Zsh 配置

在 `~/.zshrc` 中添加：

```zsh
source ~/.enva/hooks/enva-hook.zsh
```

---

## 7. Web 管理界面

```bash
enva serve --vault ~/.enva/vault.json --port 8080
```

在浏览器中打开 `http://127.0.0.1:8080`。

---

## 8. 安全性

### 内存安全

Enva 完全由 Rust 实现。密钥在释放时通过 `zeroize` crate 清零。`secrecy::SecretString` 封装所有敏感值。

### 密钥派生（Argon2id）

密码不会被存储。Vault 使用 Argon2id（RFC 9106）从密码 + 32 字节随机 salt 派生 64 字节主密钥。

---

## 9. 跨平台说明

| 平台 | 状态 |
|------|------|
| Linux x86_64 | 预编译二进制 |
| macOS aarch64 | 预编译二进制 |
| 其他 | 从源码编译 `cargo build --release` |

---

## 10. 常见问题排查

**"Authentication failed"** — Vault 密码错误。

**"HMAC verification failed"** — Vault 文件在 Enva 之外被修改过。

```bash
enva self-test
```

---

*文档版本: 2.0 | 更新日期: 2026-03-28*
*参阅: [架构设计](architecture.md) · [Vault 格式规范](vault_spec.md) · [配置参考](config_reference.md)*
