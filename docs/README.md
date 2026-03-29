# Enva

> Encrypted environment variable manager with per-app injection.
> 基于加密 vault 的环境变量管理工具，支持按应用粒度注入。

## Quick Start / 快速开始

### Install / 安装

```bash
curl -fsSL https://raw.githubusercontent.com/YoRHa-Agents/EnvA/main/scripts/install.sh | bash
```

Or build from source:

```bash
cargo build --release
cp target/release/enva ~/.local/bin/
```

### Create a vault / 创建 vault

```bash
enva vault init --vault ~/.enva/vault.json
```

### Add secrets / 添加密钥

```bash
enva vault set prod-db \
  --key DATABASE_URL \
  --value "postgres://user:pass@db.example.com:5432/mydb"
```

### Assign to an app / 分配到应用

```bash
enva vault assign prod-db --app backend
```

### Inject into app / 注入到应用

```bash
enva backend -- python app.py
```

The subprocess receives `DATABASE_URL` in its environment without the secret
ever touching disk or shell history.

子进程在环境变量中接收 `DATABASE_URL`，密钥不会出现在磁盘文件或 shell 历史记录中。

---

## Documentation / 文档

| Document | 文档 | Path |
|----------|------|------|
| User Guide (EN) | 用户指南 (中文) | [design/en/userguide.md](design/en/userguide.md) / [design/zh/userguide.md](design/zh/userguide.md) |
| Architecture | 架构设计 | [design/en/architecture.md](design/en/architecture.md) |
| API Spec | 接口规范 | [design/en/api_spec.md](design/en/api_spec.md) |
| Vault Format | Vault 格式 | [design/en/vault_spec.md](design/en/vault_spec.md) |
| Config Reference | 配置参考 | [design/en/config_reference.md](design/en/config_reference.md) |
| Deployment | 部署方案 | [design/en/deployment.md](design/en/deployment.md) |
| Tech Decision | 技术选型 | [design/en/tech_decision.md](design/en/tech_decision.md) |
| Agent Index | Agent 参考 | [agent-index.md](agent-index.md) |
| Web Demo | 网页演示 | [design/demo/index.html](design/demo/index.html) |

---

## Key Concepts / 核心概念

### Alias (别名)

A unique, human-readable identifier for each secret in the vault. Aliases use
lowercase letters, digits, and hyphens (e.g. `prod-db`, `jwt-secret`).

每个密钥在 vault 中的唯一标识符。别名使用小写字母、数字和连字符。

### Key (环境变量名)

The environment variable name injected at runtime (e.g. `DATABASE_URL`).

运行时注入的环境变量名。

### Apps (应用)

Named application profiles that reference secrets by alias. Multiple apps can
share the same secret without duplication.

命名的应用配置，通过别名引用密钥。多个应用可共享同一密钥。

### Overrides (注入覆盖)

Per-app mapping of `alias → custom env var name`.

按应用维度的 `别名 → 自定义变量名` 映射。

### Vault Format v2.0

A single encrypted JSON file with three sections: `_meta` (KDF params, salt,
HMAC), `secrets` (alias-keyed encrypted values), `apps` (references + overrides).

```json
{
  "_meta": { "format_version": "2.0", "kdf": { "algorithm": "argon2id" }, "salt": "...", "hmac": "..." },
  "secrets": { "prod-db": { "key": "DATABASE_URL", "value": "ENC[...]" } },
  "apps": { "backend": { "secrets": ["prod-db"], "overrides": {} } }
}
```

---

## License

MIT
