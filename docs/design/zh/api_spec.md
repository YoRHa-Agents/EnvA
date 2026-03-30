# 接口规范文档 — Secrets Manager (Interface Specification)

> **Summary (EN):** Complete interface specification for the Secrets Manager covering three surface areas: (1) **CLI** — a Click-based command tree with 10 subcommands (`init`, `set`, `get`, `list`, `delete`, `run`, `export`, `import`, `serve`, `self-test`), global options, and structured exit codes; (2) **Shell hooks** — Bash (`PROMPT_COMMAND`) and Zsh (native `precmd`/`chpwd`) hooks for automatic secret injection with history protection and password caching; (3) **Web API** — a RESTful API with JWT authentication, CRUD endpoints for secrets and apps, import/export, rate limiting, and full error schema. All CLI output formats, Shell hook lifecycle events, and Web API request/response JSON schemas are defined to a level of detail sufficient for direct implementation.

> **交叉引用 (Cross-references):**
> - 加密方案与 vault 格式 → `secrets_manager_vault_spec.md`（待编写）
> - 配置体系（五层配置、字段定义） → `secrets_manager_config_reference.md`（待编写）
> - 技术选型（纯 Rust + clap） → [`tech_decision.md`](./tech_decision.md)
> - 调研报告 → [`secrets_manager_research.md`](./secrets_manager_research.md)
> - 架构设计 → `secrets_manager_design.md`（待编写）

---

## 目录

- [第一部分：CLI 接口规范](#第一部分cli-接口规范)
  - [1.1 命令树总览](#11-命令树总览)
  - [1.2 全局选项](#12-全局选项)
  - [1.3 退出码规范](#13-退出码规范)
  - [1.4 各子命令详细规范](#14-各子命令详细规范)
- [第二部分：Shell Hook 规范](#第二部分shell-hook-规范)
  - [2.1 Bash Hook](#21-bash-hook-secrets-hookbash)
  - [2.2 Zsh Hook](#22-zsh-hook-secrets-hookzsh)
  - [2.3 注入生命周期](#23-注入生命周期)
  - [2.4 配置文件自动发现](#24-配置文件自动发现)
- [第三部分：Web API 规范](#第三部分web-api-规范)
  - [3.1 总览](#31-总览)
  - [3.2 认证](#32-认证)
  - [3.3 Secrets CRUD](#33-secrets-crud)
  - [3.4 导入导出](#34-导入导出)
  - [3.5 App 管理](#35-app-管理)
  - [3.6 错误响应](#36-错误响应)

---

## 第一部分：CLI 接口规范

> **安装说明**：`enva` CLI 是独立的 Rust 二进制文件。通过 `cargo install enva` 或安装脚本（`scripts/install.sh`）安装。无需任何外部运行时依赖。

### 1.1 命令树总览

CLI 基于 Click 框架（`click>=8`），入口为 `secrets` 命令组。

```
secrets
├── init --vault PATH                                              # 创建新 vault（交互式密码）
├── set ALIAS --key ENV_NAME --value VALUE --vault PATH            # 在密钥池中添加/更新 secret
├── get ALIAS --vault PATH                                         # 按别名解密取值
├── list [--app NAME] --vault PATH                                 # 列出 secrets（按 app 过滤）
├── delete ALIAS --vault PATH                                      # 从密钥池删除
├── assign ALIAS --app NAME [--as CUSTOM_KEY] --vault PATH         # 将 secret 分配给 app
├── unassign ALIAS --app NAME --vault PATH                         # 从 app 移除 secret 引用
├── run --app NAME --vault PATH -- CMD [ARGS]                      # 解析别名后注入子进程环境
├── export --app NAME --vault PATH [--format]                      # 导出 app 解析后的环境变量
├── import --from FILE --app NAME --vault PATH                     # 从 .env 文件导入（自动生成别名）
├── serve --port PORT --vault PATH [--host]                        # 启动 Web 管理服务
└── self-test                                                      # 验证安装完整性
```

### 1.2 全局选项

以下选项在所有子命令上可用（在命令组级别定义）：

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--vault PATH` | `click.Path` | 配置文件中 `defaults.vault_path`，最终 fallback `~/.secrets/vault.json` | vault 文件路径。支持 `~` 展开。 |
| `--config PATH` | `click.Path` | `~/.secrets/config.yaml` | 全局配置文件路径。 |
| `--password-stdin` | `bool` (flag) | `False` | 从 stdin 读取密码（用于脚本/CI），不使用交互式提示。 |
| `--quiet` / `-q` | `bool` (flag) | `False` | 静默模式——仅输出数据到 stdout，不输出状态消息到 stderr。 |
| `--verbose` / `-v` | `bool` (flag) | `False` | 详细模式——输出调试信息到 stderr。与 `--quiet` 互斥。 |

**互斥约束**: `--quiet` 和 `--verbose` 不可同时使用，Click 以 `cls=MutuallyExclusive` 或回调校验实现。

**密码获取优先级**:
1. `--password-stdin` → 从 stdin 读取一行
2. 环境变量 `ENVA_PASSWORD` → 直接使用
3. 内存缓存（Shell hook 场景） → 使用已缓存的密码
4. 交互式提示 → `click.prompt("Vault password", hide_input=True)`

### 1.3 退出码规范

| 退出码 | 常量名 | 含义 | 触发场景 |
|--------|--------|------|---------|
| `0` | `EXIT_SUCCESS` | 成功 | 所有正常完成的操作 |
| `1` | `EXIT_ERROR` | 一般错误 | IO 错误、vault 格式损坏、参数校验失败、未知异常 |
| `2` | `EXIT_AUTH_FAILED` | 认证失败 | 密码错误（HMAC 校验不通过）、vault 解密失败 |
| `3` | `EXIT_KEY_NOT_FOUND` | Key 不存在 | `get`/`delete` 指定的 key 在 vault 中不存在 |

**输出约定**:
- **stdout**: 仅输出命令结果数据（value、列表、export 语句等）
- **stderr**: 状态消息（`✓ Key stored`）、错误消息（`Error: ...`）、调试日志（`--verbose`）
- `--quiet` 模式下 stderr 不输出状态消息，仅输出错误

### 1.4 各子命令详细规范

---

#### 1.4.1 `secrets init`

**功能**: 创建新 vault 文件。交互式输入并确认密码，生成 KDF salt，初始化空 vault 结构。

**签名**:

```
secrets init [--vault PATH]
```

| 参数/选项 | 类型 | 必填 | 默认值 | 说明 |
|-----------|------|------|--------|------|
| `--vault` | `click.Path` | 否 | 全局默认 | vault 文件输出路径 |

**行为**:
1. 如果 vault 文件已存在 → 退出码 `1`，stderr 输出 `Error: Vault already exists at {path}. Use --force to overwrite.`
2. 交互式提示密码（二次确认）：`New vault password:` / `Confirm password:`
3. 生成 32 字节 salt（`os.urandom(32)`）
4. 通过 Argon2id 派生 256-bit 密钥
5. 写入初始 vault JSON 结构（含 `_meta`，空 `global`/`apps`）
6. 计算并写入 HMAC

**stdout**: 无

**stderr**（正常）:

```
✓ Vault created at /home/user/.secrets/vault.json
  KDF: argon2id (memory=64MB, iterations=3, parallelism=4)
```

**stderr**（已存在）:

```
Error: Vault already exists at /home/user/.secrets/vault.json
```

**示例**:

```bash
# 交互式创建
secrets init --vault ./my-vault.json

# CI 场景
echo "my-password" | secrets init --vault ./vault.json --password-stdin
```

---

#### 1.4.2 `secrets set`

**功能**: 在全局密钥池中以别名（alias）添加或更新一个 secret。如果 alias 已存在则覆盖。

**签名**:

```
secrets set ALIAS --key ENV_NAME --value VALUE [--description DESC] [--tags tag1,tag2] [--vault PATH]
```

| 参数/选项 | 类型 | 必填 | 默认值 | 说明 |
|-----------|------|------|--------|------|
| `ALIAS` | `str` (argument) | 是 | — | 密钥别名（唯一标识）。校验规则：`^[a-z0-9][a-z0-9-]*$`，最大 128 字符。 |
| `--key` | `str` | 是 | — | 注入时的环境变量名。校验规则：`^[A-Za-z_][A-Za-z0-9_]*$`，最大 128 字符。 |
| `--value` | `str` | 是 | — | 密钥值。如果为 `-`，从 stdin 读取。最大 64KB。 |
| `--description` | `str` | 否 | `""` | 可选描述。 |
| `--tags` | `str` | 否 | `""` | 逗号分隔的标签列表。 |
| `--vault` | `click.Path` | 否 | 全局默认 | vault 文件路径 |

**行为**:
1. 读取并解密 vault（密码获取按 §1.2 优先级链）
2. HMAC 完整性校验
3. AES-256-GCM 加密 VALUE（独立 12-byte nonce）
4. 存入密钥池 `secrets[ALIAS]`，包含 `key`, `value`, `description`, `tags`
5. 更新 `_meta.updated_at`，重算 HMAC
6. 原子写回 vault（write-to-temp + rename）

**stdout**: 无

**stderr**（正常）:

```
✓ Set alias "prod-db" (key=DATABASE_URL)
```

**stderr**（更新已存在 alias）:

```
✓ Updated alias "prod-db" (key=DATABASE_URL)
```

**示例**:

```bash
# 添加新 secret
secrets set prod-db --key DATABASE_URL --value "postgres://..." --vault ./vault.json

# 带描述和标签
secrets set jwt-secret --key JWT_SECRET --value "abc" --description "JWT signing key" --tags auth,backend --vault ./vault.json

# 从 stdin 读取 value（适合多行或含特殊字符的值）
echo "long-secret-value" | secrets set my-secret --key MY_SECRET --value - --vault ./vault.json
```

---

#### 1.4.3 `secrets edit`

**用途**：编辑已有密钥的单个字段，未指定的字段保持不变。适用于迁移场景——将 vault 迁移到新设备后仅更新连接地址等字段。

**签名**：

```
secrets edit ALIAS [--key KEY] [--value VALUE] [--description DESC] [--tags TAGS]
```

| 参数/选项 | 类型 | 必填 | 默认值 | 说明 |
|-----------|------|------|--------|------|
| `ALIAS` | `str` (参数) | 是 | — | 要编辑的密钥别名 |
| `--key` | `str` | 否 | 不变 | 新的环境变量名 |
| `--value` | `str` | 否 | 不变 | 新的密钥值 |
| `--description` | `str` | 否 | 不变 | 新的描述 |
| `--tags` | `str` | 否 | 不变 | 逗号分隔的标签（替换已有） |

**行为**：
1. 至少需要提供一个可选标志，否则报错退出
2. 读取并解密 vault，验证 HMAC
3. 查找别名——未找到则退出码 `3`
4. 对每个提供的标志更新对应字段；未指定的字段保持不变
5. 如果提供了 `--value`，使用 AES-256-GCM 重新加密
6. 更新 `updated_at` 时间戳；保留 `created_at`
7. 重新计算 HMAC 并保存

**stdout**（非安静模式）：`Updated <ALIAS> (key, value, ...)` 列出更改的字段

---

#### 1.4.4 `secrets get`

**功能**: 按别名解密并输出 secret 的 value。

**签名**:

```
secrets get ALIAS [--vault PATH]
```

| 参数/选项 | 类型 | 必填 | 默认值 | 说明 |
|-----------|------|------|--------|------|
| `ALIAS` | `str` (argument) | 是 | — | 密钥别名 |
| `--vault` | `click.Path` | 否 | 全局默认 | vault 文件路径 |

**行为**:
1. 读取并解密 vault
2. HMAC 完整性校验
3. 在密钥池中查找 alias
4. AES-256-GCM 解密值
5. 输出明文到 stdout（不含换行后缀，除非值本身包含）

**Alias 不存在时**: 退出码 `3`，stderr 输出 `Error: Alias "ALIAS" not found`

**stdout**: 纯明文值，无引号，无换行后缀

```
sk-abc123
```

**示例**:

```bash
# 按别名获取
secrets get prod-db --vault ./vault.json

# 管道使用
DB_URL=$(secrets get prod-db --vault ./vault.json)
```

---

#### 1.4.4 `secrets list`

**功能**: 列出密钥池中的 secrets（不暴露 value）。可按 app 过滤。

**签名**:

```
secrets list [--app NAME] [--vault PATH]
```

| 参数/选项 | 类型 | 必填 | 默认值 | 说明 |
|-----------|------|------|--------|------|
| `--app` | `str` | 否 | `None`（列出所有） | 如指定，仅列出该 app 引用的 secrets；未指定则列出密钥池全部。 |
| `--vault` | `click.Path` | 否 | 全局默认 | vault 文件路径 |

**stdout 格式**（不指定 `--app`，表格式）:

```
Alias           Key              App(s)              Updated
prod-db         DATABASE_URL     backend              2026-03-27
jwt-secret      JWT_SECRET       backend, auth        2026-03-26
shared-sentry   SENTRY_DSN       backend, frontend    2026-03-25
stripe-key      STRIPE_KEY       frontend             2026-03-24
redis-cache     REDIS_URL        worker, backend      2026-03-24
```

**stdout 格式**（指定 `--app backend`）:

```
Alias           Injected As      Updated
prod-db         DB_URL           2026-03-27       (override)
jwt-secret      JWT_SECRET       2026-03-26
shared-sentry   SENTRY_DSN       2026-03-25
```

**空 vault**: 不输出任何内容，退出码 `0`。

**示例**:

```bash
# 列出密钥池全部
secrets list --vault ./vault.json

# 仅某 app 引用的 secrets
secrets list --app backend --vault ./vault.json

# 统计 secret 数量
secrets list --vault ./vault.json | tail -n +2 | wc -l
```

---

#### 1.4.5 `secrets delete`

**功能**: 从密钥池中删除指定 alias 的 secret，同时移除所有 app 对该 alias 的引用。

**签名**:

```
secrets delete ALIAS [--vault PATH]
```

| 参数/选项 | 类型 | 必填 | 默认值 | 说明 |
|-----------|------|------|--------|------|
| `ALIAS` | `str` (argument) | 是 | — | 要删除的密钥别名 |
| `--vault` | `click.Path` | 否 | 全局默认 | vault 文件路径 |

**Alias 不存在时**: 退出码 `3`，stderr 输出 `Error: Alias "ALIAS" not found`

**stdout**: 无

**stderr**（正常）:

```
✓ Deleted alias "prod-db" (was referenced by: backend)
```

**示例**:

```bash
secrets delete prod-db --vault ./vault.json
secrets delete jwt-secret --vault ./vault.json
```

---

#### 1.4.5b `secrets assign`

**功能**: 将密钥池中的一个 secret 分配给指定 app，可选覆盖注入环境变量名。

**签名**:

```
secrets assign ALIAS --app NAME [--as CUSTOM_KEY] [--vault PATH]
```

| 参数/选项 | 类型 | 必填 | 默认值 | 说明 |
|-----------|------|------|--------|------|
| `ALIAS` | `str` (argument) | 是 | — | 密钥别名 |
| `--app` | `str` | 是 | — | 目标应用名称 |
| `--as` | `str` | 否 | `None` | 覆盖注入时的环境变量名 |
| `--vault` | `click.Path` | 否 | 全局默认 | vault 文件路径 |

**stdout**: 无

**stderr**（正常）:

```
✓ Assigned "prod-db" to app "backend" (injected as DB_URL)
```

**示例**:

```bash
# 直接分配（使用 secret 默认 key 名注入）
secrets assign jwt-secret --app backend --vault ./vault.json

# 分配并覆盖注入 key 名
secrets assign prod-db --app backend --as DB_URL --vault ./vault.json
```

---

#### 1.4.5c `secrets unassign`

**功能**: 从指定 app 中移除对某 secret 的引用（不删除密钥池中的 secret）。

**签名**:

```
secrets unassign ALIAS --app NAME [--vault PATH]
```

| 参数/选项 | 类型 | 必填 | 默认值 | 说明 |
|-----------|------|------|--------|------|
| `ALIAS` | `str` (argument) | 是 | — | 密钥别名 |
| `--app` | `str` | 是 | — | 应用名称 |
| `--vault` | `click.Path` | 否 | 全局默认 | vault 文件路径 |

**stdout**: 无

**stderr**（正常）:

```
✓ Unassigned "prod-db" from app "backend"
```

**示例**:

```bash
secrets unassign prod-db --app backend --vault ./vault.json
```

---

#### 1.4.6 `secrets run`

**功能**: 解析指定 app 引用的 aliases，解密 secret 值并以环境变量形式注入子进程执行指定命令。

**签名**:

```
secrets run --app NAME [--vault PATH] -- COMMAND [ARGS...]
```

| 参数/选项 | 类型 | 必填 | 默认值 | 说明 |
|-----------|------|------|--------|------|
| `--app` | `str` | 是 | — | 注入指定 app 引用的密钥。 |
| `--vault` | `click.Path` | 否 | 全局默认 | vault 文件路径 |
| `COMMAND [ARGS...]` | `str` (variadic) | 是 | — | `--` 之后的命令及其参数 |

**别名解析注入逻辑**:
1. 读取 `apps[NAME].secrets` 别名列表
2. 对每个 alias：检查 `overrides[alias]`，有则用 override 值作为 env var name，否则用 `secret.key`
3. 解密 secret value
4. 已有系统环境变量 → 默认不覆盖（除非项目配置 `override_system: true`）

**行为**:
1. 解密 vault，按 alias 解析收集 key-value 对
2. 构造子进程环境：`{**os.environ, **resolved_secrets}`
3. 使用 `os.execvpe(command, args, env)` 执行子进程（替换当前进程）
4. 子进程退出码直接作为 `secrets run` 的退出码

**stderr**（`--verbose` 模式）:

```
[secrets] Resolving 3 aliases for app "backend"
[secrets] prod-db → DB_URL (override), jwt-secret → JWT_SECRET, shared-sentry → SENTRY_DSN
[secrets] Executing: python manage.py runserver
```

**示例**:

```bash
# 注入 app 解析后的 secrets 运行命令
secrets run --app backend --vault ./vault.json -- python manage.py runserver

# CI 场景
echo "$VAULT_PASSWORD" | secrets run --password-stdin --app backend --vault ./vault.json -- pytest
```

---

#### 1.4.7 `secrets export`

**功能**: 导出指定 app 解析后的环境变量（alias 解析 + overrides 应用后）。

**签名**:

```
secrets export --app NAME [--vault PATH] [--format FORMAT]
```

| 参数/选项 | 类型 | 必填 | 默认值 | 说明 |
|-----------|------|------|--------|------|
| `--app` | `str` | 是 | — | 应用名称 |
| `--vault` | `click.Path` | 否 | 全局默认 | vault 文件路径 |
| `--format` | `click.Choice(["env", "json"])` | 否 | `env` | 输出格式 |

**stdout**（`--format env`）:

```
export API_KEY='sk-abc123'
export DATABASE_URL='postgres://user:pass@host:5432/db'
export REDIS_URL='redis://localhost:6379/0'
```

格式规则：value 使用单引号包裹，内部单引号转义为 `'\''`。

**stdout**（`--format json`）:

```json
{
  "API_KEY": "sk-abc123",
  "DATABASE_URL": "postgres://user:pass@host:5432/db",
  "REDIS_URL": "redis://localhost:6379/0"
}
```

**示例**:

```bash
# eval 注入当前 shell
eval "$(secrets export --app backend --vault ./vault.json)"

# 导出 JSON 供程序读取
secrets export --app backend --vault ./vault.json --format json > /tmp/secrets.json

# 管道到 Docker
secrets export --app backend --vault ./vault.json --format env | xargs docker run --env
```

---

#### 1.4.8 `secrets import`

**功能**: 从 `.env` 文件导入 key-value 对到密钥池，并自动从 key 名生成 alias（如 `DATABASE_URL` → `database-url`）。同时将导入的 secrets 分配给指定 app。

**签名**:

```
secrets import --from FILE --app NAME [--vault PATH]
```

| 参数/选项 | 类型 | 必填 | 默认值 | 说明 |
|-----------|------|------|--------|------|
| `--from` | `click.Path(exists=True)` | 是 | — | 源 `.env` 文件路径。格式：每行 `KEY=VALUE`，支持 `#` 注释、空行、引号值。 |
| `--app` | `str` | 是 | — | 导入后自动分配到的应用名称 |
| `--vault` | `click.Path` | 否 | 全局默认 | vault 文件路径 |

**`.env` 解析规则**:
- 忽略空行和 `#` 开头的注释行
- `KEY=VALUE` — 去除 VALUE 两端空白
- `KEY="VALUE"` — 去除双引号，处理 `\n`/`\t`/`\\`/`\"` 转义
- `KEY='VALUE'` — 去除单引号，不处理转义
- `export KEY=VALUE` — 忽略 `export ` 前缀
- 重复 key 以最后出现的为准

**stdout**: 无

**stderr**（正常）:

```
✓ Imported 5 secrets into pool and assigned to app "backend" from .env.production
  New aliases: database-url, redis-url, jwt-secret
  Updated aliases: api-key, sentry-dsn
```

**示例**:

```bash
secrets import --from .env.production --app backend --vault ./vault.json
```

---

#### 1.4.9 `secrets serve`

**功能**: 启动 Web 管理服务（Axum + Tokio），提供 RESTful API 和 Web UI。

**签名**:

```
secrets serve [--port PORT] [--vault PATH] [--host HOST]
```

| 参数/选项 | 类型 | 必填 | 默认值 | 说明 |
|-----------|------|------|--------|------|
| `--port` | `int` | 否 | `8080`（来自全局配置 `web.port`） | 监听端口 |
| `--host` | `str` | 否 | `127.0.0.1`（来自全局配置 `web.host`） | 监听地址 |
| `--vault` | `click.Path(exists=True)` | 否 | 全局默认 | vault 文件路径 |

**行为**:
1. 加载全局配置获取 CORS、session timeout、rate limit 参数
2. 校验 vault 文件存在且可读
3. 启动 Axum HTTP 服务器
4. 阻塞直到 `SIGINT`/`SIGTERM`

**stderr**（启动）:

```
✓ Secrets Manager Web UI
  Vault:   /home/user/.secrets/vault.json
  Listen:  http://127.0.0.1:8080
  Press Ctrl+C to stop
```

**示例**:

```bash
secrets serve --vault ./vault.json
secrets serve --port 9090 --host 0.0.0.0 --vault ./vault.json
```

---

#### 1.4.10 `secrets self-test`

**功能**: 验证安装完整性——检查依赖库可用性、加密功能正确性、配置文件可读性。

**签名**:

```
secrets self-test
```

无额外参数。不需要 `--vault`（不操作真实 vault）。

**行为**:
1. 检查 Rust 加密后端（Argon2id + AES-256-GCM）
2. 执行内存加密/解密往返测试（Argon2id → AES-256-GCM → 解密 → 比对）
3. 检查全局配置文件可读性
4. 报告系统信息（Enva 版本、OS、架构）

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

**依赖缺失时**: 标记 `✗ not installed`，最终退出码 `1`。

---

## 第二部分：Shell Hook 规范

### 2.1 Bash Hook (`secrets-hook.bash`)

**安装路径**: `~/.secrets/hooks/secrets-hook.bash`（全局配置 `shell.hooks.bash` 可覆盖）

**激活方式**: 用户在 `~/.bashrc` 或 `~/.bash_profile` 中添加:

```bash
source ~/.secrets/hooks/secrets-hook.bash
```

#### 2.1.1 触发机制

使用 `PROMPT_COMMAND` 函数链：

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

要点：
- 追加到 `PROMPT_COMMAND` 链而非替换，避免破坏已有 hook
- 仅在配置文件路径变化时触发重新注入（避免每次命令后都解密）

#### 2.1.2 History 保护

```bash
export HISTCONTROL="ignorespace:${HISTCONTROL}"
```

所有包含敏感信息的命令自动前缀空格：

```bash
__secrets_inject() {
    # 前缀空格使 bash 不记录到 history
     eval "$( secrets export --app "$app" --vault "$vault" --quiet)"
}
```

#### 2.1.3 反激活

提供 `secrets-unhook` 函数用于在当前 session 中取消注入：

```bash
secrets-unhook() {
    # 清理已注入的环境变量
    local key
    for key in ${__SECRETS_INJECTED_KEYS[@]}; do
        unset "$key"
    done
    __SECRETS_INJECTED_KEYS=()
    __SECRETS_LAST_CONFIG=""

    # 从 PROMPT_COMMAND 链中移除
    PROMPT_COMMAND="${PROMPT_COMMAND/__secrets_prompt_hook;/}"
    PROMPT_COMMAND="${PROMPT_COMMAND/__secrets_prompt_hook/}"
}
```

**行为**: 调用后清除所有已注入的环境变量、重置跟踪状态、从 `PROMPT_COMMAND` 链中移除 hook。

---

### 2.2 Zsh Hook (`secrets-hook.zsh`)

**安装路径**: `~/.secrets/hooks/secrets-hook.zsh`（全局配置 `shell.hooks.zsh` 可覆盖）

**激活方式**: 用户在 `~/.zshrc` 中添加:

```zsh
source ~/.secrets/hooks/secrets-hook.zsh
```

#### 2.2.1 触发机制

使用 Zsh 原生 hook 系统（**非 Bash 移植**）：

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

要点：
- `precmd`: 每次命令执行后、提示符渲染前触发——与 Bash `PROMPT_COMMAND` 等价
- `chpwd`: 目录切换时触发——强制重新检测配置文件并重新注入
- 使用 `add-zsh-hook` 而非直接赋值 `precmd()` / `chpwd()`，避免覆盖用户已有 hook

#### 2.2.2 History 保护

```zsh
setopt HIST_IGNORE_SPACE
```

与 Bash hook 相同，所有敏感命令以空格前缀执行。

#### 2.2.3 反激活

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

### 2.3 注入生命周期

#### 2.3.1 密码缓存

| 属性 | 说明 |
|------|------|
| 缓存方式 | 内存变量 `__SECRETS_CACHED_PASSWORD`（仅存在于当前 shell 进程） |
| 超时 | 由全局配置 `defaults.password_timeout` 控制（默认 300 秒，即 5 分钟） |
| 过期检测 | 每次注入前检查 `__SECRETS_CACHE_TIMESTAMP` + `password_timeout` 与当前时间 |
| 手动清除 | `unset __SECRETS_CACHED_PASSWORD __SECRETS_CACHE_TIMESTAMP` |
| 可选增强 | 全局配置 `defaults.password_cache: keyring` 时使用系统 keyring（macOS Keychain / Linux Secret Service） |
| CI/脚本场景 | `ENVA_PASSWORD` 环境变量优先于缓存 |

密码缓存伪逻辑：

```
if ENVA_PASSWORD env var is set:
    password = $ENVA_PASSWORD
elif cached password exists AND not expired:
    password = cached
else:
    prompt user for password
    cache password with current timestamp
```

#### 2.3.2 触发时机

| 触发事件 | Bash | Zsh | 行为 |
|---------|------|-----|------|
| Shell 启动 | `PROMPT_COMMAND`（首次） | `precmd`（首次） | 检测 CWD 下是否有 `.enva.yaml`，有则注入 |
| 命令执行后 | `PROMPT_COMMAND` | `precmd` | 仅在配置路径变化时重新注入（性能保护） |
| 目录切换 | 无原生感知（依赖 `PROMPT_COMMAND` 下次检测） | `chpwd`（即时） | 重置状态，立即检测新目录 |
| 手动刷新 | 用户调用 `secrets-refresh` | 同左 | 强制清除缓存并重新注入 |

`secrets-refresh` 函数（Bash/Zsh 通用逻辑）：

```bash
secrets-refresh() {
    __SECRETS_LAST_CONFIG=""
    unset __SECRETS_CACHED_PASSWORD __SECRETS_CACHE_TIMESTAMP
    __secrets_precmd_hook  # 或 __secrets_prompt_hook (Bash)
}
```

#### 2.3.3 注入优先级链

同名 key 冲突时的覆盖顺序（后者覆盖前者）：

```
[低优先级]                             [高优先级]
系统环境变量 → global keys → app-specific keys
       ↑                                    
       └── override_system=true 时反转：     
           global keys → app-specific keys → 系统环境变量
```

详细规则：
1. 读取 `.enva.yaml` 中 `default_app` 或 `apps` 配置
2. 解密 vault 中 global 域的 keys → 注入
3. 解密 vault 中指定 app 的 keys → 覆盖同名 global key
4. 如果项目配置 `override_system: false`（默认），系统已有的同名环境变量**不被覆盖**
5. 如果项目配置 `override_system: true`，vault 中的值覆盖系统环境变量

### 2.4 配置文件自动发现

从 CWD 开始向上查找 `.enva.yaml`：

```
/home/user/projects/myapp/src/  ← CWD
/home/user/projects/myapp/      ← 检查 .enva.yaml
/home/user/projects/            ← 检查 .enva.yaml
/home/user/                     ← 检查 .enva.yaml
/home/                          ← 停止（到达 $HOME 的父目录）
/                               ← 不检查
```

**停止条件**: 到达 `$HOME` 的父目录或文件系统根目录。

**找到配置文件后**: 读取其中的 `vault_path`（支持相对路径，相对于配置文件所在目录解析）和 `default_app` 确定注入范围。

---

## 第三部分：Web API 规范

### 3.1 总览

| 属性 | 值 |
|------|-----|
| 框架 | Axum 0.8 |
| 服务器 | Tokio |
| 基础路径 | `/api` |
| 内容类型 | `application/json`（除 import 为 `multipart/form-data`） |
| 认证 | JWT Bearer Token |
| CORS | 可配置（默认 `http://localhost:*`） |

### 3.2 认证

#### 3.2.1 `POST /api/auth/login`

登录获取 JWT token。

**请求**:

```
POST /api/auth/login
Content-Type: application/json
```

```json
{
  "password": "my-vault-password"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `password` | `string` | 是 | vault 密码 |

**成功响应** (`200 OK`):

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YXVsdF9wYXRoIjoiL2hvbWUvdXNlci8uc2VjcmV0cy92YXVsdC5qc29uIiwiaWF0IjoxNzExNTI3MDAwLCJleHAiOjE3MTE1Mjg4MDB9.abc123signature",
  "expires_in": 1800
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `token` | `string` | JWT token（HS256 签名） |
| `expires_in` | `integer` | token 有效期（秒），由全局配置 `web.session_timeout` 决定，默认 1800 |

**JWT Payload 结构**:

```json
{
  "vault_path": "/home/user/.secrets/vault.json",
  "iat": 1711527000,
  "exp": 1711528800
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `vault_path` | `string` | 当前服务的 vault 文件路径 |
| `iat` | `integer` | 签发时间（Unix timestamp） |
| `exp` | `integer` | 过期时间（Unix timestamp） |

**JWT 签名密钥**: 服务启动时生成的随机 32 字节（`os.urandom(32)`），进程生命周期内有效。服务重启后所有 token 失效。

**失败响应** (`401 Unauthorized`):

```json
{
  "error": "authentication_failed",
  "message": "Invalid vault password"
}
```

**速率限制响应** (`403 Forbidden`):

```json
{
  "error": "rate_limited",
  "message": "Too many failed attempts. Locked out for 300 seconds.",
  "retry_after": 300
}
```

#### 3.2.2 速率限制

| 参数 | 默认值 | 配置路径 | 说明 |
|------|--------|----------|------|
| `max_attempts` | `5` | `web.rate_limit.max_attempts` | 连续失败次数上限 |
| `lockout_seconds` | `300` | `web.rate_limit.lockout_seconds` | 锁定时长（秒） |

实现方式：内存计数器，按客户端 IP 跟踪。lockout 期间所有 login 请求返回 `403`。

#### 3.2.3 认证中间件

除 `POST /api/auth/login` 外，所有 `/api/*` 端点需要在请求头中携带 JWT token：

```
Authorization: Bearer <token>
```

**token 缺失或无效时**: 返回 `401 Unauthorized`。

```json
{
  "error": "unauthorized",
  "message": "Missing or invalid authentication token"
}
```

**token 过期时**: 返回 `401 Unauthorized`。

```json
{
  "error": "token_expired",
  "message": "Authentication token has expired"
}
```

---

### 3.3 Secrets CRUD（别名模型）

#### 3.3.1 列出密钥池 — `GET /api/secrets`

**请求**:

```
GET /api/secrets
Authorization: Bearer <token>
```

无查询参数。返回密钥池中的所有 secrets。

**成功响应** (`200 OK`):

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

| 响应字段 | 类型 | 说明 |
|---------|------|------|
| `[].alias` | `string` | 密钥别名 |
| `[].key` | `string` | 注入时的环境变量名 |
| `[].value_masked` | `string` | 遮盖后的值 `"••••••••"` |
| `[].description` | `string` | 描述 |
| `[].tags` | `array[string]` | 标签列表 |
| `[].apps` | `array[string]` | 引用此 secret 的 app 列表 |
| `[].updated_at` | `string` | ISO 8601 格式的最后更新时间 |

---

#### 3.3.2 获取单个密钥 — `GET /api/secrets/:alias`

**请求**:

```
GET /api/secrets/prod-db?reveal=true
Authorization: Bearer <token>
```

| 路径参数 | 类型 | 必填 | 说明 |
|---------|------|------|------|
| `alias` | `string` | 是 | 密钥别名 |

| 查询参数 | 类型 | 必填 | 默认值 | 说明 |
|---------|------|------|--------|------|
| `reveal` | `boolean` | 否 | `false` | 是否返回明文值 |

**成功响应** (`200 OK`，`reveal=false`):

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

**成功响应** (`200 OK`，`reveal=true`):

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

**Alias 不存在** (`404 Not Found`):

```json
{
  "error": "not_found",
  "message": "Alias \"prod-db\" not found"
}
```

---

#### 3.3.3 创建或更新密钥 — `PUT /api/secrets/:alias`

**请求**:

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

| 路径参数 | 类型 | 必填 | 说明 |
|---------|------|------|------|
| `alias` | `string` | 是 | 密钥别名 |

| Body 字段 | 类型 | 必填 | 默认值 | 说明 |
|-----------|------|------|--------|------|
| `key` | `string` | 是 | — | 注入时的环境变量名 |
| `value` | `string` | 是 | — | 密钥值，最大 64KB |
| `description` | `string` | 否 | `""` | 描述 |
| `tags` | `array[string]` | 否 | `[]` | 标签列表 |

**成功响应** (`200 OK`，已存在 alias 更新):

```json
{
  "alias": "prod-db",
  "created": false,
  "updated_at": "2026-03-27T12:00:00+08:00"
}
```

**成功响应** (`201 Created`，新增 alias):

```json
{
  "alias": "prod-db",
  "created": true,
  "updated_at": "2026-03-27T12:00:00+08:00"
}
```

---

#### 3.3.4 删除密钥 — `DELETE /api/secrets/:alias`

**请求**:

```
DELETE /api/secrets/prod-db
Authorization: Bearer <token>
```

| 路径参数 | 类型 | 必填 | 说明 |
|---------|------|------|------|
| `alias` | `string` | 是 | 密钥别名 |

**成功响应** (`200 OK`):

```json
{
  "deleted": true,
  "removed_from_apps": ["backend"]
}
```

**Alias 不存在** (`404 Not Found`):

```json
{
  "error": "not_found",
  "message": "Alias \"prod-db\" not found"
}
```

---

### 3.3b App Secrets 管理

#### 3.3b.1 获取 App 解析后的 Secrets — `GET /api/apps/:app/secrets`

**请求**:

```
GET /api/apps/backend/secrets
Authorization: Bearer <token>
```

返回指定 app 的 resolved secrets（alias 解析 + overrides 应用后）。

**成功响应** (`200 OK`):

```json
{
  "app": "backend",
  "secrets": [
    {"alias": "prod-db", "injected_as": "DB_URL", "override": true},
    {"alias": "jwt-secret", "injected_as": "JWT_SECRET", "override": false}
  ]
}
```

#### 3.3b.2 设置 App 引用 — `PUT /api/apps/:app/secrets`

**请求**:

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

**成功响应** (`200 OK`):

```json
{
  "app": "backend",
  "assigned": 2
}
```

#### 3.3b.3 移除 App 中的单个引用 — `DELETE /api/apps/:app/secrets/:alias`

**请求**:

```
DELETE /api/apps/backend/secrets/prod-db
Authorization: Bearer <token>
```

**成功响应** (`200 OK`):

```json
{
  "unassigned": true
}
```

---

### 3.4 导入导出

#### 3.4.1 导入 — `POST /api/secrets/import`

**请求**:

```
POST /api/secrets/import
Authorization: Bearer <token>
Content-Type: multipart/form-data
```

| 表单字段 | 类型 | 必填 | 默认值 | 说明 |
|---------|------|------|--------|------|
| `file` | `UploadFile` | 是 | — | `.env` 格式文件 |
| `app` | `string` | 否 | `None`（global 域） | 目标 app 名称 |

**成功响应** (`200 OK`):

```json
{
  "imported": 5,
  "details": {
    "new": ["DATABASE_URL", "REDIS_URL", "JWT_SECRET"],
    "updated": ["API_KEY", "SENTRY_DSN"]
  }
}
```

| 响应字段 | 类型 | 说明 |
|---------|------|------|
| `imported` | `integer` | 导入的 key 总数 |
| `details.new` | `array[string]` | 新增的 key 名称列表 |
| `details.updated` | `array[string]` | 更新的 key 名称列表 |

**空文件或无有效 key** (`422 Unprocessable Entity`):

```json
{
  "error": "validation_error",
  "message": "No valid key-value pairs found in uploaded file"
}
```

---

#### 3.4.2 导出 — `GET /api/secrets/export`

**请求**:

```
GET /api/secrets/export?app=backend&format=json
Authorization: Bearer <token>
```

| 查询参数 | 类型 | 必填 | 默认值 | 说明 |
|---------|------|------|--------|------|
| `app` | `string` | 否 | `None`（global 域） | 应用名称 |
| `format` | `string` (`env` \| `json`) | 否 | `env` | 导出格式 |

**成功响应**（`format=env`，`200 OK`，`Content-Type: text/plain`）:

```
DATABASE_URL=postgres://user:pass@host:5432/mydb
REDIS_URL=redis://localhost:6379/0
JWT_SECRET=super-secret-jwt-key
```

注意：Web API 导出的 env 格式**不含** `export ` 前缀（与 CLI `--format env` 行为不同），便于直接作为 `.env` 文件保存。

**成功响应**（`format=json`，`200 OK`，`Content-Type: application/json`）:

```json
{
  "DATABASE_URL": "postgres://user:pass@host:5432/mydb",
  "REDIS_URL": "redis://localhost:6379/0",
  "JWT_SECRET": "super-secret-jwt-key"
}
```

---

### 3.5 App 管理

#### 3.5.1 列出应用 — `GET /api/apps`

**请求**:

```
GET /api/apps
Authorization: Bearer <token>
```

无查询参数。

**成功响应** (`200 OK`):

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

| 响应字段 | 类型 | 说明 |
|---------|------|------|
| `apps` | `array` | 应用列表（始终包含 `"global"` 作为首项） |
| `apps[].name` | `string` | 应用名称（`"global"` 表示全局域） |
| `apps[].key_count` | `integer` | 该应用下的 key 总数 |

---

### 3.6 错误响应

#### 3.6.1 错误 JSON 格式

所有错误响应遵循统一格式：

```json
{
  "error": "<error_code>",
  "message": "<human_readable_message>",
  "details": []
}
```

| 字段 | 类型 | 必有 | 说明 |
|------|------|------|------|
| `error` | `string` | 是 | 机器可读错误码 |
| `message` | `string` | 是 | 人类可读消息 |
| `details` | `array` | 仅 `422` | 字段级校验错误详情 |

#### 3.6.2 HTTP 状态码与错误码映射

| HTTP 状态码 | 错误码 | 触发条件 | 示例响应 |
|------------|--------|---------|---------|
| `401` | `authentication_failed` | 登录密码错误 | `{"error":"authentication_failed","message":"Invalid vault password"}` |
| `401` | `unauthorized` | token 缺失或格式错误 | `{"error":"unauthorized","message":"Missing or invalid authentication token"}` |
| `401` | `token_expired` | token 已过期 | `{"error":"token_expired","message":"Authentication token has expired"}` |
| `403` | `rate_limited` | 超过登录尝试次数 | `{"error":"rate_limited","message":"Too many failed attempts. Locked out for 300 seconds.","retry_after":300}` |
| `404` | `not_found` | key 或 app 不存在 | `{"error":"not_found","message":"Key \"X\" not found in app \"Y\""}` |
| `409` | `conflict` | 保留——将来用于严格 create-only 语义 | `{"error":"conflict","message":"Key \"X\" already exists in app \"Y\""}` |
| `422` | `validation_error` | 请求体字段校验失败 | 见下方示例 |

**422 详细示例**:

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

#### 3.6.3 CORS 配置

| 参数 | 默认值 | 配置路径 | 说明 |
|------|--------|----------|------|
| `allow_origins` | `["http://localhost:*"]` | `web.cors_origins` | 允许的来源域名列表 |
| `allow_methods` | `["GET", "PUT", "POST", "DELETE"]` | 不可配置 | 允许的 HTTP 方法 |
| `allow_headers` | `["Authorization", "Content-Type"]` | 不可配置 | 允许的请求头 |
| `allow_credentials` | `true` | 不可配置 | 允许携带凭证 |

### 3.7 Web UI 页面组件

Web 管理界面为静态 SPA（单页应用），由 Axum 进程直接托管提供服务，无需独立的前端构建或部署流程。

| 页面 | 路由 | 说明 |
|------|------|------|
| 登录页 | `/` | 输入 vault 密码进行认证，获取 JWT token |
| 仪表盘（Dashboard） | `/dashboard` | 以列表/分组视图展示所有 app 及其 key 名称（不显示值），支持搜索和筛选 |
| 添加/编辑模态框 | — （弹窗组件） | 创建新 key 或编辑已有 key 的 value，选择目标 app |
| 导入/导出页 | `/import-export` | 上传 `.env` 文件批量导入，或按 app 导出为 `.env` / JSON 格式 |

> 详细的页面线框图与交互设计参见架构设计文档（`architecture.md`）。

---

## 附录 A：端点汇总表

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| `POST` | `/api/auth/login` | 否 | 登录获取 JWT token |
| `GET` | `/api/secrets` | 是 | 列出密钥池中所有 secrets |
| `GET` | `/api/secrets/:alias` | 是 | 获取单个密钥（可选 reveal） |
| `PUT` | `/api/secrets/:alias` | 是 | 创建或更新密钥（按 alias） |
| `DELETE` | `/api/secrets/:alias` | 是 | 从密钥池删除（级联移除 app 引用） |
| `GET` | `/api/apps/:app/secrets` | 是 | 获取 app 解析后的 secrets |
| `PUT` | `/api/apps/:app/secrets` | 是 | 设置 app 的 secret 引用和 overrides |
| `DELETE` | `/api/apps/:app/secrets/:alias` | 是 | 从 app 移除单个 secret 引用 |
| `POST` | `/api/secrets/import` | 是 | 导入 .env 文件 |
| `GET` | `/api/secrets/export` | 是 | 导出密钥 |
| `GET` | `/api/apps` | 是 | 列出应用 |

## 附录 B：CLI 命令汇总表

| 命令 | 必填参数 | 可选参数 | 退出码 |
|------|---------|---------|--------|
| `init` | — | `--vault` | 0, 1 |
| `set` | `ALIAS`, `--key`, `--value` | `--description`, `--tags`, `--vault` | 0, 1, 2 |
| `get` | `ALIAS` | `--vault` | 0, 1, 2, 3 |
| `list` | — | `--app`, `--vault` | 0, 1, 2 |
| `delete` | `ALIAS` | `--vault` | 0, 1, 2, 3 |
| `assign` | `ALIAS`, `--app` | `--as`, `--vault` | 0, 1, 2, 3 |
| `unassign` | `ALIAS`, `--app` | `--vault` | 0, 1, 2, 3 |
| `run` | `COMMAND [ARGS]`, `--app` | `--vault` | 0, 1, 2, 子进程退出码 |
| `export` | `--app` | `--vault`, `--format` | 0, 1, 2 |
| `import` | `--from FILE`, `--app` | `--vault` | 0, 1, 2 |
| `serve` | — | `--port`, `--host`, `--vault` | 0, 1 |
| `self-test` | — | — | 0, 1 |

## 附录 C：校验规则汇总

| 字段 | 正则/规则 | 最大长度 | 说明 |
|------|----------|---------|------|
| Alias 别名 | `^[a-z0-9][a-z0-9-]*$` | 128 字符 | 密钥池唯一标识，小写字母数字及连字符 |
| Key 名称（env var） | `^[A-Za-z_][A-Za-z0-9_]*$` | 128 字符 | 环境变量命名约定 |
| App 名称 | `^[A-Za-z_][A-Za-z0-9_]*$` | 64 字符 | 同 key 约束 |
| Value | 非空 | 64 KB | 支持任意 UTF-8 字符串 |
| Vault 密码 | 无正则约束 | 无上限 | 建议 >= 12 字符（仅 UI/文档层面建议，不强制） |

---

*文档版本: 4.0 | 更新时间: 2026-03-28 | 数据模型: 别名引用 (alias-based) | 关联决策: 纯 Rust + clap CLI ([`tech_decision.md`](./tech_decision.md))*
