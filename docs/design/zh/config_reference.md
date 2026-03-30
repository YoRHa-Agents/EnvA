# 配置体系参考文档 (Configuration Reference)

> **Summary (EN):** Complete configuration reference for the five-layer secrets manager config system. Covers global config (`~/.enva/config.yaml`), project config (`.enva.yaml`), environment overrides (`.enva.{env}.yaml`), CLI flags/env vars, and built-in defaults. Every field is defined with path, type, default value, description, validation rules, example, and applicable layers. Merge priority: CLI > env-override > project > global > defaults.

---

## 1. 五层配置体系概览

配置按优先级从高到低分五层，高层覆盖低层同名字段：

| 层级 | 名称 | 路径/来源 | 作用域 | 格式 |
|------|------|----------|--------|------|
| **Layer 5** (最高) | CLI flags / 环境变量 | 命令行参数、`ENVA_*` 环境变量 | 单次执行 | N/A |
| **Layer 4** | 环境覆盖 | `.enva.{env}.yaml` | 项目 + 特定环境 | YAML |
| **Layer 3** | 项目配置 | `.enva.yaml` | 项目目录 | YAML |
| **Layer 2** | 全局配置 | `~/.enva/config.yaml` | 用户级，跨项目 | YAML |
| **Layer 1** (最低) | 内置默认值 | 硬编码于程序内 | 全局 | N/A |

---

## 2. CLI Flags 与环境变量（Layer 5）

| Flag | 环境变量 | 类型 | 说明 | 覆盖配置字段 |
|------|---------|------|------|-------------|
| `--vault PATH` | `ENVA_VAULT_PATH` | string | vault 文件路径 | `defaults.vault_path` / `vault_path` |
| `--app NAME` | `ENVA_APP` | string | 目标 app 名称 | `default_app` |
| `--password-stdin` | — | bool | 从 stdin 读取密码 | — |
| `--config PATH` | `ENVA_CONFIG` | string | 指定全局配置文件路径 | — |
| `--env ENV` | — | string | 激活环境覆盖文件 `.enva.{ENV}.yaml` | — |
| `--quiet` | — | bool | 静默模式，仅输出结果 | — |
| `--verbose` | — | bool | 详细输出（含调试信息） | `logging.level` → debug |
| — | `ENVA_PASSWORD` | string | vault 密码（仅用于 CI/自动化，生产环境不推荐） | — |

**优先级规则**：CLI flag > 环境变量 > 配置文件字段。`--quiet` 与 `--verbose` 互斥，同时指定时以 `--verbose` 为准。

---

## 3. 全局配置字段参考（Layer 2）

文件路径：`~/.enva/config.yaml`

### 3.1 顶层字段

| 字段路径 | 类型 | 默认值 | 说明 | 校验规则 | 示例 | 可设定层 |
|----------|------|--------|------|---------|------|---------|
| `version` | string | `"1"` | 配置文件格式版本号，用于未来向前兼容迁移 | 必填；当前仅允许 `"1"` | `"1"` | L2 |

### 3.2 defaults — 默认行为

| 字段路径 | 类型 | 默认值 | 说明 | 校验规则 | 示例 | 可设定层 |
|----------|------|--------|------|---------|------|---------|
| `defaults.vault_path` | string | `"~/.enva/vault.json"` | 默认 vault 文件路径；项目配置或 `--vault` 可覆盖 | 可选；路径字符串，支持 `~` 展开，且相对路径按当前工作目录解析 | `"~/.enva/vault.json"` | L2, L3, L4, L5 |
| `defaults.password_timeout` | int | `300` | 密码在内存中缓存的秒数；`0` 表示每次操作都要求输入密码 | 可选；`>= 0` | `300` | L2 |
| `defaults.password_cache` | enum | `"memory"` | 密码缓存模式 | 可选；枚举值 `memory` \| `keyring` \| `none` | `"memory"` | L2 |

**`password_cache` 枚举说明**：

| 值 | 行为 |
|----|------|
| `memory` | 密码在进程内存中缓存 `password_timeout` 秒，进程退出后清除 |
| `keyring` | 使用 OS keyring（macOS Keychain / Linux Secret Service）持久缓存 |
| `none` | 不缓存，每次操作均需输入密码 |

### 3.3 defaults.kdf — 密钥派生函数参数

| 字段路径 | 类型 | 默认值 | 说明 | 校验规则 | 示例 | 可设定层 |
|----------|------|--------|------|---------|------|---------|
| `defaults.kdf.algorithm` | enum | `"argon2id"` | KDF 算法；Argon2id 为 RFC 9106 推荐的密码哈希算法 | 可选；枚举值 `argon2id` \| `scrypt` | `"argon2id"` | L2 |
| `defaults.kdf.memory_cost` | int | `65536` | 内存开销，单位 KiB；`65536` = 64 MB | 可选；`>= 8192`（8 MB 最低安全阈值） | `65536` | L2 |
| `defaults.kdf.time_cost` | int | `3` | 迭代次数；值越大越慢越安全 | 可选；`>= 1` | `3` | L2 |
| `defaults.kdf.parallelism` | int | `4` | 并行线程数 | 可选；`>= 1`, `<= 256` | `4` | L2 |

> **注意**：KDF 参数在 vault 创建时写入 `_meta.kdf`，后续解密以 vault 内嵌参数为准。全局配置中的 KDF 参数仅影响 **新建 vault** 时的默认值。

### 3.4 shell — Shell 集成

| 字段路径 | 类型 | 默认值 | 说明 | 校验规则 | 示例 | 可设定层 |
|----------|------|--------|------|---------|------|---------|
| `shell.default_mode` | enum | `"exec"` | 默认注入模式 | 可选；枚举值 `exec` \| `export` | `"exec"` | L2 |
| `shell.auto_inject` | bool | `false` | 是否在 shell hook 触发时自动注入 secrets 到环境 | 可选 | `false` | L2 |
| `shell.history_protection` | bool | `true` | 阻止 secrets 出现在 shell 历史记录中（bash: `HISTCONTROL=ignorespace`; zsh: `setopt HIST_IGNORE_SPACE`） | 可选 | `true` | L2 |
| `shell.hooks.bash` | string | `"~/.secrets/hooks/secrets-hook.bash"` | bash hook 脚本路径 | 可选；路径字符串 | `"~/.secrets/hooks/secrets-hook.bash"` | L2 |
| `shell.hooks.zsh` | string | `"~/.secrets/hooks/secrets-hook.zsh"` | zsh hook 脚本路径 | 可选；路径字符串 | `"~/.secrets/hooks/secrets-hook.zsh"` | L2 |

**注入模式说明**：

| 模式 | 行为 | 安全性 |
|------|------|--------|
| `exec` | 以子进程方式注入：`enva <app> -- <cmd>`，secrets 仅存在于子进程环境 | 高 — secrets 不驻留父 shell |
| `export` | 以 `eval "$(enva vault export --app <app> --format env)"` 方式注入当前 shell | 中 — 需配合 `history_protection` |

### 3.5 web — Web 管理界面

| 字段路径 | 类型 | 默认值 | 说明 | 校验规则 | 示例 | 可设定层 |
|----------|------|--------|------|---------|------|---------|
| `web.host` | string | `"127.0.0.1"` | Web 服务监听地址 | 可选；有效 IP 地址或 `"0.0.0.0"` | `"127.0.0.1"` | L2, L5 |
| `web.port` | int | `8080` | Web 服务监听端口 | 可选；`1024–65535` | `8080` | L2, L5 |
| `web.cors_origins` | list\[string\] | `["http://localhost:*"]` | CORS 白名单；支持通配符 `*` | 可选；字符串列表 | `["http://localhost:*"]` | L2 |
| `web.session_timeout` | int | `1800` | Web 会话超时时间（秒）；超时后需重新认证 | 可选；`>= 60` | `1800` | L2 |
| `web.rate_limit.max_attempts` | int | `5` | 密码错误最大尝试次数；超限后锁定 | 可选；`>= 1` | `5` | L2 |
| `web.rate_limit.lockout_seconds` | int | `300` | 锁定持续时间（秒） | 可选；`>= 0`；`0` 表示不锁定 | `300` | L2 |

### 3.6 logging — 日志与审计

| 字段路径 | 类型 | 默认值 | 说明 | 校验规则 | 示例 | 可设定层 |
|----------|------|--------|------|---------|------|---------|
| `logging.level` | enum | `"warning"` | 日志级别 | 可选；枚举值 `debug` \| `info` \| `warning` \| `error` | `"warning"` | L2, L5 |
| `logging.audit_file` | string \| null | `"~/.secrets/audit.log"` | 审计日志文件路径；设为 `null` 禁用审计日志 | 可选；路径字符串或 `null` | `"~/.secrets/audit.log"` | L2 |
| `logging.redact_values` | bool | `true` | 在日志输出中脱敏 secret 值（使用 `enva-core` / `audit.rs` 中的 `redact_secret()` 逻辑） | 可选 | `true` | L2 |

> **说明**：`logging.audit_file` 使用简单的文件日志记录器。日志格式简洁，适合被外部日志聚合系统消费。

---

## 4. 项目配置字段参考（Layer 3）

文件路径：`.enva.yaml`（项目根目录）

### 4.1 顶层字段

| 字段路径 | 类型 | 默认值 | 说明 | 校验规则 | 示例 | 可设定层 |
|----------|------|--------|------|---------|------|---------|
| `vault_path` | string | 继承全局 `defaults.vault_path` | 项目专用的 vault 文件路径 | 可选；路径字符串，支持 `~`，且相对路径按运行时当前工作目录解析 | `"./secrets/project.vault.json"` | L3, L4, L5 |
| `default_app` | string | `""` | 默认的 `--app` 值；当 CLI 未指定 `--app` 时使用 | 可选；须匹配 `apps` 下已定义的 app 名称 | `"backend"` | L3, L4, L5 |

### 4.2 apps.\<name\> — 应用定义（别名引用模型）

`apps` 是一个 map，key 为应用名称（用于 `--app` 选项），value 为应用配置对象。App 通过别名（alias）列表引用密钥池中的 secrets，而非直接拥有 secrets。

| 字段路径 | 类型 | 默认值 | 说明 | 校验规则 | 示例 | 可设定层 |
|----------|------|--------|------|---------|------|---------|
| `apps.<name>.description` | string | `""` | 应用的人类可读描述，用于 `enva vault list` 输出 | 可选 | `"后端 API 服务"` | L3, L4 |
| `apps.<name>.secrets` | list\[string\] | `[]` | 此 app 引用的密钥别名列表；每个 alias 指向密钥池中的一个 secret | 可选；字符串列表，每项须为密钥池中已定义的 alias | `["prod-db", "jwt-secret", "shared-sentry"]` | L3, L4 |
| `apps.<name>.overrides` | map\[string, string\] | `{}` | 注入时覆盖环境变量名的映射：`alias → 自定义 env var name`；未在此 map 中的 alias 使用 secret 自身的 `key` 值注入 | 可选；key 为 alias，value 为合法环境变量名 | `{"prod-db": "DB_URL"}` | L3, L4 |
| `apps.<name>.app_path` | string | `""` | 执行 `enva <APP>` 且未显式传入 `-- <cmd>` 时使用的本地可执行路径 | 可选；支持 `~`、相对路径和绝对路径。相对路径按启动 `enva` 时的当前工作目录解析；若 vault 中该 app 已存有非空 `app_path`，则 vault 值优先，配置值仅作回退 | `"./bin/backend"` | L3, L4 |
| `apps.<name>.override_system` | bool | `false` | 当系统环境中已存在同名变量时，是否用 vault 中的值覆盖 | 可选 | `false` | L3, L4 |

**别名解析注入逻辑**：

```
for alias in app.secrets:
    if alias in app.overrides:
        env_var_name = app.overrides[alias]
    else:
        env_var_name = secrets_pool[alias].key
    env[env_var_name] = decrypt(secrets_pool[alias].value)
```

**配置示例**：

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

在此示例中：
- `backend` 引用 3 个 secrets，其中 `prod-db` 以 `DB_URL` 注入（而非默认的 `DATABASE_URL`）
- `backend` 也可以通过 `enva backend` 直接启动，此时 `./bin/backend` 按当前工作目录解析
- `frontend` 引用 1 个 secret，以 `NEXT_PUBLIC_SENTRY_DSN` 注入（而非默认的 `SENTRY_DSN`）
- `shared-sentry` 被多个 app 共享引用，无需重复定义

---

## 5. 环境覆盖配置（Layer 4）

文件路径：`.enva.{env}.yaml`（例如 `.enva.staging.yaml`, `.enva.production.yaml`）

环境覆盖文件的字段结构与项目配置（Layer 3）相同，所有字段均可出现。激活方式：

```bash
enva backend -- ./start.sh
```

环境覆盖文件中的字段 **深度合并** 到项目配置之上。`apps` 下同名 app 的字段逐一覆盖；不同名 app 保留项目配置中的定义。

---

## 6. 内置默认值（Layer 1）

当所有层均未设置某字段时，使用以下内置默认值：

| 字段路径 | 内置默认值 |
|----------|-----------|
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
| `vault_path` | 继承 `defaults.vault_path` |
| `default_app` | `""` |
| `apps.<name>.description` | `""` |
| `apps.<name>.secrets` | `[]` |
| `apps.<name>.overrides` | `{}` |
| `apps.<name>.app_path` | `""` |
| `apps.<name>.override_system` | `false` |

---

## 7. 合并规则

### 7.1 配置合并优先级

```
CLI flags / env vars  (Layer 5, 最高)
       ↓ 覆盖
.enva.{env}.yaml   (Layer 4, 环境覆盖)
       ↓ 覆盖
.enva.yaml         (Layer 3, 项目配置)
       ↓ 覆盖
~/.enva/config.yaml (Layer 2, 全局配置)
       ↓ 覆盖
内置默认值             (Layer 1, 最低)
```

**合并策略**：

| 字段类型 | 合并行为 |
|----------|---------|
| 标量（string, int, bool, enum） | 高层直接覆盖低层 |
| map（如 `apps`, `kdf`） | 深度合并 — 逐 key 递归，同 key 高层覆盖低层 |
| list（如 `inject_keys`, `cors_origins`） | 高层整体替换低层（不做元素级合并） |

### 7.2 注入优先级（别名解析模型）

当多个来源提供同名环境变量时，按以下优先级决定最终值：

```
1. CLI --env 覆盖文件中的值                  (最高)
2. app 引用的 alias 解析结果（含 overrides）
3. 系统已有环境变量                           (最低)
```

当 `override_system: true` 时，alias 解析结果覆盖系统环境变量。当 `override_system: false`（默认）时，系统已有同名环境变量不被覆盖。

### 7.3 别名解析注入逻辑

```
for alias in apps[NAME].secrets:
    env_var = overrides.get(alias, secrets_pool[alias].key)
    value = decrypt(secrets_pool[alias].value)
    if override_system or env_var not in os.environ:
        env[env_var] = value
```

若 `secrets` 列表引用了密钥池中不存在的 alias，则报错并退出。

---

## 8. 配置目录发现

程序启动时按以下顺序搜索全局配置目录：

| 优先级 | 平台 | 路径 | 条件 |
|--------|------|------|------|
| 1 | 全平台 | `$ENVA_CONFIG` 指定路径 | `--config` 或 `ENVA_CONFIG` 环境变量已设置 |
| 2 | Linux | `$XDG_CONFIG_HOME/secrets/config.yaml` | `$XDG_CONFIG_HOME` 已设置 |
| 3 | macOS | `~/Library/Application Support/secrets/config.yaml` | 检测到 macOS（`sys.platform == "darwin"`） |
| 4 | 全平台 | `~/.enva/config.yaml` | 统一 fallback |

**项目配置发现**：从当前工作目录向上逐级搜索 `.enva.yaml`，直到文件系统根目录。找到的第一个文件作为项目配置；同目录下的 `.enva.{env}.yaml` 作为环境覆盖候选。

### 8.1 独立模式配置发现

配置发现使用以下两个来源：

| 优先级 | 路径 | 说明 |
|--------|------|------|
| 1 | `~/.enva/config.yaml` | 用户级全局配置 |
| 2 | 当前目录下的 `.enva.yaml` | 当前项目配置 |

在独立模式下，宿主框架集成相关配置字段（若有）将被忽略（不会触发错误，仅静默跳过）。

---

## 9. 校验规则汇总

### 9.1 类型约束

| 类型 | 约束 |
|------|------|
| string | UTF-8 字符串；路径类型支持 `~` 展开。相对路径会拼接到当前工作目录，不做环境变量插值。 |
| int | 64 位有符号整数 |
| bool | `true` / `false`（YAML 原生布尔值） |
| enum | 仅允许文档中列出的枚举值，大小写敏感 |
| list\[string\] | YAML 序列，每个元素为 string |
| map | YAML 映射 |

### 9.2 值范围约束

| 字段 | 约束 | 违反时行为 |
|------|------|-----------|
| `defaults.password_timeout` | `>= 0` | 报错并退出 |
| `defaults.kdf.memory_cost` | `>= 8192` | 报错：低于安全阈值 |
| `defaults.kdf.time_cost` | `>= 1` | 报错 |
| `defaults.kdf.parallelism` | `1–256` | 报错 |
| `web.port` | `1024–65535` | 报错 |
| `web.session_timeout` | `>= 60` | 报错 |
| `web.rate_limit.max_attempts` | `>= 1` | 报错 |
| `web.rate_limit.lockout_seconds` | `>= 0` | — |
| `apps.<name>.secrets` 中的 alias | 须存在于密钥池 | 报错：alias 未定义 |

### 9.3 加载时校验流程

```
1. 解析 YAML → 原始 dict
2. 检查 version 字段是否为已知版本
3. 逐字段类型校验（类型 + 枚举值 + 值范围）
4. 跨字段引用校验：
   - secrets 列表中的 alias 须在密钥池中已定义
   - overrides 中的 key 须出现在 secrets 列表中
   - default_app 须在 apps 下已定义（或为空）
5. 合并各层配置（Layer 1 → Layer 5）
6. 路径展开（`~` → `$HOME`，相对路径 → 拼接当前工作目录）
7. 返回冻结的配置对象
```

---

## 10. 与其他文档的交叉引用

| 引用内容 | 参考文档 |
|----------|---------|
| Vault 文件格式（`_meta.kdf` 参数定义） | `secrets_manager_vault_spec.md` |
| CLI 命令签名与 `--vault`/`--app` 等选项 | `secrets_manager_api_spec.md` |
| Shell hook 注入机制与 history 保护实现 | `secrets_manager_api_spec.md` |
| 加密方案（Argon2id + AES-256-GCM）技术选型 | `secrets_manager_tech_decision.md` |
| 跨平台配置目录差异 | `secrets_manager_deployment.md` |
| 审计日志 `redact_secret()` 复用 | `secrets_manager_codebase_analysis.md` |

---

## 11. 配置示例文件

- 全局配置示例：[`config/enva.example.yaml`](../../config/enva.example.yaml)
- 项目配置示例：[`config/enva.project.example.yaml`](../../config/enva.project.example.yaml)

---

*文档版本: 3.0 | 更新时间: 2026-03-27 | 数据模型: 别名引用 (alias-based) | 配置格式版本: 1*
