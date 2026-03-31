# Vault 文件格式规范 (Vault File Format Specification)

> **Summary (EN):** Defines the on-disk format for the Enva secrets vault — a single JSON file with an alias-based secrets pool and per-value AES-256-GCM encryption. Secrets are identified by human-readable aliases and mapped to environment variable names; applications reference secrets by alias and may override injection names. Password-based key derivation uses Argon2id (RFC 9106). Values are encoded in a SOPS-inspired `ENC[AES256_GCM,data:…,iv:…,tag:…,type:…]` format. File-level integrity is enforced via HMAC-SHA256 over a canonical serialization of all aliases, keys, values, app bindings, and metadata. The format is self-describing: KDF parameters, salt, and format version are embedded in `_meta`, enabling any compliant reader to decrypt without external configuration. Version evolution follows semver with strict forward-compatibility guarantees for minor releases.
>
> **更新说明（2026-03-30）：** 运行时格式 `2.1` 为每个 secret 和 application 增加了不可变 `id` 字段。顶层仍然以 alias 和 app name 作为 JSON key，以保持人类可读性；但应用里的 secret 绑定和 override map 在保存时会规范化为 secret id，因此 alias 重命名后绑定关系不会丢失。现有 `2.0` vault 仍可正常加载，并会在保存时升级。当前实现强制的最小 `kdf.memory_cost` 为 `8192` KiB。

---

## 目录

1. [Vault JSON Schema](#1-vault-json-schema)
2. [加密值编码格式](#2-加密值编码格式-encrypted-value-encoding)
3. [密钥派生](#3-密钥派生-key-derivation)
4. [HMAC 完整性校验](#4-hmac-完整性校验-hmac-integrity)
5. [版本演进策略](#5-版本演进策略-version-evolution-strategy)
6. [完整示例](#6-完整示例-full-example)
7. [安全考量](#7-安全考量-security-considerations)

---

## 1. Vault JSON Schema

Vault 文件为单个 UTF-8 编码的 JSON 文件，顶层包含三个字段：`_meta`（元数据）、`secrets`（以 alias 为 key、带不可变 id 的密钥池）、`apps`（以应用名为 key、带不可变 app id 的应用引用配置）。

### 1.1 顶层结构

```json
{
  "_meta": { … },
  "secrets": { … },
  "apps": { … }
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `_meta` | `object` | 是 | 文件元数据，包含加密参数、完整性校验值、时间戳 |
| `secrets` | `object` | 是 | 别名密钥池，key 为人类可读 alias，value 包含不可变 `id`、环境变量名、加密值和元信息 |
| `apps` | `object` | 是 | 应用配置，以应用名为 key；每个应用记录也包含不可变 `id`，并以 secret id 保存绑定关系 |

### 1.2 `_meta` 对象

```json
{
  "_meta": {
    "format_version": "2.1",
    "kdf": {
      "algorithm": "argon2id",
      "memory_cost": 65536,
      "time_cost": 3,
      "parallelism": 4
    },
    "salt": "BASE64_ENCODED_32_BYTES",
    "hmac": "BASE64_ENCODED_32_BYTES",
    "created_at": "2026-03-27T10:30:00+08:00",
    "updated_at": "2026-03-27T14:15:30+08:00",
    "created_by": "developer@workstation"
  }
}
```

#### 字段定义

| 字段路径 | 类型 | 必填 | 说明 |
|---------|------|------|------|
| `format_version` | `string` | 是 | 格式版本号，遵循 `major.minor` 语义化版本。当前版本 `"2.1"` |
| `kdf` | `object` | 是 | 密钥派生函数参数（自描述，解密时无需外部配置） |
| `kdf.algorithm` | `string` | 是 | KDF 算法标识。v2.x 仅允许 `"argon2id"` |
| `kdf.memory_cost` | `integer` | 是 | Argon2id 内存开销，单位 KiB。推荐值 `65536`（64 MiB） |
| `kdf.time_cost` | `integer` | 是 | Argon2id 迭代次数。推荐值 `3` |
| `kdf.parallelism` | `integer` | 是 | Argon2id 并行线程数。推荐值 `4` |
| `salt` | `string` | 是 | 32 字节随机 salt，标准 Base64 编码（含 padding）。由 `os.urandom(32)` 生成 |
| `hmac` | `string` | 是 | 文件完整性校验值，HMAC-SHA256 的 Base64 编码。详见 [§4](#4-hmac-完整性校验-hmac-integrity) |
| `created_at` | `string` | 是 | vault 创建时间，ISO 8601 格式含时区偏移 |
| `updated_at` | `string` | 是 | 最后修改时间，ISO 8601 格式含时区偏移 |
| `created_by` | `string` | 是 | 创建者标识，格式 `user@hostname`，由 `getpass.getuser()` + `socket.gethostname()` 生成 |

#### 约束条件

- `format_version` 必须匹配 `^\d+\.\d+$`
- `kdf.memory_cost` 最小值 `8192`（8 MiB），与当前运行时实现保持一致
- `kdf.time_cost` 最小值 `1`
- `kdf.parallelism` 最小值 `1`
- `salt` 解码后必须为 32 字节
- `hmac` 解码后必须为 32 字节
- 时间戳必须包含时区信息

### 1.3 `secrets` 对象

别名密钥池。每个条目以人类可读的别名（alias）为 key，value 为包含环境变量名、加密值和元信息的结构体。多个别名可映射到相同的 `key`（环境变量名），实现同一变量在不同环境/版本下的多份密钥管理。

```json
{
  "secrets": {
    "prod-db": {
      "key": "DATABASE_URL",
      "value": "ENC[AES256_GCM,data:cG9zdGdyZXM=,iv:YWJjZGVmZ2hpamts,tag:bW5vcHFyc3R1dnd4,type:str]",
      "description": "Production PostgreSQL",
      "tags": ["production", "database"],
      "created_at": "2026-03-27T10:00:00Z",
      "updated_at": "2026-03-27T10:00:00Z"
    },
    "jwt-secret": {
      "key": "JWT_SECRET",
      "value": "ENC[AES256_GCM,data:and0X3NlY3JldA==,iv:cXdlcnR5dWlvcGFz,tag:enhjdmJubWFzZGZn,type:str]",
      "description": "JWT signing key",
      "tags": ["auth"],
      "created_at": "2026-03-26T14:00:00Z",
      "updated_at": "2026-03-26T14:00:00Z"
    }
  }
}
```

#### 密钥条目字段定义

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `key` | `string` | 是 | 注入时使用的环境变量名。推荐 UPPER_SNAKE_CASE。允许跨别名重复 |
| `value` | `string` | 是 | `ENC[…]` 编码的加密值 |
| `description` | `string` | 否 | 人类可读描述（默认 `""`） |
| `tags` | `string[]` | 否 | 分类标签（默认 `[]`） |
| `created_at` | `string` | 是 | 创建时间，ISO 8601 格式 |
| `updated_at` | `string` | 是 | 最后修改时间，ISO 8601 格式 |

#### 别名命名规则

| 规则 | 说明 |
|------|------|
| 正则 | `^[a-z0-9][a-z0-9_-]{0,62}$` |
| 字符集 | 小写字母、数字、连字符、下划线 |
| 首字符 | 必须为小写字母或数字 |
| 长度 | 1–63 字符 |
| 唯一性 | 同一 vault 内别名不可重复 |
| 示例 | `prod-db`、`staging_redis`、`jwt-secret-v2` |

#### `key` 命名规则

| 规则 | 说明 |
|------|------|
| 字符集 | `[A-Za-z_][A-Za-z0-9_]*`，即合法的环境变量名 |
| 大小写 | 保留原始大小写，推荐全大写（POSIX 惯例） |
| 长度 | 最大 256 字符 |
| 唯一性 | 允许跨别名重复（同一环境变量名可存在于多个别名下） |

#### value 格式

所有 `value` 必须匹配 `ENC[…]` 编码格式（详见 [§2](#2-加密值编码格式-encrypted-value-encoding)）。不允许明文值或空字符串。

### 1.4 `apps` 对象

应用引用配置。每个应用通过别名列表引用 `secrets` 池中的密钥，运行时按引用列表注入对应环境变量。应用不直接持有加密值，仅持有别名引用和可选的注入名覆盖。

```json
{
  "apps": {
    "backend": {
      "description": "Backend API service",
      "secrets": ["prod-db", "jwt-secret", "shared-sentry"],
      "overrides": {}
    },
    "frontend": {
      "description": "Frontend build",
      "secrets": ["shared-sentry"],
      "overrides": {
        "shared-sentry": "NEXT_PUBLIC_SENTRY_DSN"
      }
    }
  }
}
```

#### 应用条目字段定义

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `description` | `string` | 否 | 人类可读的应用描述 |
| `secrets` | `string[]` | 是 | 引用的别名列表，每个元素必须是 `secrets` 池中存在的别名 |
| `overrides` | `object` | 否 | 别名 → 自定义环境变量名的映射，用于覆盖注入时的默认 `key` |

#### 应用名命名规则

| 规则 | 说明 |
|------|------|
| 字符集 | `[a-z][a-z0-9_-]*`，小写字母开头，允许小写字母、数字、下划线、连字符 |
| 长度 | 1–64 字符 |
| 保留名 | `_meta`、`secrets` 不可用作应用名 |

#### 注入解析算法

当运行 `enva <app_name> -- <command>` 时，按以下算法解析并注入环境变量：

```python
for alias in apps[app_name]["secrets"]:
    secret = secrets[alias]
    env_name = apps[app_name]["overrides"].get(alias, secret["key"])
    os.environ[env_name] = decrypt(secret["value"])
```

- 若 `overrides` 中存在该别名的映射，使用覆盖名作为环境变量名
- 否则使用 `secret["key"]` 作为环境变量名
- 相同环境变量名后出现的条目会覆盖先出现的（列表顺序决定优先级）

### 1.5 JSON Schema（形式化定义）

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://enva.dev/schemas/vault/v2.0.json",
  "title": "Enva Secrets Vault",
  "type": "object",
  "required": ["_meta", "secrets", "apps"],
  "additionalProperties": false,
  "properties": {
    "_meta": {
      "type": "object",
      "required": ["format_version", "kdf", "salt", "hmac", "created_at", "updated_at", "created_by"],
      "additionalProperties": true,
      "properties": {
        "format_version": {
          "type": "string",
          "pattern": "^\\d+\\.\\d+$"
        },
        "kdf": {
          "type": "object",
          "required": ["algorithm", "memory_cost", "time_cost", "parallelism"],
          "properties": {
            "algorithm": { "type": "string", "enum": ["argon2id"] },
            "memory_cost": { "type": "integer", "minimum": 16384 },
            "time_cost": { "type": "integer", "minimum": 1 },
            "parallelism": { "type": "integer", "minimum": 1 }
          }
        },
        "salt": {
          "type": "string",
          "pattern": "^[A-Za-z0-9+/]+=*$"
        },
        "hmac": {
          "type": "string",
          "pattern": "^[A-Za-z0-9+/]+=*$"
        },
        "created_at": { "type": "string", "format": "date-time" },
        "updated_at": { "type": "string", "format": "date-time" },
        "created_by": { "type": "string", "minLength": 1 }
      }
    },
    "secrets": {
      "type": "object",
      "patternProperties": {
        "^[a-z0-9][a-z0-9_-]{0,62}$": {
          "type": "object",
          "required": ["key", "value", "created_at", "updated_at"],
          "additionalProperties": false,
          "properties": {
            "key": {
              "type": "string",
              "pattern": "^[A-Za-z_][A-Za-z0-9_]*$",
              "maxLength": 256
            },
            "value": {
              "type": "string",
              "pattern": "^ENC\\[AES256_GCM,data:[A-Za-z0-9+/]+=*,iv:[A-Za-z0-9+/]+=*,tag:[A-Za-z0-9+/]+=*,type:(str|int|float|bool|bytes)\\]$"
            },
            "description": { "type": "string", "default": "" },
            "tags": {
              "type": "array",
              "items": { "type": "string" },
              "default": []
            },
            "created_at": { "type": "string", "format": "date-time" },
            "updated_at": { "type": "string", "format": "date-time" }
          }
        }
      },
      "additionalProperties": false
    },
    "apps": {
      "type": "object",
      "patternProperties": {
        "^[a-z][a-z0-9_-]*$": {
          "type": "object",
          "required": ["secrets"],
          "additionalProperties": false,
          "properties": {
            "description": { "type": "string", "default": "" },
            "secrets": {
              "type": "array",
              "items": { "type": "string" }
            },
            "overrides": {
              "type": "object",
              "patternProperties": {
                "^[a-z0-9][a-z0-9_-]{0,62}$": {
                  "type": "string",
                  "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"
                }
              },
              "additionalProperties": false,
              "default": {}
            }
          }
        }
      },
      "additionalProperties": false
    }
  }
}
```

---

## 2. 加密值编码格式 (Encrypted Value Encoding)

### 2.1 编码格式

每个加密值编码为自描述的单行字符串，灵感来源于 SOPS 的 ENC 格式：

```
ENC[AES256_GCM,data:<BASE64>,iv:<BASE64>,tag:<BASE64>,type:<TYPE>]
```

#### 字段说明

| 字段 | 内容 | 编码 | 长度 |
|------|------|------|------|
| `AES256_GCM` | 算法标识（固定） | 明文 | — |
| `data` | 密文（AES-256-GCM 加密输出） | 标准 Base64（含 `=` padding） | 可变，等于明文长度 |
| `iv` | 初始向量 / nonce | 标准 Base64（含 `=` padding） | 固定 12 字节（编码后 16 字符） |
| `tag` | GCM 认证标签 | 标准 Base64（含 `=` padding） | 固定 16 字节（编码后 24 字符） |
| `type` | 原始值类型标识 | 明文 | 见下表 |

#### 分隔符规则

- 字段间以 `,`（逗号）分隔，**无空格**
- 字段名与值以 `:`（冒号）分隔，**无空格**
- 整体由 `ENC[` 和 `]` 包裹

### 2.2 AES-256-GCM 参数

| 参数 | 值 | 依据 |
|------|-----|------|
| 密钥长度 | 256 bit (32 bytes) | NIST SP 800-38D |
| Nonce 长度 | 96 bit (12 bytes) | GCM 标准推荐长度，避免 birthday-bound 退化 |
| 认证标签长度 | 128 bit (16 bytes) | GCM 最大标签长度，完整认证强度 |
| 附加认证数据 (AAD) | 密钥路径（见 §2.5） | 防止加密值在不同别名之间互换 |

**每个值使用独立的随机 nonce**：每次加密操作调用 `os.urandom(12)` 生成新 nonce。同一密钥下 nonce 不可复用（GCM 安全性核心要求）。

### 2.3 支持的类型

加密前，原始值按类型编码为字节序列；解密后按 `type` 字段还原为 Python 原生类型。

| type 标识 | Python 类型 | 编码为字节的方式 | 解码方式 | 示例原始值 |
|-----------|------------|----------------|---------|-----------|
| `str` | `str` | `value.encode('utf-8')` | `bytes.decode('utf-8')` | `"postgresql://..."` |
| `int` | `int` | `str(value).encode('utf-8')` | `int(bytes.decode('utf-8'))` | `5432` |
| `float` | `float` | `str(value).encode('utf-8')` | `float(bytes.decode('utf-8'))` | `0.95` |
| `bool` | `bool` | `b"true"` 或 `b"false"` | `bytes == b"true"` | `True` |
| `bytes` | `bytes` | 原始字节 | 直接返回 | `b"\x00\x01\x02"` |

> **设计选择**：`int` / `float` / `bool` 使用文本编码而非二进制，以便 debug 时对解密结果可读。`bytes` 类型用于存储证书、私钥等二进制数据。

### 2.4 Base64 编码规范

- 使用 RFC 4648 §4 标准 Base64 字母表（`A-Z`, `a-z`, `0-9`, `+`, `/`）
- **必须包含 `=` padding**（`base64.b64encode` 默认行为）
- 不使用 URL-safe 变体（无 `-` 或 `_`）
- 不插入换行符

### 2.5 附加认证数据 (AAD)

AES-256-GCM 加密时，密钥路径作为 AAD（Additional Authenticated Data）绑定到密文，防止攻击者将一个别名的加密值移到另一个别名下：

```
AAD = "secrets:<alias>"
```

| 作用域 | AAD 格式 | 示例 |
|--------|---------|------|
| `secrets` | `"secrets:<ALIAS>"` | `"secrets:prod-db"` |

AAD 以 UTF-8 编码传入 GCM 加密函数。此设计参考 SOPS 的 tree-path AAD 机制（`aes/cipher.go` 中 `additionalData` 参数）。

### 2.6 编码示例

#### 示例 1：字符串值

原始值：`"postgresql://user:pass@localhost:5432/mydb"`

```
ENC[AES256_GCM,data:mK3fR7bQ9xYpLdNwA2sTvHjE6iUoZcGk1gDhCqWfXeJm0y4B5nI8rOaS,iv:f0E2gH4iJ6kL8mN0,tag:pQ2rS4tU6vW8xY0zA2bC4d==,type:str]
```

分解：
- `data:mK3fR7…` — UTF-8 编码后的明文经 AES-256-GCM 加密，再 Base64 编码
- `iv:f0E2gH4iJ6kL8mN0` — 12 字节随机 nonce 的 Base64（16 字符）
- `tag:pQ2rS4tU6vW8xY0zA2bC4d==` — 16 字节 GCM 认证标签的 Base64（24 字符）
- `type:str` — 解密后还原为 Python `str`

#### 示例 2：整数值

原始值：`5432`

```
ENC[AES256_GCM,data:NjQzMg==,iv:aB1cD2eF3gH4iJ5k,tag:lM6nO7pQ8rS9tU0vW1xY2z==,type:int]
```

- `data:NjQzMg==` — `"5432"` 的 UTF-8 字节经加密后编码
- `type:int` — 解密后调用 `int()` 还原

#### 示例 3：布尔值

原始值：`True`

```
ENC[AES256_GCM,data:dHJ1ZQ==,iv:zA0yB1xC2wD3vE4u,tag:fG5hH6iI7jJ8kK9lL0mM1n==,type:bool]
```

- `data:dHJ1ZQ==` — `b"true"` 经加密后编码
- `type:bool` — 解密后与 `b"true"` 比较

#### 示例 4：浮点值

原始值：`0.95`

```
ENC[AES256_GCM,data:MC45NQ==,iv:nO2pP3qQ4rR5sS6t,tag:uU7vV8wW9xX0yY1zZ2aA3b==,type:float]
```

#### 示例 5：二进制值

原始值：`b"\x30\x82\x01\x22"` （DER 证书片段）

```
ENC[AES256_GCM,data:MIIBIQ==,iv:cC4dD5eE6fF7gG8h,tag:iI9jJ0kK1lL2mM3nN4oO5p==,type:bytes]
```

- `type:bytes` — 解密后直接返回原始字节，不做文本解码

### 2.7 解析正则表达式

实现可使用以下正则提取各字段：

```python
import re

ENC_PATTERN = re.compile(
    r'^ENC\[AES256_GCM,'
    r'data:(?P<data>[A-Za-z0-9+/]+=*),'
    r'iv:(?P<iv>[A-Za-z0-9+/]+=*),'
    r'tag:(?P<tag>[A-Za-z0-9+/]+=*),'
    r'type:(?P<type>str|int|float|bool|bytes)\]$'
)
```

解析失败（不匹配）应视为 vault 文件损坏，拒绝处理。

---

## 3. 密钥派生 (Key Derivation)

### 3.1 KDF 选择：Argon2id

选择 Argon2id（RFC 9106 推荐）作为密码派生函数：

| 特性 | 说明 |
|------|------|
| 抗 GPU/ASIC | memory-hard，大量内存访问使得并行硬件攻击代价极高 |
| 混合模式 | Argon2id = Argon2i（第 1 轮，抗侧信道）+ Argon2d（后续轮次，抗 GPU） |
| 标准化 | RFC 9106，Password Hashing Competition 冠军 |
| 可调参数 | 内存、时间、并行度三维调节，适应不同硬件 |

> **与现有 Rust HKDF 的关系**：Rust crate 中的 HKDF-SHA256 用于从高熵密钥材料派生子密钥（非密码场景），两者服务不同用途，独立共存。参见 [secrets_manager_tech_decision.md](./secrets_manager_tech_decision.md) §2。

> **实现说明**：Argon2id 通过 `enva-core` 库中的 Rust `argon2` crate 实现。Vault 文件格式与具体实现无关——任何兼容的读取器在获取正确密码后均可解密 vault 文件。

### 3.2 推荐参数

| 参数 | 推荐值 | 最小值 | 说明 |
|------|--------|--------|------|
| `memory_cost` | `65536` (64 MiB) | `16384` (16 MiB) | 内存开销，单位 KiB。越大越安全但越慢 |
| `time_cost` | `3` | `1` | 迭代次数。增大可线性增加计算时间 |
| `parallelism` | `4` | `1` | 并行 lane 数。应不超过 CPU 核心数 |

**参数选择依据**：

- `memory_cost=65536` (64 MiB)：OWASP 2024 推荐的最低配置为 19 MiB（`m=19456, t=2, p=1`），64 MiB 提供显著安全余量，同时在现代开发机上仅增加约 100-200ms 延迟
- `time_cost=3`：3 次迭代在 64 MiB 内存下，典型耗时 200-400ms，用户可接受
- `parallelism=4`：匹配主流开发机（4+ 核），充分利用多核但不过度占用

**可调整场景**：

| 场景 | 建议调整 |
|------|---------|
| CI/CD 环境（资源受限） | `memory_cost=32768, time_cost=2` |
| 高安全服务器 | `memory_cost=131072, time_cost=4` |
| 嵌入式/低内存设备 | `memory_cost=16384, time_cost=5`（用时间换内存） |

### 3.3 Salt 生成

- 长度：**32 字节**（256 bit）
- 来源：`os.urandom(32)`（操作系统 CSPRNG）
- 编码：标准 Base64 存储于 `_meta.salt`
- 生命周期：**每个 vault 文件一个 salt**，创建时生成，不可更改
- 更换 salt 等同于创建新 vault（需重新加密所有值）

```python
import os
import base64

salt = os.urandom(32)
salt_b64 = base64.b64encode(salt).decode('ascii')
# 示例输出: "x7Kj2mN+pQ8rS4tU6vW8xY0zA2bC4dEfGhIjKlMnOp0="
```

### 3.4 密钥派生流程

从用户密码派生两个独立密钥：一个用于 AES-256-GCM 加解密，一个用于 HMAC-SHA256 完整性校验。

```
password (用户输入)
    │
    ├── Argon2id(password, salt, params) → 64 bytes 主密钥材料
    │       │
    │       ├── [0:32]  → encryption_key (256 bit, AES-256-GCM)
    │       │
    │       └── [32:64] → hmac_key (256 bit, HMAC-SHA256)
    │
    (salt 从 _meta.salt 读取)
```

**实现伪代码**：

```python
from argon2.low_level import hash_secret_raw, Type

def derive_keys(
    password: str,
    salt: bytes,
    memory_cost: int,
    time_cost: int,
    parallelism: int,
) -> tuple[bytes, bytes]:
    """派生加密密钥和 HMAC 密钥。返回 (encryption_key, hmac_key)。"""
    raw = hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=64,           # 输出 64 字节
        type=Type.ID,          # Argon2id
    )
    encryption_key = raw[:32]  # 前 32 字节
    hmac_key = raw[32:]        # 后 32 字节
    return encryption_key, hmac_key
```

**为何派生 64 字节而非两次 32 字节**：

单次 Argon2id 调用输出 64 字节，然后切分为两个 32 字节密钥。相比于使用不同 salt 或 context 调用两次 Argon2id：
1. **性能**：只需一次 memory-hard 计算（~200-400ms），而非两次
2. **安全性**：Argon2id 的输出已经是密码学安全的伪随机序列，前后 32 字节在计算上不可关联
3. **简洁性**：减少参数管理复杂度

### 3.5 密码强度要求

Vault 实现应强制（可通过配置禁用）：

| 检查项 | 规则 |
|--------|------|
| 最小长度 | 12 字符 |
| 字符多样性 | 至少包含大写、小写、数字中的两类 |
| 熵估计 | 建议 ≥ 60 bit（可用 `zxcvbn` 等库评估） |

密码强度检查在 CLI 层执行，vault 格式本身不记录密码信息。

---

## 4. HMAC 完整性校验 (HMAC Integrity)

### 4.1 目的

HMAC 校验覆盖 vault 文件的数据完整性，防止以下攻击：

| 攻击类型 | 防御机制 |
|---------|---------|
| 篡改加密值 | HMAC 覆盖所有 `ENC[…]` 字符串 |
| 删除/添加别名或密钥 | HMAC 覆盖所有别名和 key 名 |
| 重排序条目 | 规范序列化消除顺序歧义 |
| 篡改应用引用 | HMAC 覆盖所有应用名和 secrets 引用列表 |
| 降级 KDF 参数 | HMAC 覆盖 `format_version` 和 `kdf` |
| 替换整个 vault（不同 salt） | HMAC 密钥由 salt 参与派生，不同 salt 产生不同 HMAC 密钥 |

> AES-GCM 的认证标签只保护单个值的完整性。HMAC 提供文件级全局完整性，确保所有值的组合未被篡改。

### 4.2 算法

**HMAC-SHA256**，密钥为 §3.4 中派生的 `hmac_key`（32 字节）。

### 4.3 HMAC 密钥

HMAC 使用与加密密钥**独立的** 256-bit 密钥，由同一次 Argon2id 派生的后 32 字节提供（见 §3.4）。密钥分离确保：
- 加密密钥泄漏不影响 HMAC 验证能力
- HMAC 密钥泄漏不影响密文安全性

### 4.4 规范序列化 (Canonical Serialization)

HMAC 的输入为 vault 数据的规范序列化字节序列，构造方式如下：

```
HMAC_INPUT = CANONICAL_SERIALIZE(_meta, secrets, apps)
```

#### HMAC 覆盖范围

- 所有别名（sorted）
- 所有 `secret.key` 值（按别名排序）
- 所有 `secret.value` 值（按别名排序）
- 所有应用名（sorted）
- 所有 `app.secrets` 引用列表（按应用名排序）
- `_meta.format_version` + `_meta.kdf`

#### 序列化步骤

**步骤 1**：序列化 `_meta` 中的受保护字段

```
meta_part = "format_version:" + _meta.format_version + "\n"
          + "kdf.algorithm:" + _meta.kdf.algorithm + "\n"
          + "kdf.memory_cost:" + str(_meta.kdf.memory_cost) + "\n"
          + "kdf.time_cost:" + str(_meta.kdf.time_cost) + "\n"
          + "kdf.parallelism:" + str(_meta.kdf.parallelism) + "\n"
```

**步骤 2**：收集 `secrets` 池条目

对 `secrets` 中的每个别名（按别名 UTF-8 字节序排列）：
```
"secrets:<ALIAS>:key=" + secret.key
"secrets:<ALIAS>:value=" + secret.value
```

**步骤 3**：收集 `apps` 条目

对 `apps` 中的每个应用（按应用名 UTF-8 字节序排列）：
```
"apps:<APP>:secrets=" + ",".join(app.secrets)
```

**步骤 4**：将所有条目按 UTF-8 字节序升序排列（确保确定性顺序）

**步骤 5**：拼接为最终输入

```
HMAC_INPUT = meta_part + sorted_entries.join("\n") + "\n"
```

#### 示例

给定 vault 内容：

```json
{
  "_meta": {
    "format_version": "2.0",
    "kdf": { "algorithm": "argon2id", "memory_cost": 65536, "time_cost": 3, "parallelism": 4 },
    "salt": "...", "hmac": "...",
    "created_at": "...", "updated_at": "...", "created_by": "..."
  },
  "secrets": {
    "prod-db": {
      "key": "DATABASE_URL",
      "value": "ENC[...db...]",
      "description": "Production DB",
      "tags": ["production"],
      "created_at": "...", "updated_at": "..."
    },
    "jwt-secret": {
      "key": "JWT_SECRET",
      "value": "ENC[...jwt...]",
      "description": "JWT key",
      "tags": ["auth"],
      "created_at": "...", "updated_at": "..."
    }
  },
  "apps": {
    "backend": {
      "description": "Backend API",
      "secrets": ["prod-db", "jwt-secret"],
      "overrides": {}
    }
  }
}
```

规范序列化结果（UTF-8 字节序排列）：

```
format_version:2.0
kdf.algorithm:argon2id
kdf.memory_cost:65536
kdf.time_cost:3
kdf.parallelism:4
apps:backend:secrets=prod-db,jwt-secret
secrets:jwt-secret:key=JWT_SECRET
secrets:jwt-secret:value=ENC[...jwt...]
secrets:prod-db:key=DATABASE_URL
secrets:prod-db:value=ENC[...db...]
```

> 注意：`apps:backend:secrets…` < `secrets:jwt-secret:key…`（按 UTF-8 字节序）。`description`、`tags`、`created_at`、`updated_at` 等元字段不参与 HMAC。`_meta.salt`、`_meta.hmac`、时间戳等不参与 HMAC 计算（salt 已通过密钥派生隐式绑定；hmac 是输出而非输入）。

### 4.5 HMAC 计算

```python
import hmac
import hashlib

def compute_hmac(hmac_key: bytes, canonical_input: bytes) -> bytes:
    """计算 HMAC-SHA256。"""
    return hmac.new(hmac_key, canonical_input, hashlib.sha256).digest()
```

结果为 32 字节，标准 Base64 编码后存入 `_meta.hmac`。

### 4.6 校验时机与流程

#### 加载时校验（每次读取 vault 必须执行）

```
1. 读取 vault JSON
2. 从 _meta 提取 salt、kdf 参数
3. 向用户请求密码
4. derive_keys(password, salt, kdf_params) → (encryption_key, hmac_key)
5. 规范序列化 vault 数据 → canonical_input
6. 计算 expected_hmac = HMAC-SHA256(hmac_key, canonical_input)
7. 读取 _meta.hmac → stored_hmac
8. 使用 hmac.compare_digest(expected_hmac, stored_hmac) 进行恒定时间比较
9. 如果不匹配 → 拒绝解密，报错 "vault integrity check failed"
```

> **恒定时间比较**：必须使用 `hmac.compare_digest()` 而非 `==`，防止计时侧信道攻击。

#### 保存前校验（每次写入 vault 必须执行）

```
1. 加密所有新/修改的值
2. 规范序列化全部数据 → canonical_input
3. 计算 new_hmac = HMAC-SHA256(hmac_key, canonical_input)
4. 将 new_hmac Base64 编码后写入 _meta.hmac
5. 更新 _meta.updated_at
6. 原子写入 vault 文件（write-to-temp + rename）
```

#### 错误处理

| 校验结果 | 处理 |
|---------|------|
| HMAC 匹配 | 继续正常解密 |
| HMAC 不匹配（密码正确） | 文件被篡改，拒绝操作，记录审计日志 |
| HMAC 不匹配（密码错误） | 提示 "incorrect password or corrupted vault" |
| `_meta.hmac` 缺失 | 视为格式错误，拒绝操作 |

> 不对外区分"密码错误"与"文件篡改"，避免信息泄漏。对内（审计日志）记录具体原因。

---

## 5. 版本演进策略 (Version Evolution Strategy)

### 5.1 版本号语义

`format_version` 遵循 `major.minor` 格式：

| 变更类型 | 版本号变化 | 含义 |
|---------|-----------|------|
| 新增可选字段 | minor +1 | 向前兼容，旧版本读取器忽略未知字段 |
| 新增必填字段 | major +1 | 破坏性变更，旧版本无法读取 |
| 修改字段语义 | major +1 | 破坏性变更 |
| 修改加密算法 | major +1 | 破坏性变更 |
| 修改 HMAC 覆盖范围 | major +1 | 破坏性变更 |
| 新增 type 选项（如 `json`） | minor +1 | 旧读取器遇到未知 type 可回退为 `str` |

### 5.2 兼容性规则

#### 读取兼容性矩阵

| 读取器版本 | 文件 format_version | 行为 |
|-----------|-------------------|------|
| v1.x | `1.0` | 完全支持 |
| v1.x | `2.0` | **拒绝**，提示需升级 |
| v2.x | `1.0` | 支持（向后兼容读取 + 可选迁移） |
| v2.x | `2.0` | 完全支持 |
| v2.x | `2.1` | 支持（忽略未知字段） |
| v2.x | `3.0` | **拒绝**，提示需升级 |

#### 读取规则

```python
def check_version_compatibility(file_version: str, reader_version: str) -> None:
    """检查文件版本与读取器版本的兼容性。"""
    file_major = int(file_version.split('.')[0])
    reader_major = int(reader_version.split('.')[0])

    if file_major > reader_major:
        raise IncompatibleVersionError(
            f"Vault format v{file_version} requires reader v{file_major}.x+, "
            f"current reader is v{reader_version}. Please upgrade."
        )
    # file_major <= reader_major: 可读取（向后兼容）
```

#### 未知字段处理

- **读取时**：忽略 `_meta` 中的未知字段（forward compatibility）
- **写入时**：保留原文件中的未知字段（round-trip fidelity）
- **HMAC 计算**：仅覆盖 §4.4 中定义的规范字段，未知字段不参与 HMAC

### 5.3 版本演进路径

#### v1.0（历史版本）

初始版本：
- Argon2id KDF
- AES-256-GCM per-value 加密
- HMAC-SHA256 完整性
- `global` + `apps` 两级结构（扁平 key-value）
- 支持类型：`str`, `int`, `float`, `bool`, `bytes`

#### v2.0（当前版本）

破坏性升级——引入别名数据模型：
- `global` 移除，由 `secrets` 别名池替代
- `apps` 从值所有权模型改为引用模型
- 每个密钥条目包含 `key`、`value`、`description`、`tags`、`created_at`、`updated_at`
- 应用通过别名列表引用密钥，支持 `overrides` 注入名覆盖
- HMAC 覆盖范围更新：覆盖别名、key、value、应用引用列表

#### v2.1（计划）— 新增可选字段

向前兼容的扩展：

```json
{
  "_meta": {
    "format_version": "2.1",
    "kdf": { "…": "…" },
    "salt": "…",
    "hmac": "…",
    "created_at": "…",
    "updated_at": "…",
    "created_by": "…",
    "description": "Production vault for project X",
    "last_rotated_at": "2026-06-01T00:00:00+08:00",
    "rotation_policy_days": 90
  }
}
```

新增可选字段：
- `_meta.description`：vault 用途描述
- `_meta.last_rotated_at`：上次密码轮换时间
- `_meta.rotation_policy_days`：密码轮换策略天数

v2.0 读取器遇到这些字段时忽略，正常工作。

#### v2.2（计划）— 新增类型

新增 `type:json` 支持结构化数据加密：

```
ENC[AES256_GCM,data:…,iv:…,tag:…,type:json]
```

v2.0/v2.1 读取器遇到 `type:json` 时，可回退为 `type:str` 返回 JSON 字符串。

#### v3.0（未来）— 破坏性变更

可能的破坏性变更场景：

| 变更 | 原因 |
|------|------|
| 替换 KDF 算法 | 若 Argon2id 出现安全漏洞，需迁移到后继算法 |
| 修改 HMAC 覆盖范围 | 扩展 HMAC 覆盖到新增必填字段 |
| 变更 ENC 编码格式 | 支持新加密算法标识（如 `XCHACHA20_POLY1305`） |

### 5.4 迁移机制

#### 自动迁移（minor 版本）

minor 版本升级无需迁移。读取器忽略未知字段，写入器在保存时自动添加新字段默认值。

#### 手动迁移（major 版本）

```
enva vault migrate --vault vault.json --target-version 2.0
```

迁移流程：

```
1. 读取旧版本 vault（使用旧版本读取逻辑）
2. 解密所有值
3. 创建新版本 vault 结构
4. 用新参数重新加密所有值
5. 计算新 HMAC
6. 写入新文件（或 --in-place 覆盖）
7. 验证新文件可正常读取
```

**v1.0 → v2.0 迁移映射**：
- `global` 中的每个 `KEY: ENC[…]` → `secrets` 池中以自动生成别名（小写化 key）为条目
- `apps` 中的每个 `APP.KEY: ENC[…]` → `secrets` 池中以 `<app>-<lowercase_key>` 为别名，应用引用列表自动填充

**安全要求**：
- 迁移过程中明文仅存在于内存
- 迁移前自动备份原文件（`vault.json.bak.TIMESTAMP`）
- 迁移后验证新 vault 的完整性

---

## 6. 完整示例 (Full Example)

### 6.1 空 vault（初始化后）

```json
{
  "_meta": {
    "format_version": "2.0",
    "kdf": {
      "algorithm": "argon2id",
      "memory_cost": 65536,
      "time_cost": 3,
      "parallelism": 4
    },
    "salt": "x7Kj2mNpQ8rS4tU6vW8xY0zA2bC4dEfGhIjKlMnOp0A=",
    "hmac": "QjR1dFk3Wk9pTnFEa0hMd2xYY3ZCbk1zUndUeEZ5R2g=",
    "created_at": "2026-03-27T10:30:00+08:00",
    "updated_at": "2026-03-27T10:30:00+08:00",
    "created_by": "dev@workstation"
  },
  "secrets": {},
  "apps": {}
}
```

### 6.2 包含多应用的 vault

```json
{
  "_meta": {
    "format_version": "2.0",
    "kdf": {
      "algorithm": "argon2id",
      "memory_cost": 65536,
      "time_cost": 3,
      "parallelism": 4
    },
    "salt": "BASE64_SALT",
    "hmac": "BASE64_HMAC",
    "created_at": "2026-03-27T10:00:00Z",
    "updated_at": "2026-03-27T14:30:00Z",
    "created_by": "developer@workstation"
  },
  "secrets": {
    "prod-db": {
      "key": "DATABASE_URL",
      "value": "ENC[AES256_GCM,data:cG9zdGdyZXM=,iv:YWJjZGVmZ2hpamts,tag:bW5vcHFyc3R1dnd4,type:str]",
      "description": "Production PostgreSQL",
      "tags": ["production", "database"],
      "created_at": "2026-03-27T10:00:00Z",
      "updated_at": "2026-03-27T10:00:00Z"
    },
    "staging-db": {
      "key": "DATABASE_URL",
      "value": "ENC[AES256_GCM,data:c3RhZ2luZw==,iv:MTIzNDU2Nzg5MDEy,tag:YWJjZGVmZ2hpamts,type:str]",
      "description": "Staging PostgreSQL",
      "tags": ["staging", "database"],
      "created_at": "2026-03-27T10:30:00Z",
      "updated_at": "2026-03-27T10:30:00Z"
    },
    "jwt-secret": {
      "key": "JWT_SECRET",
      "value": "ENC[AES256_GCM,data:and0X3NlY3JldA==,iv:cXdlcnR5dWlvcGFz,tag:enhjdmJubWFzZGZn,type:str]",
      "description": "JWT signing key",
      "tags": ["auth"],
      "created_at": "2026-03-26T14:00:00Z",
      "updated_at": "2026-03-26T14:00:00Z"
    },
    "shared-sentry": {
      "key": "SENTRY_DSN",
      "value": "ENC[AES256_GCM,data:c2VudHJ5,iv:bGtqaGdmZHNhcG9p,tag:cXdlcnR5dWlvcGFz,type:str]",
      "description": "Sentry error tracking DSN",
      "tags": ["monitoring"],
      "created_at": "2026-03-25T09:00:00Z",
      "updated_at": "2026-03-25T09:00:00Z"
    }
  },
  "apps": {
    "backend": {
      "description": "Backend API service",
      "secrets": ["prod-db", "jwt-secret", "shared-sentry"],
      "overrides": {}
    },
    "frontend": {
      "description": "Frontend build",
      "secrets": ["shared-sentry"],
      "overrides": {
        "shared-sentry": "NEXT_PUBLIC_SENTRY_DSN"
      }
    },
    "staging": {
      "description": "Staging environment",
      "secrets": ["staging-db", "jwt-secret", "shared-sentry"],
      "overrides": {}
    }
  }
}
```

### 6.3 操作流程示例

#### 创建 vault

```
$ enva vault init --vault ./project.vault.json
Enter master password: ********
Confirm master password: ********
✓ Vault created at ./project.vault.json
  Format: v2.0 (alias-based)
  KDF: argon2id (memory=64MB, time=3, parallelism=4)
  Salt: 32 bytes (random)
```

#### 添加 secret（别名模式）

```
$ enva --vault ./project.vault.json vault set prod-db \
    --key DATABASE_URL \
    --value "postgresql://user:pass@localhost:5432/mydb" \
    --description "Production PostgreSQL" \
    --tags production,database
Enter master password: ********
✓ Verifying vault integrity... OK
✓ Set secrets:prod-db (key: DATABASE_URL, type: str)
✓ HMAC updated
```

#### 将密钥绑定到应用

```
$ enva --vault ./project.vault.json vault assign prod-db --app backend
Enter master password: ********
✓ Verifying vault integrity... OK
Assigned prod-db to backend
✓ HMAC updated
$ enva --vault ./project.vault.json vault assign jwt-secret --app backend
Enter master password: ********
✓ Verifying vault integrity... OK
Assigned jwt-secret to backend
✓ HMAC updated
```

#### 设置注入名覆盖

```
$ enva --vault ./project.vault.json vault assign shared-sentry --app frontend --as NEXT_PUBLIC_SENTRY_DSN
Enter master password: ********
✓ Verifying vault integrity... OK
Assigned shared-sentry to frontend (injected as NEXT_PUBLIC_SENTRY_DSN)
✓ HMAC updated
```

#### 运行应用（注入环境变量）

```
$ enva --vault ./project.vault.json backend -- python app.py
Enter master password: ********
✓ Verifying vault integrity... OK
✓ Injecting 3 secrets for app "backend":
  DATABASE_URL ← prod-db
  JWT_SECRET ← jwt-secret
  SENTRY_DSN ← shared-sentry
✓ Running: python app.py
```

#### 读取 secret

```
$ enva --vault ./project.vault.json vault get prod-db
Enter master password: ********
✓ Verifying vault integrity... OK
Alias:   prod-db
Key:     DATABASE_URL
Value:   postgresql://user:pass@localhost:5432/mydb
Tags:    production, database
```

---

## 7. 安全考量 (Security Considerations)

### 7.1 威胁模型与防御

| 威胁 | 攻击向量 | 防御措施 |
|------|---------|---------|
| 离线暴力破解 | 攻击者获取 vault 文件，离线尝试密码 | Argon2id memory-hard KDF，64 MiB + 3 iterations 使每次尝试耗时 200-400ms |
| 密文值互换 | 攻击者将别名 A 的密文移到别名 B | AAD 绑定别名路径（§2.5），GCM 认证失败 |
| 文件篡改 | 攻击者修改 vault 文件任意字段 | HMAC-SHA256 全局完整性校验（§4） |
| 应用引用篡改 | 攻击者修改 apps 的 secrets 引用列表 | HMAC 覆盖应用引用列表 |
| KDF 参数降级 | 攻击者将 memory_cost 改为最小值 | HMAC 覆盖 KDF 参数，篡改会导致 HMAC 校验失败 |
| Nonce 重用 | 实现缺陷导致相同 nonce 加密不同值 | 每次加密调用 `os.urandom(12)` 生成独立 nonce |
| 内存残留 | 解密后明文残留在进程内存 | 操作完成后主动清零（`SecureString` 模式），Python 中使用 `ctypes.memset` |
| 计时侧信道 | 通过比较时间推断 HMAC 值 | 使用 `hmac.compare_digest()` 恒定时间比较 |

### 7.2 不防御的场景

| 场景 | 原因 |
|------|------|
| 内存转储攻击（cold boot / swap）| 需操作系统级防护（mlock），超出应用层职责 |
| 恶意读取器 | 读取器可获取明文，无法在格式层面防御 |
| 密码泄漏（钓鱼/键盘记录） | 超出文件格式职责 |
| 量子计算攻击 | AES-256 在量子场景下仍有 128-bit 安全强度（Grover），暂无需迁移 |

### 7.3 实现检查清单

实现者应确保以下要点：

- [ ] 每次加密使用 `os.urandom(12)` 生成独立 nonce
- [ ] GCM 认证标签长度固定为 128 bit
- [ ] 密码不以任何形式持久化（不写入文件、不记录日志）
- [ ] HMAC 比较使用 `hmac.compare_digest()`
- [ ] 文件写入使用 atomic write（`write-to-temp` + `os.rename`）
- [ ] 加载时先校验 HMAC 再解密
- [ ] 未知 `format_version` major 版本拒绝处理
- [ ] `_meta.kdf.memory_cost` 最小值检查（`>= 16384`）
- [ ] 错误消息不区分"密码错误"和"文件损坏"（对外统一提示）
- [ ] 应用 `secrets` 列表中的别名引用在解析时验证存在性

---

*文档版本: 3.0 | 格式版本: v2.0 | 更新时间: 2026-03-27*
*关联文档: [技术选型](./secrets_manager_tech_decision.md) · [调研报告](./secrets_manager_research.md) · [现状分析](./secrets_manager_codebase_analysis.md)*
