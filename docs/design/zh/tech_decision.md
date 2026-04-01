# 技术选型决策文档 (Technology Selection Decision)

> **Summary (EN):** **Pure Rust:** `enva-core` provides the crypto core (Argon2id KDF + AES-256-GCM), file store, and precedence resolver; the `enva` binary provides CLI (`clap`), configuration under `~/.enva/`, shell integration, and an embedded Axum web UI. Build with `cargo build --release` or use the repository `scripts/install.sh`. The existing Rust HKDF path remains for API-key resolution, coexisting with the vault crypto path.

---

## 1. 决策背景

### 现有 Rust 基础设施

`enva-core` crate 已实现完整加密栈：

- `SecretsCrypto`: AES-256-GCM + **HKDF-SHA256** 密钥派生
- `FileSecretsStore`: JSON Lines 格式后端 + atomic flush
- `Precedence` resolver: store-first / env-first 策略
- `AuthProfile`, `AuditEntry` 等辅助模块
- 30+ 单元测试

**关键差异**: 现有 HKDF-SHA256 用于从高熵密钥材料派生子密钥，**不适用于**密码派生场景（无 memory-hardness）。新 vault 需要 **Argon2id**（RFC 9106 推荐的密码哈希算法，抗 GPU/ASIC）。

### Rust 单体架构

- 工作区以 `Cargo.toml` 编排 `enva-core` 与 `enva`
- CLI、配置合并、Web 均在 `crates/enva` 中实现，无跨语言绑定层

### CLI 现状

- `enva` 使用 `clap` 派生子命令与参数校验
- 配置文件发现与合并逻辑与 `~/.enva/` 约定一致

---

## 2. 加密层选型

### 方案 A: 依赖外部解释型生态（对比，未采用）

**技术栈**: 第三方 Argon2 + GCM 绑定库（常见于其他语言的包管理器）

| 维度 | 评估 |
|------|------|
| **跨平台** | 依赖各平台预构建二进制或本地编译工具链。 |
| **开发效率** | 高，但与本仓库 Rust 核心分裂。 |
| **性能** | Argon2id CPU 密集；GCM 通常走原生实现。 |
| **维护性** | 多语言、多发布物，同步成本高。 |
| **内存安全** | 解释型运行时 GC 难以保证敏感缓冲区及时清零。 |

### 方案 B: 仅扩展库、多前端（未采用）

**技术栈**: 在 `enva-core` 中增加 `argon2` 等，同时为多种宿主暴露 FFI 或绑定

| 维度 | 评估 |
|------|------|
| **跨平台** | 各绑定需独立构建与分发流程。 |
| **开发效率** | 需维护多语言边界与类型映射。 |
| **性能** | 全 Rust 核心路径性能优，跨进程/跨语言调用有额外开销。 |
| **维护性** | 高：Rust 核心 + 多套兼容层。 |

### 方案 C: **纯 Rust 单体（当前）**

**技术栈**: `enva-core` 内 Argon2id + AES-256-GCM；`enva` 负责 I/O、CLI、Web

| 维度 | 评估 |
|------|------|
| **跨平台** | `cargo build --release` 针对目标三元组构建；CI 可产出各平台二进制，或使用 `scripts/install.sh` 引导从源码安装。 |
| **开发效率** | 单一语言与 Cargo 工作区；加密与业务同仓迭代。 |
| **性能** | 加密、解析、网络均在 Rust 中，无非必要边界。 |
| **维护性** | 中低：模块边界在 crate 与模块级即可。 |
| **内存安全** | 高。`secrecy::SecretString`、`zeroize` 等可用于敏感数据生命周期。 |

### 选型对比

| 维度 | 方案 A（外部生态） | 方案 B（库 + 多前端） | 方案 C（纯 Rust 单体） |
|------|-------------------|----------------------|----------------------|
| 用户安装门槛 | 视上游包而定 | 中（多产物） | **中**（Rust 工具链源码构建，或预构建 `enva` 二进制） |
| 开发工时 | 因拆分而重复 | 高 | **与单仓一致** |
| 运行时性能 | 足够 | 优 | **优** |
| 维护复杂度 | 分散 | 高 | **相对集中** |
| 内存安全（secret 清零） | 弱 | 高（Rust 核心） | **高** |
| 现有代码复用 | 低 | 高 | **高（`enva-core` 全栈复用）** |
| 跨语言绑定复杂度 | 无 | 高 | **无** |

### 决策: 方案 C（纯 Rust）

**理由**:

1. **内存安全**：密钥管理器处理最敏感数据；在 Rust 内用 `secrecy` + `zeroize` 统一策略。
2. **分发清晰**：以 `cargo build --release` 与仓库内 `scripts/install.sh` 为主，单一构建故事。
3. **无绑定层**：`vault_crypto` 等逻辑直接作为 `enva-core` 模块被 `enva` 调用，存储与 JSON vault 同进程完成。
4. **复用基础设施**：`enva-core` 的 `aes-gcm`、`sha2`、`rand`、`base64`、`secrecy` 等依赖延续使用，并补充 `argon2` 等。
5. **性能**：Memory-hard 与 AEAD 均在 Rust 中原生执行。

---

## 3. CLI 框架选型

### 决策: `clap`（Rust）

- `enva` 二进制使用 `clap` 子命令、派生宏与 `--help`
- 与 Axum、`jsonwebtoken` 等同属 Rust 生态，无额外解释器依赖

---

## 4. 依赖清单

### Rust 核心依赖（`enva-core` / 工作区）

| Crate | 版本 | 用途 |
|-------|------|------|
| `argon2` | `>=0.5` | Argon2id 密码派生 |
| `zeroize` | `>=1.7` | 敏感内存清零 |

### `enva` 二进制（CLI / Web）

| Crate | 用途 |
|-------|------|
| `clap` | CLI |
| `axum` / `tower-http` | Web API 与静态资源 |
| `jsonwebtoken` | JWT 认证 |
| `serde_yaml` / `dirs` 等 | 配置与路径解析（含 `~/.enva/`） |

### 保持不变的 Rust 依赖（`enva-core`）

| Crate | 用途 | 关系 |
|-------|------|------|
| `aes-gcm 0.10` | AES-256-GCM（现有 + vault 复用） | 共享 |
| `hkdf 0.12` | API-key HKDF 派生（现有路径） | 独立 |
| `secrecy 0.10` | 敏感字符串封装 | 共享 |
| `rand 0.8` | 随机数生成 | 共享 |
| `base64 0.22` | 编解码 | 共享 |

---

## 5. 集成路径

```
enva-core（库）                              enva（二进制）
┌──────────────────────────┐                ┌──────────────────────┐
│ enva-core                │                │ Vault / store I/O    │
│ ├── crypto.rs (HKDF路径) │◄── crate 依赖 ─│ ├── JSON vault CRUD   │
│ ├── vault_crypto.rs      │                │ ├── HMAC 校验         │
│ │   ├── derive_key()     │                │ └── 原子写           │
│ │   ├── encrypt_value()  │                │                       │
│ │   ├── decrypt_value()  │                │ 配置加载              │
│ │   ├── generate_salt()  │                │ ├── 多层配置合并       │
│ │   └── verify_hmac()    │                │ └── XDG (~/.enva/)   │
│ ├── store.rs             │                │                       │
│ ├── resolver.rs          │                │ CLI (clap)            │
│ └── audit.rs             │                │ Shell 集成             │
└──────────────────────────┘                │ Web (Axum)            │
                                            └──────────┬────────────┘
                                                       │ 环境变量注入
                                                       ▼
                                    ┌──────────────────────────────────────┐
                                    │ 独立运行: enva X [ARGS...] / --cmd "cmd" X │
                                    │ 宿主应用可通过环境变量读取密钥（任意语言）│
                                    └──────────────────────────────────────┘
```

### 库内接口（Rust）

加密与 vault 辅助由 `enva_core` 导出，供 `enva` 与集成测试直接 `use`，无 FFI。

### 集成模式

**模式一：独立使用**

- 源码构建：`cargo build --release`，将 `target/release/enva` 加入 `PATH`
- 或使用仓库 `scripts/install.sh`（见部署/用户文档）
- 通过 CLI、Shell hook 或 Web 管理 vault；配置目录默认为 `~/.enva/`

**模式二：与工作流集成**

- 通过 `enva <APP> [ARGS...]`、`enva --cmd "<command>" <APP>` 或 shell hook 向子进程注入环境变量
- 宿主应用（可用任意语言编写）通过各自运行时的环境变量 API 读取，无需绑定 `enva_core`

---

*文档版本: 3.0 | 更新时间: 2026-04-01 | 决策: 纯 Rust 单体（`enva` CLI + `enva-core` 库）*
