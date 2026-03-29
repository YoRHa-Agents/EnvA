# Technology Selection Decision

> **摘要 (ZH):** 采用 **纯 Rust 实现**：`enva-core` 负责加密核心（Argon2id KDF + AES-256-GCM）与存储解析；`enva` 二进制负责配置、CLI、可选本地 Web UI（Axum）。用户通过 `cargo build --release` 或项目提供的安装脚本获取 `enva`。配置与状态目录默认为 `~/.enva/`。现有 Rust HKDF 路径保留用于 API-key 解析，与 vault 加密路径独立共存。

---

## 1. Decision Context

### Rust stack (`enva-core` + `enva`)

The `enva-core` crate implements the encryption and storage stack:

- `SecretsCrypto`: AES-256-GCM + **HKDF-SHA256** key derivation
- `FileSecretsStore`: JSON Lines format backend + atomic flush
- `Precedence` resolver: store-first / env-first strategies
- `AuthProfile`, `AuditEntry`, and other supporting modules
- Vault crypto (Argon2id + AES-256-GCM) in the Rust tree
- 30+ unit tests

**Critical distinction**: The existing HKDF-SHA256 derives sub-keys from high-entropy key material and is **unsuitable** for password-based derivation (no memory-hardness). The vault requires **Argon2id** (the password hashing algorithm recommended by RFC 9106, resistant to GPU/ASIC attacks).

### Workspace layout

- `crates/enva-core/`: library crate (`enva_core` in code)
- `crates/enva/`: CLI and embedded web UI, depends on `enva-core`

### CLI status

- The `enva` binary uses **clap** (derive API) for commands and flags
- Configuration resolves under **`~/.enva/`** (and project-level overlays per config reference)

---

## 2. Encryption Layer Selection

### Option A: Pure interpreted stack (not chosen)

**Stack**: External crates/bindings for Argon2id and AES-256-GCM outside a single Rust binary.

| Dimension | Assessment |
|-----------|------------|
| **Cross-platform** | Depends on packaging; no single statically reasoned memory model for secrets. |
| **Dev efficiency** | Fewer Rust lines, but weaker alignment with the rest of the workspace. |
| **Performance** | Argon2id is CPU-bound; AES-GCM performance matters less than KDF tuning. |
| **Maintainability** | Splits crypto across runtimes and ABI boundaries. |
| **Memory safety** | **Low** for a secrets tool: nondeterministic reclamation of plaintext outside Rust’s `secrecy` / `zeroize` patterns. |

### Option B: Extend `enva-core` only (library-only)

**Stack**: Argon2 + AES-GCM entirely in Rust; no first-party CLI.

| Dimension | Assessment |
|-----------|------------|
| **Cross-platform** | Same as any Rust library: build for the target triple. |
| **Dev efficiency** | Medium: crypto + store APIs without shipping a product surface. |
| **Performance** | Full Rust path, no foreign boundary for crypto. |
| **Maintainability** | Lower surface than a hybrid stack, but users still need an integration layer. |
| **Memory safety** | **High** with `secrecy::SecretString` + `zeroize`. |

### Option C: Full Rust product — `enva-core` + `enva` CLI (chosen)

**Stack**: Rust handles crypto core (Argon2id + AES-256-GCM), file store, resolver, CLI, and optional local Web UI.

| Dimension | Assessment |
|-----------|------------|
| **Cross-platform** | Release binaries or `cargo build --release` per target; CI can build on `ubuntu-latest`, `macos-*`, etc. Install script can ship prebuilt artifacts where policy allows. |
| **Dev efficiency** | Single language and workspace; shared types from `enva-core` through to CLI. |
| **Performance** | Encryption/decryption and KDF run in Rust with predictable allocation patterns. |
| **Maintainability** | **Medium-high**: one toolchain, clear crate boundaries (`enva-core` vs `enva`). |
| **Memory safety** | **High**: sensitive material handled with Rust crypto crates and explicit zeroization. |

### Comparison Matrix

| Dimension | Option A (interpreted crypto) | Option B (library only) | Option C (full Rust `enva`) |
|-----------|------------------------------|-------------------------|----------------------------|
| User install barrier | Varies | Depends on integrator | **Low–medium** (`cargo build --release` or install script) |
| Estimated dev effort | Lower initial Rust scope | Medium | Aligned with current repo |
| Runtime performance | Sufficient if tuned | Strong | **Strong** |
| Maintenance complexity | Higher (split stack) | Lower | **Controlled** |
| Memory safety (secret zeroing) | **Low** | High | **High** |
| Existing code reuse | Low | High | **High** (`enva-core`) |
| Foreign boundary complexity | High | None | **None** (crypto stays in Rust) |

### Decision: Option C (pure Rust `enva`)

**Rationale**:

1. **Memory safety is non-negotiable**: A secrets manager handles the user’s most sensitive data. Keeping KDF, AEAD, and vault parsing in Rust with `secrecy` + `zeroize` is the default posture for this project.
2. **Shipping is explicit**: Users build with `cargo build --release` or use the repository install script; CI can publish binaries for common targets.
3. **Single crate graph**: `enva` depends on `enva-core`; no split between a crypto DLL and a separate runtime for core logic.
4. **Reuses existing infrastructure**: The `enva-core` crate’s `aes-gcm`, `sha2`, `rand`, `base64`, `secrecy` dependencies stay central; Argon2id lives in the same codebase as the CLI.
5. **Performance**: The Rust `argon2` crate is appropriate for memory-hard work; AES-GCM stays in-tree.

---

## 3. CLI Framework Selection

### Decision: **clap** (derive)

- Declared in `crates/enva/Cargo.toml` with derive, color, and env features
- Provides subcommands, generated help, and typed arguments
- Integrates naturally with async Axum serving for optional local Web UI

---

## 4. Dependency Inventory

### Key Rust dependencies (`enva-core` / workspace)

| Crate | Role |
|-------|------|
| `argon2` | Argon2id password derivation |
| `aes-gcm` | AES-256-GCM (vault + existing HKDF-related paths as applicable) |
| `hkdf` | API-key HKDF derivation (existing path) |
| `secrecy` | Sensitive string wrapper |
| `zeroize` | Sensitive memory zeroing |
| `rand` | Random number generation |
| `base64` | Encoding/decoding |

### Application crate (`enva`)

| Crate | Role |
|-------|------|
| `clap` | CLI |
| `axum` / `tower-http` | Optional local Web UI and static assets |
| `jsonwebtoken` | JWT for local Web auth |
| `serde` / `serde_yaml` | Config |

---

## 5. Integration Path

```
┌─────────────────────────────────────────────────────────────┐
│ enva-core (library)                                          │
│ ├── crypto.rs (HKDF path)                                   │
│ ├── vault_crypto.rs (Argon2id + AES-GCM)                    │
│ ├── store.rs, resolver.rs, file_backend.rs, audit.rs, …     │
└──────────────────────────────┬──────────────────────────────┘
                               │ Rust API
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ enva (binary)                                                │
│ ├── CLI (clap)                                               │
│ ├── Config (~/.enva/ and overlays)                           │
│ ├── Optional Web UI (Axum, rust-embed)                       │
│ └── Shell-oriented workflows (documented in user guide)      │
└──────────────────────────────┬──────────────────────────────┘
                               │ environment injection
                               ▼
              User workloads (any language; e.g. apps that read `std::env` or
              their runtime’s equivalent for injected variables)
```

### Vault crypto API (Rust, in-process)

Callers inside the workspace use `enva_core` types and functions (for example `derive_key`, encrypt/decrypt helpers, salt generation, HMAC verification) directly from Rust—no foreign function boundary for the hot path.

### Integration modes

**Mode 1: Standalone**

- Install via `cargo build --release` (binary `target/release/enva`) or the project **`scripts/install.sh`** where provided.
- Manages vault under configured paths and injects environment variables via CLI, shell integration, or local Web UI as documented.

**Mode 2: Embedded in a larger platform**

- The same `enva` binary or `enva-core` as a dependency can be orchestrated by higher-level tooling; environment injection semantics stay consistent with standalone use.

---

*Document version: 3.0 | Updated: 2026-03-28 | Decision: Option C — pure Rust `enva` CLI with `enva-core` library*
