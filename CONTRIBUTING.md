# 「 Contributing to Enva 」

> YoRHa Env[A]rmament Unit — Contribution Protocol

Thank you for your interest in contributing to Enva. This document outlines the development workflow, coding standards, and submission process.

## 「 Development Environment 」

### Prerequisites

- [Rust](https://rustup.rs/) 1.85 or later
- Git

### Setup

```bash
git clone https://github.com/YoRHa-Agents/EnvA.git
cd EnvA
cargo build
cargo test --workspace
```

### Project Structure

| Crate | Purpose |
|-------|---------|
| `enva-core` | Core library: AES-256-GCM, Argon2id, HMAC-SHA256, vault crypto |
| `enva` | CLI binary (clap) + embedded Axum web UI |
| `site/` | GitHub Pages static site |

## 「 Branch Strategy 」

- `main` — protected, requires PR review
- `feat/<description>` — new features
- `fix/<description>` — bug fixes
- `docs/<description>` — documentation changes

Always branch from `main`. Never push directly to `main`.

## 「 Pull Request Process 」

1. Create a feature branch from `main`
2. Write or update tests for your changes
3. Ensure all checks pass:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace -- -D warnings
   cargo test --workspace
   ```
4. Open a PR with a clear description of what and why
5. Address review feedback

### PR Checklist

- [ ] Tests pass locally (`cargo test --workspace`)
- [ ] Code formatted (`cargo fmt --all`)
- [ ] No clippy warnings (`cargo clippy --workspace -- -D warnings`)
- [ ] Documentation updated if applicable
- [ ] Changelog entry added for user-facing changes

## 「 Code Style 」

### Rust

- Follow standard `rustfmt` formatting
- Use braces for all `if`/`else` branches (no single-line bodies)
- No silent error suppression — log, re-throw, or return explicit errors
- Prefer `thiserror` for error types
- Use `tracing` for structured logging

### Web UI

- The embedded web UI (`crates/enva/web/index.html`) is a single-file SPA
- Inline styles and scripts (no external build toolchain)
- Use CSS custom properties for theming

### Commit Messages

Use concise, imperative-mood messages:

```
add vault rename support
fix HMAC verification on empty vault
update SSH sync error handling
```

## 「 Testing 」

- Unit tests live alongside source code in `#[cfg(test)]` modules
- Integration tests are in `crates/enva/tests/`
- Run the full suite: `cargo test --workspace`
- Benchmarks: `cargo bench -p enva-core`

## 「 Reporting Issues 」

Use the [issue templates](https://github.com/YoRHa-Agents/EnvA/issues/new/choose) for bug reports and feature requests.

## 「 License 」

By contributing, you agree that your contributions will be licensed under the MIT License.

---

*Glory to Mankind.*
