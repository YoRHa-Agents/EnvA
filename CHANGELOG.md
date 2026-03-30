# Changelog

All notable changes to [Enva](https://github.com/YoRHa-Agents/EnvA) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-03-30

### Added

- **Branding**: Added SVG logo/icon assets for documentation and the embedded web UI favicon.
- **Demo media**: Added real web UI screenshots for login, dashboard overview, secret editing, and light theme presentation.

### Changed

- **README**: Refreshed the project landing section with a centered hero, spotlight summary, release badges, screenshot gallery, and build script guidance while keeping the technical reference sections intact.
- **Web UI**: Exposed `icon.svg` as an embedded static asset and added a focused test to ensure the favicon ships with the bundled web files.

## [0.1.0] - 2026-03-30

First stable release of the Enva CLI and vault tooling.

### Added

- **Vault**: Encrypted local vault (AES-256-GCM, Argon2id KDF, HMAC-SHA256 integrity) with alias-based secrets, per-app bindings, import/export, and `vault edit` for partial updates (key, value, description, tags).
- **CLI**: `enva` command-line interface for vault lifecycle, app injection (`enva <app> -- <cmd>`), and configuration under `~/.enva/`.
- **Web UI**: Built-in Axum web UI for vault management; authenticated HTTP API for apps, secrets (list/get/upsert/edit/delete), assignments, and login/session flow.
- **Core library**: `enva-core` crate for crypto, file store, and credential resolution.
- **Distribution**: `scripts/install.sh` for GitHub release binaries; root `build.sh` for parallel multi-platform release builds into `release/` (Linux x86_64/aarch64, macOS Apple Silicon).

### Notes

- Prebuilt binaries for this release: `enva-linux-x86_64`, `enva-linux-aarch64`, `enva-macos-aarch64`. Verify with `SHA256SUMS` attached to the GitHub release.

[Unreleased]: https://github.com/YoRHa-Agents/EnvA/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.1.1
[0.1.0]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.1.0
