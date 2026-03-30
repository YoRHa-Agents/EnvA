# Changelog

All notable changes to [Enva](https://github.com/YoRHa-Agents/EnvA) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Vault sync**: Added `enva vault deploy --to user@host:/path` and `enva vault sync-from --from user@host:/path` for SSH/SFTP-based whole-vault transfer, with explicit overwrite handling and post-transfer validation.
- **Path UX**: Added absolute-path toggles and resolved-path previews in the web login, settings, and app edit flows so vault and application paths can be reviewed before saving.

### Changed

- **Path resolution**: Unified `--vault`, config `vault_path`, `vault init --vault`, and direct app launch `app_path` handling so `~`, relative, and absolute paths resolve consistently from the current working directory.
- **App launch fallback**: `apps.<name>.app_path` in `.enva.yaml` now serves as a direct-launch fallback when the vault-stored app path is empty.
- **Web settings**: Changing the selected vault path in the web UI now updates the backend session state and forces re-authentication so tokens stay bound to the active vault file.
- **Documentation**: Updated README, config references, API specs, and project config examples to match the implemented vault and app path semantics.

### Fixed

- **CLI flags**: Removed the `serve -p` short-flag collision with the global password flag so debug and release builds can start the web server consistently.

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
