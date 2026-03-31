# Changelog

All notable changes to [Enva](https://github.com/YoRHa-Agents/EnvA) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-03-31

### Added

- **Self-update CLI**: Added `enva update [--version <tag>] [--force]` to download the matching release binary from GitHub Releases, verify the asset size / SHA256 digest, and atomically replace the installed executable.
- **Remote vault preview**: Added `POST /api/ssh/remote-preview` plus web UI support for inspecting remote secrets, apps, and bindings before running sync/deploy actions.
- **Selective remote actions**: Added `POST /api/ssh/selective-sync` and `POST /api/ssh/selective-deploy` so the web UI can merge only selected secrets/apps (and optional bindings) instead of replacing the whole vault.
- **Web-managed SSH hosts**: Added `POST` / `PUT` / `DELETE /api/ssh/hosts` backed by `~/.enva/ssh_hosts.json`, merged with parsed `~/.ssh/config` entries for a single host list.
- **Vault diff/merge endpoints**: Added `POST /api/ssh/sync-preview` and `POST /api/ssh/sync-merge` to support the diff/merge review workflow from the web UI.
- **Update check endpoint**: Added `GET /api/update/check` returning current/target version and platform asset information.

### Changed

- **Web remote UX**: Expanded the `Remote` modal to support host CRUD, remote preview, selective sync/deploy, and diff/merge review without leaving the dashboard.
- **Settings UX**: Added a settings-panel update check powered by `/api/update/check` so operators can see when a newer release is available for the current platform.
- **Vault merge API**: Extended `merge_from` with optional `selected_secret_aliases` and `selected_app_names` filter parameters; `None` preserves existing full-merge behavior.
- **Dependencies**: Added `reqwest` (rustls-tls), `semver`, `sha2`, and `mockito` (dev) to the `enva` crate.

## [0.2.0] - 2026-03-31

### Added

- **Web SSH management**: Added browser-driven SSH host discovery from `~/.ssh/config`, explicit host-list refresh, and web `deploy` / `sync-from` flows that reuse the existing validated SSH/SFTP transport.
- **Rename-safe identity**: Added immutable internal ids for secrets and applications so aliases and app names can be edited without breaking assignments, overrides, or env injection.
- **Release coverage**: Added migration, rename, SSH route, and CLI injection regressions to cover the new release surface end to end.

### Changed

- **Vault format**: Upgraded the runtime vault format to `2.1`, preserving alias- and app-name keyed UX while normalizing internal app secret references to stable ids on save.
- **Web UX**: Expanded the built-in web UI with a `Remote` modal for SSH actions plus editable secret aliases and application names.
- **Documentation**: Updated the README and vault format specifications to document the SSH workflow, stable-id migration model, and rename semantics.

### Fixed

- **Alias rename safety**: Secret alias renames now re-encrypt the ciphertext with the new alias-bound AAD so decrypted values remain valid after save.
- **Binding persistence**: Secret and app renames now preserve override mappings, assigned secret references, and command injection behavior instead of orphaning them.

## [0.1.2] - 2026-03-30

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

[Unreleased]: https://github.com/YoRHa-Agents/EnvA/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.3.0
[0.2.0]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.2.0
[0.1.2]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.1.2
[0.1.1]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.1.1
[0.1.0]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.1.0
