# Changelog

All notable changes to [Enva](https://github.com/YoRHa-Agents/EnvA) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.5] - 2026-09-01

### Fixed

- **npm publishing now succeeds without a manual re-dispatch**: `release.yml` reached npm through `workflow_call`, and npm's trusted publishing validates the *calling* workflow, so the registry saw `release.yml` while the registered publisher names `npm-publish.yml` and rejected every automated publish with `ENEEDAUTH`. The release now dispatches `npm-publish.yml` as its own run — matching the identity the publisher expects — and watches it for the exit status, so a failed publish still turns the release red. `npm-publish.yml` no longer exposes a `workflow_call` trigger, and the run it dispatches is located by correlation id rather than by timestamp so a concurrent publish cannot be mistaken for it.

## [1.4.4] - 2026-09-01

### Changed

- **Crypto stack upgraded to the RustCrypto `digest` 0.11 generation**: `aes-gcm` 0.11, `argon2` 0.6, `hkdf` and `hmac` 0.13, `sha2` 0.11, and `rand` 0.10. The vault's on-disk format is unchanged — vaults written by earlier releases decrypt as-is, and values written by this release are still readable by 1.4.3, so downgrading stays safe.
- **Dependencies**: `criterion` 0.8, `jsonwebtoken` 11, `tower-http` 0.7, `base64` 0.23, and all GitHub Actions repinned to current releases.

### Added

- **Crypto known-answer vectors**: Argon2id key derivation, alias-bound AES-256-GCM ciphertexts, HMAC-SHA256 integrity tags, and HKDF-SHA256 payloads are now asserted byte-for-byte against vectors captured from a previous release. A dependency upgrade that would silently orphan existing vaults now fails CI instead.

### Fixed

- **Malformed vault IV**: A stored `ENC[...]` entry whose IV is the wrong length now reports an invalid ENC format instead of relying on a helper that panics.
- **v1.4.2 checksum manifest**: The published `SHA256SUMS` for v1.4.2 listed only one of the three binaries, under a stale `release/` path prefix. It has been regenerated in place; the binaries themselves are untouched.

## [1.4.3] - 2026-09-01

### Fixed

- **Release checksum manifest**: `SHA256SUMS` is now generated once after every platform binary is present, instead of separately by each build job where the second artifact download overwrote the first. The v1.4.2 manifest listed only one binary and prefixed it with a stale `release/` path; entries now use bare filenames so `shasum -a 256 -c SHA256SUMS` works directly in the download directory.
- **npm packaging on macOS**: `scripts/prepare-npm-packages.sh` no longer relies on a bash 4 associative array, which aborted on the macOS runner's bash 3.2.
- **Release automation permissions**: `auto-tag-release.yml` now requests the `actions: write` scope it needs to dispatch the release workflow, and `release-prep.yml` degrades to a manual compare link where organization policy forbids Actions from opening pull requests instead of failing the run.
- **Changelog ordering**: `scripts/bump_version.sh` inserts new release sections below `[Unreleased]` rather than above the file's introductory prose.

## [1.4.2] - 2026-08-31

### Added

- **npm distribution**: Enva is now installable with `npm install -g @yorha-agents/enva`. The main package is a thin shim that resolves a platform package (`@yorha-agents/enva-linux-x64`, `@yorha-agents/enva-linux-arm64`, `@yorha-agents/enva-darwin-arm64`) declared through `os`/`cpu` and `optionalDependencies`. Publishing runs on npm trusted publishing (OIDC) with build provenance.
- **GitHub Actions CI**: PR and `main` gates for `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, `cargo deny`, HTML lint, coverage floors, and benchmark compilation, aggregated behind a single `CI status` check. GitHub is now the sole authoritative CI; `.gitlab-ci.yml` was removed.
- **Three-stage release pipeline**: `release-prep.yml` bumps every version surface and opens a release branch, `auto-tag-release.yml` tags once the version lands on `main`, and `release.yml` cross-compiles all three targets, runs the macOS end-to-end suite against the real binary, publishes the GitHub Release, then hands off to `npm-publish.yml`.
- **Coverage, fuzz, and benchmark gates**: Blocking coverage floors for the workspace and `enva-core`, three `cargo-fuzz` targets (vault JSON parsing, import formats, key material), and a weekly benchmark run that archives criterion output.
- **Supply-chain policy**: `deny.toml` advisory/license/source policy, Dependabot for `cargo` and `github-actions`, and SHA-pinned third-party actions.
- **Version consistency test**: A Rust test asserts the crate version matches the marketing site, the embedded web UI, and all four npm manifests.

### Changed

- **Toolchain pinned to Rust 1.98.0** via `rust-toolchain.toml`, with workspace-level lints (`unsafe_code = "forbid"`) inherited by both crates, and MSRV documentation updated to match.
- **`jsonwebtoken` now uses the `aws_lc_rs` backend** instead of `rust_crypto`, dropping the vulnerable `rsa` dependency.

### Fixed

- **`enva update` under npm**: Updating a binary installed through npm now warns and points at `npm update -g @yorha-agents/enva` rather than silently replacing a package-managed file. `--force` bypasses the guard.
- **Environment-dependent config tests** no longer race on process-global environment variables when the suite runs in parallel.
- **Single-platform builds**: `build.sh` resolves one explicitly requested target instead of failing on an empty deduplication result.

## [1.4.1] - 2026-04-12

### Fixed

- **Sticky table headers**: All column headers now remain visible while scrolling. A CSS specificity bug (`position: relative` on sortable headers overriding `position: sticky`) caused sortable columns to scroll away while non-sortable ones stayed pinned.
- **Export modal layout**: Relocated the tag filter control to the Select All / Clear All row and made the search box full-width standalone, eliminating horizontal overflow on narrow viewports.

### Added

- **Copy value button**: Each secret row now has a clipboard icon that copies the decrypted value without needing to reveal it first. Uses Clipboard API with textarea fallback.
- **Responsive modal handling**: Added `@media (max-width: 640px)` breakpoint constraining modals to 95vw with tighter action row gaps.
- **Accessibility improvements**: Eye toggle buttons now carry dynamic `title` attributes ("Reveal value" / "Hide value"); added missing `filterTags` i18n key to both EN and ZH locales.

## [1.4.0] - 2026-04-08

### Added

- **Export tag filter**: The export modal now includes tag-based filtering with Any/All matching so operators can isolate the subset they want to export without scrolling the full scope.
- **Export keyword search**: The export modal now supports keyword search across aliases, injected keys, descriptions, and tags to locate export targets faster.

### Changed

- **Filtered export bulk actions**: Select/Clear All now applies to the visible filtered export list while preserving any selections outside the current filter, and the GitHub Pages demo keeps the same control surface as the embedded UI.

## [1.3.0] - 2026-04-07

### Added

- **Column sorting**: Click any column header (Alias, Key, Tags, Used By, Updated) in the All Secrets view to sort ascending/descending. Sort state persists across sessions via localStorage. Includes keyboard accessibility (Enter/Space to toggle) and ARIA sort attributes.
- **Tag checkbox filter**: New "Tags" filter button in the toolbar opens a dropdown with checkboxes for each tag. Supports AND/OR mode toggle. Filter state persists across sessions. Shows active filter count badge. Close with Escape or outside click.

### Changed

- **UI-Pro polish**: Sort headers show animated arrow indicators, tag filter dropdown has smooth open/close transitions, all interactive elements have visible focus states per WCAG guidelines.

## [1.2.0] - 2026-04-07

### Added

- **Environment variable interpolation**: Secret values can now reference earlier secrets using `$VAR` or `${VAR}` syntax. Variables are resolved in the app's secret list order during injection — if A=aaa and B=$A, then B resolves to aaa. Unknown references resolve to empty string; `\$` escapes a literal dollar sign. Falls back to OS environment variables.
- **Secret reordering**: New `PUT /api/apps/{app}/secrets/order` endpoint to reorder secrets within an app. The web UI app view now includes drag handles for reordering secrets via drag-and-drop — order is saved automatically.
- **Drag-and-drop UI**: When viewing a specific app's secrets, a grip handle appears on each row. Drag rows to reorder; the new order is persisted immediately via the API.

### Fixed

- **Table header spacing**: Removed extra top padding on the secrets table container so the column headers sit flush against the toolbar.

## [1.1.0] - 2026-04-06

### Added

- **Version display**: The static GitHub Pages site and the embedded web UI now show the current release version. A public `/api/version` endpoint returns the compiled version without authentication.
- **Port persistence**: `enva` (no subcommand) reads the last successfully used port from `~/.enva/last_port`, falling back to `web.port` in config (default 8080). Every serve invocation saves the port for next time.
- **Auto-open browser**: `enva` and `enva serve` now open the default browser automatically on startup. Use `enva serve --no-open` to suppress.
- **Web UI self-update**: The Settings panel can now check for updates *and* apply them directly (`POST /api/update/apply`), replacing the previous "run `enva update` in your shell" message.

### Changed

- **Documentation sync**: README, English and Chinese user guides, API specs, config references, deployment guides, agent index, and GitHub Pages site updated to reflect port persistence, `--no-open`, web UI update flow, and corrected `enva vault self-test` command references.

## [1.0.0] - 2026-04-02

### Added

- **Tracked migration adoption guide**: Added `docs/design/en/migration_adoption.md` so Enva's downstream adoption of `RustWebAppCommon` validation seams has a tracked, portable handoff instead of relying on `.local/` notes.
- **Post-install smoke script**: Added `scripts/post_install_smoke.sh` as the canonical Enva product smoke entry point for installed binaries.
- **Product validation oracle coverage**: Expanded `reimplementation_oracle.rs` to cover tracked migration adoption docs, installer hook compatibility, and product CI gate expectations.

### Changed

- **Web shell alignment**: Restyled the GitHub Pages landing, live demo, embedded web UI, and design demo to use the neutral shell language shared with `RustWebAppCommon` while preserving Enva-specific workflows and parity hooks.
- **Installer hook compatibility**: `scripts/install.sh` now accepts `ENVA_POST_INSTALL_HOOK` and `RWC_POST_INSTALL_HOOK`, running product smoke through a unified post-install seam.
- **Product gate alignment**: Tightened GitHub Pages and GitLab validation so Rust tests, HTML validation, and tracked oracle expectations stay closer to the release validation bar.
- **Documentation front door**: Refreshed README, docs index, agent index, and common-alignment docs to describe the shared shell, tracked adoption notes, and portable truth sources.

### Fixed

- **Local-only oracle dependency**: Replaced `.local` as the only compatibility-oracle source in tracked tests with a checked-in migration adoption document so clean clones and CI do not depend on ignored workspace notes.

## [0.6.1] - 2026-04-01

### Fixed

- **Remote action modal alignment**: Fixed the remote deploy/sync option checkboxes so labels align correctly in the embedded web UI instead of being pushed to the far edge of the modal.
- **Inline remote validation**: Added an in-modal remote action error area so host/path/password validation stays visually aligned with the remote action form.

## [0.6.0] - 2026-04-01

### Added

- **Dedicated command mode**: Added `enva --cmd "<command>" <app>` so arbitrary command injection stays available while direct app launches use a clearer argv-forwarding path.
- **Static page coverage**: Added `static_pages.rs` smoke tests to keep the embedded web UI and browser demo import/export selection controls in sync.
- **Release branding exports**: Added PNG project icon, social preview, and YoRHa avatar assets for GitHub/social release surfaces.

### Changed

- **App launch argv**: `enva <APP> [ARGS...]` now forwards trailing arguments directly to the configured `app_path`, including flag-like args and a literal `--`.
- **Bundle import merge behavior**: Portable bundle imports now preserve existing app bindings instead of clearing them before applying imported bindings.
- **Import/export UX**: Expanded the embedded web UI and demo with row selection, conflict summaries, and replace-existing controls before import/export actions.
- **Documentation**: Updated the README, agent index, and EN/ZH design docs to reflect the new launch contract and release-facing workflows.

### Fixed

- **Launch mode argument passing**: Direct application launches no longer misinterpret trailing arguments as a replacement command.

## [0.5.0] - 2026-04-01

### Added

- **Portable bundle formats**: Added `enva-json` and `yaml` bundle import/export formats so Enva data can be moved between instances without manual conversion.
- **Shared transfer layer**: Added a centralized import/export module to keep CLI, API, web UI, and demo format handling aligned.
- **Import/export coverage**: Added CLI and web route regression tests for bundle round-trips, unsupported format validation, and cross-surface format behavior.

### Changed

- **CLI import/export**: `enva vault export` now supports `env`, flat `json`, `enva-json`, and `yaml`; `enva vault import` now imports flat env/json files or bundle files with inferred or explicit formats.
- **Web UI and demo**: Expanded import/export selectors and previews to cover `.env`, flat JSON, Enva JSON bundles, and YAML bundles with matching terminology across both surfaces.
- **Documentation**: Updated README, agent index, API specs, and user guides to reflect the new format matrix and command vocabulary.

## [0.4.0] - 2026-03-31

### Added

- **GitHub Pages site**: Static landing page at `yorha-agents.github.io/EnvA/` with feature overview, installation guide, and quickstart — built with NieR:Automata design language.
- **Interactive demo**: Browser-based vault simulation at `demo.html` with full CRUD workflow, localStorage persistence, pre-seeded example data, and simulated CLI output.
- **NieR:Automata branding**: New SVG logo, icon, and banner in YoRHa military style (gold/black/ivory palette, lock motif, corner brackets, diamond decorations).
- **Design language spec**: `docs/assets/branding/BRANDING.md` with complete palette, typography (EB Garamond + Jost + Share Tech Mono), WCAG AA contrast ratios, spacing, and decoration reference.
- **GitHub Actions**: `deploy-pages.yml` workflow for automatic site deployment with HTML validation.
- **Community files**: `CONTRIBUTING.md`, issue templates (bug report, feature request), and PR template.

### Changed

- **Web UI restyle**: Migrated the embedded product web UI from indigo/Outfit to NieR:Automata gold/Jost design language — CSS-only changes with zero JavaScript modifications. Dark theme uses black/gold/ivory; light theme uses parchment/amber.
- **README rewrite**: Updated with NieR narrative style, new banner, demo links, SVG mock screenshots, and restructured documentation links.
- **Favicon**: Updated `icon.svg` to NieR-style lock icon with corner brackets.
- **Border radius**: Reduced from 8px/12px to 2px/4px across all UI components for sharper NieR aesthetic.

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

[Unreleased]: https://github.com/YoRHa-Agents/EnvA/compare/v1.4.5...HEAD
[1.4.5]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v1.4.5
[1.4.4]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v1.4.4
[1.4.3]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v1.4.3
[1.4.2]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v1.4.2
[1.4.1]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v1.4.1
[1.4.0]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v1.4.0
[1.3.0]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v1.3.0
[1.2.0]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v1.2.0
[1.1.0]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v1.1.0
[1.0.0]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v1.0.0
[0.6.1]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.6.1
[0.6.0]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.6.0
[0.5.0]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.5.0
[0.4.0]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.4.0
[0.3.0]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.3.0
[0.2.0]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.2.0
[0.1.2]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.1.2
[0.1.1]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.1.1
[0.1.0]: https://github.com/YoRHa-Agents/EnvA/releases/tag/v0.1.0
