# Common Base Alignment

## Goal
Enva keeps its current product behavior compatible while using
`RustWebAppCommon` as the reusable base for repository structure, adapter
boundaries, static site workflows, and release/install/update-check contracts.

This document freezes the reimplementation boundary before deeper code changes
so future work can tell which capabilities should be reused, extended, or kept
inside Enva itself.

## Compatibility Oracles
- `README.md`
- `docs/README.md`
- `docs/agent-index.md`
- `crates/enva/tests/cli_integration.rs`
- `crates/enva/tests/static_pages.rs`
- `site/demo.html`
- `build.sh`
- `scripts/install.sh`
- `crates/enva/src/update.rs`

## Capability Map
| Surface | Current Enva contract | RustWebAppCommon baseline | Placement |
|---|---|---|---|
| Docs, Pages, static front door | `README.md`, `docs/README.md`, `site/` and Pages demo stay user-visible and stable | Shared docs/demo/site structure, Pages workflow, static shell patterns | `directly_reuse_from_common` |
| Release/install/update-check contracts | Asset naming, checksum flow, installer behavior, Pages/release workflows stay aligned | `scripts/build-release.sh`, `scripts/install.sh`, `scripts/update-check.sh`, release metadata contracts | `directly_reuse_from_common` |
| CLI dispatch layering | Keep Enva verbs and error semantics, but separate parsing, dispatch, and execution | `common_cli` split between vocabulary, dispatch, and adapters | `directly_reuse_from_common` |
| Binary self-update | `enva update` still supports tag selection, force rules, asset lookup, verification, and atomic replace | Common only provides update-check and release seams today | `extend_common_adapter_or_scripts` |
| Embedded UI and static demo parity | Embedded UI and `site/demo.html` must preserve key hooks and Pages paths | Common already generates `site/` and local HTTP shell, but not Enva's dual-surface parity model | `extend_common_adapter_or_scripts` |
| CLI integration test harness | Enva needs subprocess tests, fake release API coverage, and smoke-style assertions | Common currently focuses on static-site and contract tests | `extend_common_adapter_or_scripts` |
| Vault crypto and storage | AES-256-GCM, Argon2id, HMAC, vault format, migration, path/config resolution | Explicitly outside common scope | `keep_app_owned_in_enva` |
| Product CLI vocabulary | `enva`, `vault`, `serve`, `update`, `enva <APP>`, `--cmd` stay stable | Common keeps its own `common` command words | `keep_app_owned_in_enva` |
| Web API and remote flows | `/api` routes, SSH preview/review/sync, conflict handling, remote actions | No product API or SSH domain in common | `keep_app_owned_in_enva` |

## Non-Goals
- Do not move vault crypto, secret/app domain logic, or SSH sync semantics into
  `common_core`.
- Do not rename Enva commands to match `common dev/demo/docs/release`.
- Do not treat brand redesign or new product features as part of this
  reimplementation pass.

## Branching Strategy
- Enva implementation work happens on an Enva feature branch, currently
  `feat/reimpl-enva`.
- Shared requirements for `RustWebAppCommon` are tracked separately in
  `/home/agent/workspace/RustWebAppCommon/doc_auto/enva_gap_requirements.md`.
- If the common workspace is later checked out as a git repo, its changes should
  be made on a separate feature branch instead of mixing both repos into one
  branch.

## Handoff To RustWebAppCommon
If Enva discovers a missing reusable capability, record it as a common-side
requirement when all of the following are true:
- The behavior would help more than one product or starter repo.
- The change can live in adapters, scripts, workflows, or shared test scaffolds.
- The change does not require moving Enva-specific vault, SSH, or route semantics
  into `common_core`.

## Tracked Adoption Notes
- Use `docs/design/en/migration_adoption.md` as the tracked downstream handoff for
  Enva-side adoption, CI alignment, and closure criteria.
- Treat `.local/reimpl_for_enva.md` as a local aid only. It can help with
  historical context, but it is not required for clean clones or CI.
- `scripts/post_install_smoke.sh` is the canonical product smoke entry point for
  Enva installers. `scripts/install.sh` also accepts `RWC_POST_INSTALL_HOOK` as a
  compatibility alias when a cross-repo hook contract is needed.

## Web Shell Alignment
- `site/index.html`, `site/demo.html`, and `docs/design/demo/index.html` now use
  the same shell language as `RustWebAppCommon`: `shell`, `masthead`, `topnav`,
  status cards, and bordered neutral panels.
- `crates/enva/web/index.html` keeps its app-specific sidebar/topbar/product DOM,
  but its tokens, typography, borders, and panel treatment are aligned to the
  same neutral system.
- Visual alignment does not change Enva's product contracts: static demo parity
  hooks, embedded-only remote hooks, CLI vocabulary, and `/api` behavior remain
  owned by Enva.

## Last Updated
- 2026-04-02T07:11:49+00:00
