# Migration Adoption and Validation

## Goal
This document is the tracked handoff for Enva's downstream adoption of
`RustWebAppCommon` validation seams. It exists so clean clones, CI runners, and
future agents have a portable source of truth without depending on `.local/`
files.

## Tracked Truth Sources
- `README.md`
- `docs/README.md`
- `docs/agent-index.md`
- `docs/design/en/common_alignment.md`
- `crates/enva/tests/cli_integration.rs`
- `crates/enva/tests/static_pages.rs`
- `crates/enva/tests/reimplementation_oracle.rs`
- `site/demo.html`
- `build.sh`
- `scripts/install.sh`
- `scripts/post_install_smoke.sh`
- `.gitlab-ci.yml`
- `.github/workflows/deploy-pages.yml`

## Supplemental Local Reference
- `.local/reimpl_for_enva.md` may exist in a local workspace and can still help
  with historical context.
- It is not required for clean clones, CI, or tracked compatibility oracles.

## Common-Side Seams To Adopt Now
- `RWC_POST_INSTALL_HOOK` can be used as the compatibility hook variable for
  product post-install smoke.
- `ENVA_POST_INSTALL_HOOK` remains a product-specific alias for the same purpose.
- `build.sh`, installer behavior, asset naming, and updater expectations should
  keep matching the shared release/install/update-check contract documented on
  the common side.
- Common subprocess and mock release API harnesses should be treated as reusable
  patterns for product-side smoke and migration validation.
- If Enva finds a reusable upstream gap, record it in
  `/home/agent/workspace/RustWebAppCommon/doc_auto/enva_gap_requirements.md`.

## Product-Owned Validation
- Vault crypto, session handling, `/api` behavior, SSH preview/review/sync, and
  updater replacement policy remain product-owned.
- Shared import/export selection hooks must stay aligned across embedded and
  static demo surfaces.
- Embedded-only remote hooks remain embedded-only. `remote-option-list`,
  `remote-option-copy`, and `remoteActionError` are not required on
  `site/demo.html`.

## Immediate Adoption Sequence
1. Keep tracked docs and tests as the portable compatibility oracles.
2. Run installer smoke through `scripts/post_install_smoke.sh`, with
   `RWC_POST_INSTALL_HOOK` / `ENVA_POST_INSTALL_HOOK` available when a custom
   command is needed.
3. Keep GitHub and GitLab validation aligned on Rust tests, HTML checks, and
   product oracle coverage.
4. Reuse common-side harness patterns for release/update readiness checks before
   adding deeper product-specific scenarios.

## Later Roadmap
- in-process binary self-update beyond current readiness and product smoke
- signing and provenance
- deeper multi-platform native build depth
- native desktop shell evolution beyond the current browser-backed preview model

## Closure Criteria
- Enva no longer depends on `.local/` to pass tracked oracle checks.
- Installer, CI, and docs agree on the post-install smoke entry point.
- Product and common responsibilities stay explicit in docs and tests.

## Last Updated
- 2026-04-02T07:11:49+00:00
