use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn readme_freezes_common_reimplementation_contract() {
    let readme = fs::read_to_string(repo_root().join("README.md")).unwrap();

    assert!(readme.contains("docs/design/en/common_alignment.md"));
    assert!(readme.contains("enva update"));
    assert!(readme.contains("enva-linux-x86_64"));
    assert!(readme.contains("download size plus any SHA256 digest shipped in release metadata"));
}

#[test]
fn docs_index_links_common_alignment_and_live_demo() {
    let docs_index = fs::read_to_string(repo_root().join("docs").join("README.md")).unwrap();

    assert!(docs_index.contains("design/en/common_alignment.md"));
    assert!(docs_index.contains("design/en/migration_adoption.md"));
    assert!(docs_index.contains("../site/demo.html"));
    assert!(docs_index.contains("design/demo/index.html"));
}

#[test]
fn agent_index_tracks_common_boundary_and_remote_commands() {
    let agent_index = fs::read_to_string(repo_root().join("docs").join("agent-index.md")).unwrap();

    assert!(agent_index.contains("RustWebAppCommon"));
    assert!(agent_index.contains("app_owned"));
    assert!(agent_index.contains("enva update [--version <tag>] [--force]"));
    assert!(agent_index.contains("enva vault deploy --to"));
    assert!(agent_index.contains("enva vault sync-from --from"));
    assert!(agent_index.contains("--env <name>"));
    assert!(agent_index.contains("-P, --password <value>"));
}

#[test]
fn tracked_migration_doc_replaces_local_only_oracle_dependencies() {
    let migration_doc = fs::read_to_string(
        repo_root()
            .join("docs")
            .join("design")
            .join("en")
            .join("migration_adoption.md"),
    )
    .unwrap();

    assert!(migration_doc
        .contains("/home/agent/workspace/RustWebAppCommon/doc_auto/enva_gap_requirements.md"));
    assert!(migration_doc.contains("Embedded-only remote hooks remain embedded-only"));
    assert!(migration_doc.contains(".local/reimpl_for_enva.md"));
    assert!(migration_doc.contains("RWC_POST_INSTALL_HOOK"));
}

#[test]
fn release_scripts_keep_asset_contract_and_install_self_test() {
    let build_script = fs::read_to_string(repo_root().join("build.sh")).unwrap();
    let install_script =
        fs::read_to_string(repo_root().join("scripts").join("install.sh")).unwrap();
    let smoke_script =
        fs::read_to_string(repo_root().join("scripts").join("post_install_smoke.sh")).unwrap();

    for asset in [
        "enva-linux-x86_64",
        "enva-linux-aarch64",
        "enva-macos-aarch64",
    ] {
        assert!(build_script.contains(asset));
        assert!(install_script.contains(asset));
    }

    assert!(install_script.contains("RWC_POST_INSTALL_HOOK"));
    assert!(install_script.contains("ENVA_POST_INSTALL_HOOK"));
    assert!(install_script.contains("vault self-test"));
    assert!(smoke_script.contains("vault self-test"));
    assert!(smoke_script.contains("update --help"));
}

#[test]
fn pages_and_ci_workflows_keep_product_validation_guards() {
    let github_pages = fs::read_to_string(
        repo_root()
            .join(".github")
            .join("workflows")
            .join("deploy-pages.yml"),
    )
    .unwrap();
    let gitlab_ci = fs::read_to_string(repo_root().join(".gitlab-ci.yml")).unwrap();

    assert!(github_pages.contains("cargo test --workspace"));
    assert!(github_pages.contains("htmlhint@latest"));
    assert!(gitlab_ci.contains("cargo test --workspace --verbose"));
    assert!(gitlab_ci.contains("htmlhint@latest"));
}
