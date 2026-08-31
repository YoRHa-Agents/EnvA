use std::fs;
use std::path::PathBuf;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn read_package_version() -> String {
    let manifest = fs::read_to_string(repository_root().join("Cargo.toml"))
        .expect("read workspace Cargo.toml");
    manifest
        .lines()
        .find_map(|line| {
            let value = line.strip_prefix("version = \"")?;
            value.strip_suffix('"').map(str::to_owned)
        })
        .expect("workspace version")
}

#[test]
fn release_surfaces_use_workspace_version() {
    let root = repository_root();
    let version = read_package_version();
    let tag = format!("v{version}");

    for relative in [
        "site/index.html",
        "site/demo.html",
        "crates/enva/web/index.html",
    ] {
        let content =
            fs::read_to_string(root.join(relative)).unwrap_or_else(|_| panic!("read {relative}"));
        assert!(content.contains(&tag), "{relative} does not contain {tag}");
    }

    for relative in [
        "npm/enva/package.json",
        "npm/enva-linux-x64/package.json",
        "npm/enva-linux-arm64/package.json",
        "npm/enva-darwin-arm64/package.json",
    ] {
        let content =
            fs::read_to_string(root.join(relative)).unwrap_or_else(|_| panic!("read {relative}"));
        let package: serde_json::Value =
            serde_json::from_str(&content).unwrap_or_else(|_| panic!("parse {relative}"));
        assert_eq!(
            package.get("version").and_then(serde_json::Value::as_str),
            Some(version.as_str()),
            "{relative} version is out of sync"
        );
    }
}
