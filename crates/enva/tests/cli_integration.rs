mod common;

use common::{
    create_test_vault, enva_cmd, rename_app_in_vault, rename_secret_in_vault, vault_assign,
    vault_assign_with_override, vault_set,
};
use mockito::Server;
use predicates::prelude::*;
use sha2::{Digest, Sha256};
use std::fs;

#[test]
fn help_shows_enva_branding() {
    enva_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Enva"))
        .stdout(predicate::str::contains("enva <APP>"))
        .stdout(predicate::str::contains("vault"));
}

#[test]
fn serve_help_shows_short_port_flag() {
    enva_cmd()
        .args(["serve", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("-p, --port"))
        .stdout(predicate::str::contains("--host"));
}

#[test]
fn vault_init_creates_file() {
    let tmp = tempfile::tempdir().unwrap();
    let vault_path = create_test_vault(tmp.path(), "testpass123");
    assert!(vault_path.exists());
    let content = fs::read_to_string(&vault_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(parsed.get("_meta").is_some());
    assert!(parsed.get("secrets").is_some());
    assert!(parsed.get("apps").is_some());
}

#[test]
fn vault_init_expands_tilde_path() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();

    enva_cmd()
        .current_dir(tmp.path())
        .env("HOME", &home)
        .args([
            "vault",
            "init",
            "--vault",
            "~/tilde.vault.json",
            "--password-stdin",
        ])
        .write_stdin("testpass123\n")
        .assert()
        .success();

    assert!(home.join("tilde.vault.json").exists());
}

#[test]
fn vault_set_get_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "testpass", "my-secret", "MY_VAR", "secret_value");

    enva_cmd()
        .args(["vault", "get", "my-secret"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("secret_value"));
}

#[test]
fn vault_list_shows_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(
        vps,
        "testpass",
        "db-url",
        "DATABASE_URL",
        "postgres://localhost",
    );

    enva_cmd()
        .args(["vault", "list"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("db-url"))
        .stdout(predicate::str::contains("DATABASE_URL"));
}

#[test]
fn app_injection_dry_run() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "testpass", "api-key", "API_KEY", "k3y123");
    vault_assign(vps, "testpass", "api-key", "backend");

    enva_cmd()
        .args(["--vault", vps, "--password-stdin", "backend"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("API_KEY"))
        .stdout(predicate::str::contains("<redacted>"));
}

#[cfg(unix)]
#[test]
fn relative_vault_path_and_config_app_path_launch() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let vault_rel = "./relative.vault.json";

    enva_cmd()
        .current_dir(tmp.path())
        .args(["vault", "init", "--vault", vault_rel, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success();

    enva_cmd()
        .current_dir(tmp.path())
        .args([
            "vault",
            "set",
            "launch-secret",
            "-k",
            "RELATIVE_APP_SECRET",
            "-V",
            "launched-from-relative",
        ])
        .args(["--vault", vault_rel, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success();

    enva_cmd()
        .current_dir(tmp.path())
        .args(["vault", "assign", "launch-secret", "--app", "relapp"])
        .args(["--vault", vault_rel, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success();

    let bin_dir = tmp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let script_path = bin_dir.join("print-secret.sh");
    fs::write(
        &script_path,
        "#!/bin/sh\nprintf '%s' \"$RELATIVE_APP_SECRET\"\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script_path, permissions).unwrap();

    fs::write(
        tmp.path().join(".enva.yaml"),
        "apps:\n  relapp:\n    app_path: \"./bin/print-secret.sh\"\n",
    )
    .unwrap();

    enva_cmd()
        .current_dir(tmp.path())
        .args(["--vault", vault_rel, "--password-stdin", "relapp"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("launched-from-relative"));
}

#[test]
fn app_injection_exec() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(
        vps,
        "testpass",
        "test-var",
        "TEST_ENVA_VAR",
        "injected_value",
    );
    vault_assign(vps, "testpass", "test-var", "myapp");

    enva_cmd()
        .args([
            "--vault",
            vps,
            "--password-stdin",
            "myapp",
            "--",
            "printenv",
            "TEST_ENVA_VAR",
        ])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("injected_value"));
}

#[test]
fn renamed_secret_alias_preserves_dry_run_and_exec_injection() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "testpass", "db", "DATABASE_URL", "postgres://renamed");
    vault_assign_with_override(vps, "testpass", "db", "backend", "BACKEND_DB");
    rename_secret_in_vault(vps, "testpass", "db", "primary-db");

    enva_cmd()
        .args(["--vault", vps, "--password-stdin", "backend"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("BACKEND_DB"))
        .stdout(predicate::str::contains("<redacted>"));

    enva_cmd()
        .args([
            "--vault",
            vps,
            "--password-stdin",
            "backend",
            "--",
            "printenv",
            "BACKEND_DB",
        ])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("postgres://renamed"));

    enva_cmd()
        .args(["vault", "get", "primary-db"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("postgres://renamed"));

    enva_cmd()
        .args(["vault", "get", "db"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .failure();
}

#[test]
fn renamed_app_name_preserves_exec_injection_for_new_name() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "testpass", "api-key", "API_KEY", "renamed-app-secret");
    vault_assign_with_override(vps, "testpass", "api-key", "backend", "RENAMED_KEY");
    rename_app_in_vault(vps, "testpass", "backend", "api-service");

    enva_cmd()
        .args([
            "--vault",
            vps,
            "--password-stdin",
            "api-service",
            "--",
            "printenv",
            "RENAMED_KEY",
        ])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("renamed-app-secret"));

    enva_cmd()
        .args(["--vault", vps, "--password-stdin", "backend"])
        .write_stdin("testpass\n")
        .assert()
        .failure();
}

#[test]
fn vault_self_test_passes() {
    enva_cmd()
        .args(["vault", "self-test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("All checks passed"));
}

#[test]
fn vault_delete_removes_secret() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "testpass", "to-delete", "DEL_VAR", "val");

    enva_cmd()
        .args(["vault", "delete", "to-delete", "--yes"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success();

    enva_cmd()
        .args(["vault", "get", "to-delete"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .failure();
}

#[test]
fn vault_unassign_removes_from_app() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "testpass", "s1", "S1_KEY", "val1");
    vault_assign(vps, "testpass", "s1", "myapp");

    enva_cmd()
        .args(["vault", "unassign", "s1", "--app", "myapp"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success();

    enva_cmd()
        .args(["--vault", vps, "--password-stdin", "myapp"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("No secrets assigned"));
}

#[test]
fn vault_export_env_format() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "testpass", "ex-key", "EXPORT_VAR", "export_val");
    vault_assign(vps, "testpass", "ex-key", "exapp");

    enva_cmd()
        .args(["vault", "export", "--app", "exapp"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("export EXPORT_VAR="));
}

#[test]
fn vault_export_json_format() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "testpass", "jk", "JSON_KEY", "json_val");
    vault_assign(vps, "testpass", "jk", "jsonapp");

    let output = enva_cmd()
        .args(["vault", "export", "--app", "jsonapp", "--format", "json"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(parsed["JSON_KEY"], "json_val");
}

#[test]
fn vault_edit_updates_key() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "testpass", "edit-me", "OLD_KEY", "the-value");

    enva_cmd()
        .args(["vault", "edit", "edit-me", "--key", "NEW_KEY"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Updated"))
        .stdout(predicate::str::contains("key"));

    enva_cmd()
        .args(["vault", "list"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("NEW_KEY"));

    enva_cmd()
        .args(["vault", "get", "edit-me"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("the-value"));
}

#[test]
fn vault_edit_updates_value() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "testpass", "val-edit", "MY_KEY", "old-secret");

    enva_cmd()
        .args(["vault", "edit", "val-edit", "--value", "new-secret"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success();

    enva_cmd()
        .args(["vault", "get", "val-edit"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("new-secret"));
}

#[test]
fn vault_edit_nonexistent_alias_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    enva_cmd()
        .args(["vault", "edit", "no-such", "--key", "K"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .failure();
}

#[test]
fn vault_edit_no_flags_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "testpass", "s1", "K", "v");

    enva_cmd()
        .args(["vault", "edit", "s1"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Nothing to edit"));
}

#[test]
fn vault_import_env_file() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    let env_file = tmp.path().join(".env");
    fs::write(&env_file, "IMPORT_KEY=import_value\nANOTHER=val2\n").unwrap();

    enva_cmd()
        .args([
            "vault",
            "import-env",
            "--from",
            env_file.to_str().unwrap(),
            "--app",
            "imported",
        ])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Imported 2 secrets"));

    enva_cmd()
        .args(["vault", "list", "--app", "imported"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("IMPORT_KEY"));
}

#[test]
fn vault_list_with_app_filter() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "testpass", "a1", "A1", "v1");
    vault_set(vps, "testpass", "a2", "A2", "v2");
    vault_assign(vps, "testpass", "a1", "filtered-app");

    enva_cmd()
        .args(["vault", "list", "--app", "filtered-app"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("a1"))
        .stdout(predicate::str::contains("A1"));
}

#[test]
fn wrong_password_exits_with_error() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "correctpass");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "correctpass", "s1", "K1", "v1");

    enva_cmd()
        .args(["vault", "get", "s1"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("wrongpass\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn missing_vault_file_exits_with_error() {
    enva_cmd()
        .args(["vault", "list"])
        .args([
            "--vault",
            "/nonexistent/path/vault.json",
            "--password-stdin",
        ])
        .write_stdin("pw\n")
        .assert()
        .failure();
}

#[test]
fn version_flag_shows_version() {
    enva_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("enva"));
}

#[test]
fn vault_help_shows_subcommands() {
    enva_cmd()
        .args(["vault", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("set"))
        .stdout(predicate::str::contains("get"))
        .stdout(predicate::str::contains("assign"))
        .stdout(predicate::str::contains("export"))
        .stdout(predicate::str::contains("import-env"))
        .stdout(predicate::str::contains("deploy"))
        .stdout(predicate::str::contains("sync-from"));
}

#[test]
fn app_dry_run_no_secrets_message() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    enva_cmd()
        .args(["vault", "assign", "nonexistent", "--app", "emptyapp"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .failure();
}

#[test]
fn verbose_flag_accepted() {
    enva_cmd()
        .args(["--verbose", "vault", "self-test"])
        .assert()
        .success()
        .stdout(predicate::str::contains("All checks passed"));
}

#[test]
fn quiet_flag_suppresses_output() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "testpass", "q1", "Q1", "v1");

    let output = enva_cmd()
        .args(["--quiet", "vault", "set", "q2", "-k", "Q2", "-V", "v2"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert!(output.is_empty());
}

#[test]
fn empty_password_vault_init_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = tmp.path().join("empty-pw.vault.json");
    enva_cmd()
        .args(["vault", "init", "--vault", vp.to_str().unwrap()])
        .arg("--password-stdin")
        .write_stdin("\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("password"));
}

#[test]
fn wrong_password_exits_code_2() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "correctpw");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "correctpw", "s1", "K1", "v1");

    enva_cmd()
        .args(["vault", "get", "s1"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("wrongpw\n")
        .assert()
        .code(2);
}

#[test]
fn missing_alias_exits_code_3() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    enva_cmd()
        .args(["vault", "get", "nonexistent-alias"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .code(3);
}

#[test]
fn help_shows_env_flag() {
    enva_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--env"));
}

#[test]
fn invalid_app_name_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpass");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "testpass", "s1", "K1", "v1");

    enva_cmd()
        .args(["vault", "assign", "s1", "--app", "UPPER_CASE"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpass\n")
        .assert()
        .failure();
}

#[test]
fn unicode_alias_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpw123");
    let vps = vp.to_str().unwrap();

    enva_cmd()
        .args(["vault", "set", "数据库", "-k", "K", "-V", "v"])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpw123\n")
        .assert()
        .failure();
}

#[test]
fn empty_app_name_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpw123");
    let vps = vp.to_str().unwrap();

    vault_set(vps, "testpw123", "s1", "K1", "v1");

    enva_cmd()
        .args(["vault", "assign", "s1", "--app", ""])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin("testpw123\n")
        .assert()
        .failure();
}

#[test]
fn large_value_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let vp = create_test_vault(tmp.path(), "testpw123");
    let vps = vp.to_str().unwrap();

    let large_val: String = "X".repeat(100_000);
    vault_set(vps, "testpw123", "bigval", "BIG_KEY", &large_val);

    let got = String::from_utf8(
        enva_cmd()
            .args(["vault", "get", "bigval", "--vault", vps, "--password-stdin"])
            .write_stdin("testpw123\n")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert_eq!(got.trim(), large_val);
}

fn current_platform_asset() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("enva-linux-x86_64"),
        ("linux", "aarch64") => Some("enva-linux-aarch64"),
        ("macos", "aarch64") => Some("enva-macos-aarch64"),
        _ => None,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut output = String::with_capacity(64);
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn write_test_binary(path: &std::path::Path) {
    fs::write(path, b"old-binary").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }
}

#[test]
fn update_help_shows_flags() {
    enva_cmd()
        .args(["update", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--version"))
        .stdout(predicate::str::contains("--force"));
}

#[test]
fn update_downloads_requested_release_into_override_binary_path() {
    let Some(asset_name) = current_platform_asset() else {
        return;
    };

    let tmp = tempfile::tempdir().unwrap();
    let binary_path = tmp.path().join("enva");
    write_test_binary(&binary_path);

    let mut server = Server::new();
    let downloaded = b"new-binary-contents";
    let digest = sha256_hex(downloaded);
    let asset_path = format!("/downloads/{asset_name}");
    let release_body = serde_json::json!({
        "tag_name": "v0.5.0",
        "html_url": format!("{}/releases/v0.5.0", server.url()),
        "assets": [{
            "name": asset_name,
            "browser_download_url": format!("{}{}", server.url(), asset_path),
            "size": downloaded.len(),
            "digest": format!("sha256:{digest}")
        }]
    });

    let _release = server
        .mock("GET", "/repos/YoRHa-Agents/EnvA/releases/tags/v0.5.0")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(release_body.to_string())
        .create();
    let _asset = server
        .mock("GET", asset_path.as_str())
        .with_status(200)
        .with_header("content-type", "application/octet-stream")
        .with_body(downloaded.to_vec())
        .create();

    enva_cmd()
        .args(["update", "--version", "v0.5.0"])
        .env("ENVA_UPDATE_API_BASE", server.url())
        .env("ENVA_UPDATE_BIN_PATH", &binary_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Updated enva to v0.5.0"));

    assert_eq!(fs::read(&binary_path).unwrap(), downloaded);
}

#[test]
fn update_reports_already_up_to_date_for_latest_release() {
    let Some(asset_name) = current_platform_asset() else {
        return;
    };

    let tmp = tempfile::tempdir().unwrap();
    let binary_path = tmp.path().join("enva");
    write_test_binary(&binary_path);

    let mut server = Server::new();
    let downloaded = b"same-version-binary";
    let digest = sha256_hex(downloaded);
    let asset_path = format!("/downloads/{asset_name}");
    let release_body = serde_json::json!({
        "tag_name": "v0.4.0",
        "html_url": format!("{}/releases/v0.4.0", server.url()),
        "assets": [{
            "name": asset_name,
            "browser_download_url": format!("{}{}", server.url(), asset_path),
            "size": downloaded.len(),
            "digest": format!("sha256:{digest}")
        }]
    });

    let _release = server
        .mock("GET", "/repos/YoRHa-Agents/EnvA/releases/latest")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(release_body.to_string())
        .create();

    enva_cmd()
        .args(["update"])
        .env("ENVA_UPDATE_API_BASE", server.url())
        .env("ENVA_UPDATE_BIN_PATH", &binary_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Already up to date (v0.4.0)"));

    assert_eq!(fs::read(&binary_path).unwrap(), b"old-binary");
}

#[test]
fn update_missing_release_returns_exit_code_5() {
    let tmp = tempfile::tempdir().unwrap();
    let binary_path = tmp.path().join("enva");
    write_test_binary(&binary_path);

    let mut server = Server::new();
    let _release = server
        .mock("GET", "/repos/YoRHa-Agents/EnvA/releases/tags/v9.9.9")
        .with_status(404)
        .create();

    enva_cmd()
        .args(["update", "--version", "v9.9.9"])
        .env("ENVA_UPDATE_API_BASE", server.url())
        .env("ENVA_UPDATE_BIN_PATH", &binary_path)
        .assert()
        .failure()
        .code(5)
        .stderr(predicate::str::contains("release not found"));
}

#[test]
fn update_missing_asset_returns_exit_code_6() {
    let tmp = tempfile::tempdir().unwrap();
    let binary_path = tmp.path().join("enva");
    write_test_binary(&binary_path);

    let mut server = Server::new();
    let release_body = serde_json::json!({
        "tag_name": "v0.4.0",
        "html_url": format!("{}/releases/v0.4.0", server.url()),
        "assets": [{
            "name": "enva-unsupported",
            "browser_download_url": format!("{}/downloads/enva-unsupported", server.url()),
            "size": 3,
            "digest": format!("sha256:{}", sha256_hex(b"abc"))
        }]
    });

    let _release = server
        .mock("GET", "/repos/YoRHa-Agents/EnvA/releases/tags/v0.4.0")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(release_body.to_string())
        .create();

    enva_cmd()
        .args(["update", "--version", "v0.4.0"])
        .env("ENVA_UPDATE_API_BASE", server.url())
        .env("ENVA_UPDATE_BIN_PATH", &binary_path)
        .assert()
        .failure()
        .code(6)
        .stderr(predicate::str::contains("does not contain asset"));
}

#[test]
fn sync_from_help_shows_merge_flags() {
    enva_cmd()
        .args(["vault", "sync-from", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--merge"))
        .stdout(predicate::str::contains("--prefer-local"))
        .stdout(predicate::str::contains("--prefer-remote"));
}

#[test]
fn sync_from_merge_conflicts_with_overwrite() {
    enva_cmd()
        .args([
            "vault",
            "sync-from",
            "--from",
            "user@host:/path",
            "--merge",
            "--overwrite",
            "--vault",
            "/tmp/dummy.json",
            "--password-stdin",
        ])
        .write_stdin("pw\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn sync_from_prefer_local_requires_merge() {
    enva_cmd()
        .args([
            "vault",
            "sync-from",
            "--from",
            "user@host:/path",
            "--prefer-local",
            "--vault",
            "/tmp/dummy.json",
            "--password-stdin",
        ])
        .write_stdin("pw\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--merge"));
}
