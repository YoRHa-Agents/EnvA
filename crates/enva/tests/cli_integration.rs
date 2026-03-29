mod common;

use common::{create_test_vault, enva_cmd, vault_assign, vault_set};
use predicates::prelude::*;
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
        .stdout(predicate::str::contains("import-env"));
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
