use assert_cmd::Command;
use std::path::{Path, PathBuf};

pub fn enva_cmd() -> Command {
    Command::cargo_bin("enva").unwrap()
}

pub fn create_test_vault(dir: &Path, password: &str) -> PathBuf {
    let vault_path = dir.join("test.vault.json");
    enva_cmd()
        .args(["vault", "init", "--vault", vault_path.to_str().unwrap()])
        .arg("--password-stdin")
        .write_stdin(format!("{password}\n"))
        .assert()
        .success();
    vault_path
}

pub fn vault_set(vps: &str, pw: &str, alias: &str, key: &str, value: &str) {
    enva_cmd()
        .args(["vault", "set", alias, "-k", key, "-V", value])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin(format!("{pw}\n"))
        .assert()
        .success();
}

pub fn vault_assign(vps: &str, pw: &str, alias: &str, app: &str) {
    enva_cmd()
        .args(["vault", "assign", alias, "--app", app])
        .args(["--vault", vps, "--password-stdin"])
        .write_stdin(format!("{pw}\n"))
        .assert()
        .success();
}
