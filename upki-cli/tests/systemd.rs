#![cfg(target_os = "linux")]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use tempfile::TempDir;

#[test]
fn systemd_units_verify() {
    let source = systemd_dir();
    let temp = TempDir::new().unwrap();
    let service_path = temp.path().join("upki-fetch.service");
    let timer_path = temp.path().join("upki-fetch.timer");

    let service = fs::read_to_string(source.join("upki-fetch.service")).unwrap();
    let executable = std::env::current_exe().unwrap();
    fs::write(
        &service_path,
        service.replace("/usr/bin/upki", &executable.display().to_string()),
    )
    .unwrap();
    fs::copy(source.join("upki-fetch.timer"), &timer_path).unwrap();

    assert_success(
        Command::new("systemd-analyze")
            .arg("verify")
            .arg(service_path)
            .arg(timer_path)
            .output()
            .unwrap(),
    );
}

#[test]
fn sysusers_configuration_verifies() {
    let root = TempDir::new().unwrap();
    assert_success(
        Command::new("systemd-sysusers")
            .arg("--dry-run")
            .arg(format!("--root={}", root.path().display()))
            .arg(systemd_dir().join("upki.sysusers"))
            .output()
            .unwrap(),
    );
}

fn assert_success(output: Output) {
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn systemd_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../admin/systemd")
}
