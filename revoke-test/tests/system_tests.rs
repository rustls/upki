//! NB. these tests require an up-to-date `revoke-test/test-sites.json` input, and
//! that the fetched revocation data set matches. They run `upki fetch` into an
//! empty directory and so do significant network IO.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::SystemTime;

use insta_cmd::get_cargo_bin;
use revoke_test::{CertificateDetail, RevocationTestSite, RevocationTestSites, Sct};

#[ignore]
#[test]
fn real_world_system_tests() {
    fs::create_dir_all(
        Path::new(TEST_CONFIG_PATH)
            .parent()
            .unwrap(),
    )
    .unwrap();
    fs::write(TEST_CONFIG_PATH, TEST_CONFIG).unwrap();

    Command::new(get_cargo_bin("upki"))
        .arg("--config-file")
        .arg(TEST_CONFIG_PATH)
        .arg("fetch")
        .output()
        .expect("cannot execute 'upki fetch'");

    let tests = serde_json::from_reader::<_, RevocationTestSites<'static>>(
        File::open("../revoke-test/test-sites.json")
            .expect("cannot find ../revoke-test/test-sites.json"),
    )
    .expect("cannot parse test-sites.json");

    let low_level_cli = test_each_site(tests.sites.iter(), low_level_cli);
    let high_level_cli = test_each_site(tests.sites.iter(), high_level_cli);
    let rustls = test_each_site(tests.sites.iter(), test_rustls);

    for ((site, low), high) in tests
        .sites
        .iter()
        .zip(low_level_cli.iter())
        .zip(high_level_cli.iter())
        .zip(rustls.iter())
    {
        assert_eq!(
            low, high,
            "site {site:?} revocation result disagrees between low and high-level APIs"
        );
    }
}

fn test_rustls(detail: &CertificateDetail) -> TestResult {
    let start = SystemTime::now();
    let e = Command::new(get_cargo_bin("upki"))
        .arg("--config-file")
        .arg(TEST_CONFIG_PATH)
        .arg("revocation-check")
        .arg("detail")
        .arg(&detail.serial)
        .arg(&detail.issuer_spki_sha256)
        .args(
            detail
                .scts
                .iter()
                .map(|Sct { log_id, timestamp }| format!("{log_id}:{timestamp}")),
        )
        .output()
        .expect("cannot run upki");
    let time_taken = start.elapsed().unwrap();
    println!("duration: {time_taken:?}");

    match e.status.code() {
        Some(2) => {
            assert_eq!(e.stdout, b"CertainlyRevoked\n");
            TestResult::CorrectlyRevoked
        }
        Some(0) => {
            assert!(matches!(
                e.stdout.as_slice(),
                b"NotCoveredByRevocationData\n" | b"NotRevoked\n"
            ));
            TestResult::IncorrectlyNotRevoked
        }
        _ => {
            println!("unexpected stdout {}", String::from_utf8_lossy(&e.stdout));
            panic!("unexpected error");
        }
    }
}

fn low_level_cli(detail: &CertificateDetail) -> TestResult {
    let e = Command::new(get_cargo_bin("upki"))
        .arg("--config-file")
        .arg(TEST_CONFIG_PATH)
        .arg("revocation-check")
        .arg("detail")
        .arg(&detail.serial)
        .arg(&detail.issuer_spki_sha256)
        .args(
            detail
                .scts
                .iter()
                .map(|Sct { log_id, timestamp }| format!("{log_id}:{timestamp}")),
        )
        .output()
        .expect("cannot run upki");

    match e.status.code() {
        Some(2) => {
            assert_eq!(e.stdout, b"CertainlyRevoked\n");
            TestResult::CorrectlyRevoked
        }
        Some(0) => {
            assert!(matches!(
                e.stdout.as_slice(),
                b"NotCoveredByRevocationData\n" | b"NotRevoked\n"
            ));
            TestResult::IncorrectlyNotRevoked
        }
        _ => {
            println!("unexpected stdout {}", String::from_utf8_lossy(&e.stdout));
            panic!("unexpected error");
        }
    }
}

fn high_level_cli(detail: &CertificateDetail) -> TestResult {
    let mut c = Command::new(get_cargo_bin("upki"))
        .arg("--config-file")
        .arg(TEST_CONFIG_PATH)
        .arg("revocation-check")
        .arg("high")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("cannot run upki");

    let mut stdin = c
        .stdin
        .take()
        .expect("cannot get stdin");
    for base64 in [&detail.end_entity_cert, &detail.issuer_cert] {
        stdin
            .write_all(b"-----BEGIN CERTIFICATE-----\r\n")
            .unwrap();
        stdin
            .write_all(base64.as_bytes())
            .unwrap();
        stdin
            .write_all(b"\r\n-----END CERTIFICATE-----\r\n")
            .unwrap();
    }
    stdin.flush().unwrap();
    drop(stdin);
    let e = c.wait_with_output().unwrap();

    match e.status.code() {
        Some(2) => {
            assert_eq!(e.stdout, b"CertainlyRevoked\n");
            TestResult::CorrectlyRevoked
        }
        Some(0) => {
            assert!(matches!(
                e.stdout.as_slice(),
                b"NotCoveredByRevocationData\n" | b"NotRevoked\n"
            ));
            TestResult::IncorrectlyNotRevoked
        }
        _ => {
            println!("unexpected stdout {}", String::from_utf8_lossy(&e.stdout));
            panic!("unexpected error");
        }
    }
}

fn test_each_site<'a>(
    sites: impl Iterator<Item = &'a RevocationTestSite>,
    test_one: impl Fn(&CertificateDetail) -> TestResult,
) -> Vec<TestResult> {
    let mut results = Vec::new();

    for t in sites {
        println!("testing {}... ", t.test_website_revoked);

        let Some(detail) = &t.detail else {
            results.push(TestResult::DecorationFailed);
            continue;
        };
        let start = SystemTime::now();
        let result = test_one(detail);
        let time_taken = start.elapsed().unwrap();
        println!("duration: {time_taken:?}");
        results.push(result);
    }

    let correctly_revoked = results
        .iter()
        .filter(|item| matches!(item, TestResult::CorrectlyRevoked))
        .count();
    let incorrectly_not_revoked = results
        .iter()
        .filter(|item| matches!(item, TestResult::IncorrectlyNotRevoked))
        .count();
    let decorate_failed = results
        .iter()
        .filter(|item| matches!(item, TestResult::DecorationFailed))
        .count();
    println!("summary:");
    println!("       correctly revoked: {correctly_revoked}");
    println!(" incorrectly not revoked: {incorrectly_not_revoked}");
    println!("        test case absent: {decorate_failed}");

    assert!(correctly_revoked > 0);
    assert!(correctly_revoked > incorrectly_not_revoked);
    results
}

#[derive(Debug, PartialEq)]
enum TestResult {
    CorrectlyRevoked,
    IncorrectlyNotRevoked,
    DecorationFailed,
}

const TEST_CONFIG_PATH: &str = "tmp/system-test/config.toml";
const TEST_CONFIG: &str = "cache-dir=\"tmp/system-test\"\n\
    [revocation]\n\
    fetch-url=\"https://upki.rustls.dev/\"\n";
