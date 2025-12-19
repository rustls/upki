//! NB. these tests require an up-to-date `revoke-test/decorated.json` input, and
//! that the fetched revocation data set matches. They run `upki fetch` into an
//! empty directory and so do significant network IO.

use std::fs::File;
use std::process::Command;
use std::time::SystemTime;

use insta_cmd::get_cargo_bin;
use serde::Deserialize;

#[ignore]
#[test]
fn real_world_system_tests() {
    Command::new(get_cargo_bin("upki"))
        .arg("--cache-dir")
        .arg(TEST_CACHE_DIR)
        .arg("fetch")
        .output()
        .expect("cannot execute 'upki fetch'");

    let tests: RevocationTestSites = serde_json::from_reader(
        File::open("../revoke-test/decorated.json")
            .expect("cannot find ../revoke-test/decorated.json"),
    )
    .expect("cannot parse decorated.json");

    test_low_level_cli(&tests);
}

fn test_low_level_cli(tests: &RevocationTestSites) {
    let mut correctly_revoked = 0;
    let mut incorrectly_not_revoked = 0;
    let mut decorate_failed = 0;

    for t in &tests.sites {
        println!("testing {}... ", t.test_website_revoked);

        let Some(detail) = &t.detail else {
            decorate_failed += 1;
            println!("Decorate failed: {}", t.error.clone().unwrap());
            continue;
        };
        let start = SystemTime::now();
        let e = Command::new(get_cargo_bin("upki"))
            .arg("--cache-dir")
            .arg(TEST_CACHE_DIR)
            .arg("revocation-check")
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
            Some(1) => {
                assert_eq!(e.stdout, b"CertainlyRevoked\n");
                correctly_revoked += 1;
            }
            Some(0) => {
                assert_eq!(e.stdout, b"");
                incorrectly_not_revoked += 1;
                println!("Incorrectly not revoked: {}", t.ca_label);
            }
            _ => {
                println!("unexpected stdout {}", String::from_utf8_lossy(&e.stdout));
                panic!("unexpected error");
            }
        };
    }

    println!("summary:");
    println!("       correctly revoked: {correctly_revoked}");
    println!(" incorrectly not revoked: {incorrectly_not_revoked}");
    println!("        test case absent: {decorate_failed}");

    assert!(correctly_revoked > 0);
    assert!(correctly_revoked > incorrectly_not_revoked);
}

#[derive(Debug, Deserialize)]
struct RevocationTestSites {
    sites: Vec<RevocationTestSite>,
}

#[derive(Debug, Deserialize)]
#[expect(dead_code)]
struct RevocationTestSite {
    ca_sha256_fingerprint: String,
    ca_label: String,
    test_website_revoked: String,
    error: Option<String>,
    detail: Option<RevocationDetail>,
}

#[derive(Debug, Deserialize)]
#[expect(dead_code)]
struct RevocationDetail {
    end_entity_cert: String,
    issuer_cert: String,
    serial: String,
    issuer_spki_sha256: String,
    scts: Vec<Sct>,
}

#[derive(Debug, Deserialize)]
struct Sct {
    log_id: String,
    timestamp: u64,
}

const TEST_CACHE_DIR: &str = "tmp/system-test";
