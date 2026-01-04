//! NB. these tests require an up-to-date `revoke-test/test-sites.json` input, and
//! that the fetched revocation data set matches. They run `upki fetch` into an
//! empty directory and so do significant network IO.

use std::fs::{self, File};
use std::path::Path;
use std::process::Command;
use std::time::SystemTime;

use insta_cmd::get_cargo_bin;
use revoke_test::{RevocationTestSite, RevocationTestSites, Sct};

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

    test_low_level_cli(tests.sites.into_owned());
}

fn test_low_level_cli(sites: Vec<RevocationTestSite>) {
    let mut correctly_revoked = 0;
    let mut incorrectly_not_revoked = 0;
    let mut decorate_failed = 0;

    for t in sites {
        println!("testing {}... ", t.test_website_revoked);

        let Some(detail) = t.detail else {
            decorate_failed += 1;
            println!("Decorate failed: {}", t.error.unwrap());
            continue;
        };
        let start = SystemTime::now();
        let e = Command::new(get_cargo_bin("upki"))
            .arg("--config-file")
            .arg(TEST_CONFIG_PATH)
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
            Some(2) => {
                assert_eq!(e.stdout, b"CertainlyRevoked\n");
                correctly_revoked += 1;
            }
            Some(0) => {
                assert!(matches!(
                    e.stdout.as_slice(),
                    b"NotCoveredByRevocationData\n" | b"NotRevoked\n"
                ));
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

const TEST_CONFIG_PATH: &str = "tmp/system-test/config.toml";
const TEST_CONFIG: &str = "[revocation]\n\
    cache_dir=\"tmp/system-test\"\n\
    fetch_url=\"https://upki.rustls.dev/\"\n";
