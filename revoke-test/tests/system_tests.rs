//! NB. these tests require an up-to-date `revoke-test/test-sites.json` input, and
//! that the fetched revocation data set matches. They run `upki fetch` into an
//! empty directory and so do significant network IO.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::SystemTime;

use base64::prelude::*;
use insta_cmd::get_cargo_bin;
use revoke_test::{CertificateDetail, RevocationTestSite, RevocationTestSites};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, Error, RootCertStore};
use rustls_upki::{Policy, ServerVerifier};

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

    let high_level_cli = test_each_site(tests.sites.iter(), high_level_cli, "cli");

    let verifier = ServerVerifier::new(
        Policy::default(),
        Some(TEST_CONFIG_PATH.into()),
        Arc::new(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        }),
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    )
    .unwrap();

    let rustls_results = test_each_site(tests.sites.iter(), verifier, "rustls");

    for ((site, high), rustls) in tests
        .sites
        .iter()
        .zip(high_level_cli.iter())
        .zip(rustls_results.iter())
    {
        assert_eq!(
            high, rustls,
            "site {site:?} revocation result disagrees between high-level API and rustls verifier"
        );
    }
}

impl TestCase for ServerVerifier {
    fn run(&self, detail: &CertificateDetail, test: &RevocationTestSite) -> TestResult {
        // Decode certificates from base64
        let end_entity = CertificateDer::from(
            BASE64_STANDARD
                .decode(&detail.end_entity_cert)
                .expect("cannot decode end_entity_cert"),
        );
        let intermediates = detail
            .intermediates
            .iter()
            .map(|c| {
                CertificateDer::from(
                    BASE64_STANDARD
                        .decode(c)
                        .expect("cannot decode issuer_cert"),
                )
            })
            .collect::<Vec<_>>();

        let url = &test.test_website_revoked;
        let host = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url)
            .split('/')
            .next()
            .unwrap();
        // Strip port if present
        let domain = host.split(':').next().unwrap();
        let server_name = ServerName::try_from(domain.to_string()).unwrap();

        match self.verify_server_cert(
            &end_entity,
            &intermediates,
            &server_name,
            &[],
            UnixTime::now(),
        ) {
            Ok(_) => TestResult::IncorrectlyNotRevoked,
            Err(Error::InvalidCertificate(CertificateError::Revoked)) => {
                TestResult::CorrectlyRevoked
            }
            Err(e) => panic!(
                "unexpected error verifying certificate: {e} (site: {})",
                test.test_website_revoked
            ),
        }
    }
}

fn high_level_cli(detail: &CertificateDetail) -> TestResult {
    let mut c = Command::new(get_cargo_bin("upki"))
        .arg("--config-file")
        .arg(TEST_CONFIG_PATH)
        .arg("revocation")
        .arg("check")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("cannot run upki");

    let mut stdin = c
        .stdin
        .take()
        .expect("cannot get stdin");
    for base64 in [&detail.end_entity_cert, &detail.intermediates[0]] {
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
    test_one: impl TestCase,
    kind: &str,
) -> Vec<TestResult> {
    let mut results = Vec::new();

    for t in sites {
        println!("testing [{kind}] {}... ", t.test_website_revoked);

        let Some(detail) = &t.detail else {
            results.push(TestResult::DecorationFailed);
            continue;
        };
        let start = SystemTime::now();
        let result = test_one.run(detail, t);
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

impl<F> TestCase for F
where
    F: Fn(&CertificateDetail) -> TestResult,
{
    fn run(&self, detail: &CertificateDetail, _: &RevocationTestSite) -> TestResult {
        self(detail)
    }
}

trait TestCase {
    fn run(&self, detail: &CertificateDetail, test: &RevocationTestSite) -> TestResult;
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
