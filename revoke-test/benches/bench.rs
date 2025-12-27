use core::hint::black_box;
use core::iter;
use std::fs::File;

use base64::prelude::{BASE64_STANDARD, Engine};
#[cfg(feature = "__bench_codspeed")]
use codspeed_criterion_compat::{Criterion, criterion_group, criterion_main};
#[cfg(not(feature = "__bench_codspeed"))]
use criterion::{Criterion, criterion_group, criterion_main};
use revoke_test::RevocationTestSites;
use rustls_pki_types::CertificateDer;
use upki::revocation::{Manifest, RevocationCheckInput, RevocationStatus};
use upki::{Config, ConfigPath};

fn revocation(c: &mut Criterion) {
    c.bench_function("load-config", |b| {
        b.iter(|| Config::from_file_or_default(&ConfigPath::new(None).unwrap()).unwrap())
    });

    c.bench_function("load-manifest", |b| {
        let config = Config::from_file_or_default(&ConfigPath::new(None).unwrap()).unwrap();

        b.iter(|| {
            black_box(Manifest::from_config(&config).unwrap());
        })
    });

    c.bench_function("revocation-input-from-certs", |b| {
        let revoked_certs = certificates_for_test_site(BENCHMARK_CASE);

        b.iter(|| {
            black_box(RevocationCheckInput::from_certificates(&revoked_certs).unwrap());
        });
    });

    c.bench_function("revocation-check", |b| {
        let config = Config::from_file_or_default(&ConfigPath::new(None).unwrap()).unwrap();
        let revoked_certs = certificates_for_test_site(BENCHMARK_CASE);

        b.iter(|| {
            let manifest = Manifest::from_config(&config).unwrap();
            let input = RevocationCheckInput::from_certificates(&revoked_certs).unwrap();
            assert_eq!(
                manifest.check(&input, &config).unwrap(),
                RevocationStatus::CertainlyRevoked
            );
        })
    });
}

fn certificates_for_test_site(ca_label: &str) -> Vec<CertificateDer<'static>> {
    let tests = serde_json::from_reader::<_, RevocationTestSites<'static>>(
        File::open("../revoke-test/test-sites.json")
            .expect("cannot find ../revoke-test/test-sites.json"),
    )
    .expect("cannot parse test-sites.json");

    let detail = tests
        .sites
        .iter()
        .find(|item| item.ca_label == ca_label)
        .unwrap()
        .detail
        .clone()
        .unwrap();

    iter::once(detail.end_entity_cert)
        .chain(detail.intermediates)
        .map(|c| {
            CertificateDer::from(
                BASE64_STANDARD
                    .decode(c)
                    .expect("cannot decode issuer_cert"),
            )
        })
        .collect::<Vec<_>>()
}

criterion_group!(benches, revocation);
criterion_main!(benches);

// choose a stable test site for benchmarking
const BENCHMARK_CASE: &str = "COMODO ECC Certification Authority";
