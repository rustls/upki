use core::time::Duration;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::SystemTime;
use std::{fs, io};

use aws_lc_rs::digest::{SHA256, digest};
use clubcard::builder::{ApproximateRibbon, ClubcardBuilder, ExactRibbon};
use clubcard_crlite::builder::CRLiteBuilderItem;
use clubcard_crlite::{CRLiteClubcard, CRLiteCoverage, CRLiteQuery, Encoding};
use upki::data::{Manifest, ManifestFile};

/// Initial mirror state: a base filter and two deltas.
pub(super) static TYPICAL: LazyLock<MirrorFixture> = LazyLock::new(|| {
    let [base, second, third, _] = &*FILTERS;
    MirrorFixture::new(
        TYPICAL_GENERATED_AT,
        "typical test manifest",
        [base, second, third],
    )
});

/// The next mirror update: drop the oldest delta and publish a new one.
pub(super) static EVOLUTION: LazyLock<MirrorFixture> = LazyLock::new(|| {
    let [base, _, third, fourth] = &*FILTERS;
    MirrorFixture::new(
        TYPICAL_GENERATED_AT + 1_000,
        "evolution from typical test manifest",
        [base, third, fourth],
    )
});

/// Generate each filter once so a file retained across mirror updates keeps the same hash.
static FILTERS: LazyLock<[(&str, Vec<u8>); 4]> = LazyLock::new(|| {
    [
        ("filter1.filter", test_filter(1)),
        ("filter2.delta", test_filter(2)),
        ("filter3.delta", test_filter(3)),
        ("filter4.delta", test_filter(4)),
    ]
});

pub(super) struct MirrorFixture {
    files: HashMap<&'static str, Vec<u8>>,
    modified: SystemTime,
}

impl MirrorFixture {
    fn new(generated_at: u64, comment: &str, filters: [&(&'static str, Vec<u8>); 3]) -> Self {
        let mut files = HashMap::new();
        let manifest = Manifest {
            generated_at,
            comment: comment.to_string(),
            files: filters
                .into_iter()
                .map(|(name, body)| {
                    files.insert(*name, body.clone());
                    ManifestFile {
                        filename: name.to_string(),
                        size: body.len(),
                        hash: digest(&SHA256, body).as_ref().to_vec(),
                    }
                })
                .collect(),
        };
        files.insert(
            "manifest.json",
            serde_json::to_vec_pretty(&manifest).unwrap(),
        );
        Self {
            files,
            modified: SystemTime::UNIX_EPOCH + Duration::from_secs(generated_at),
        }
    }

    /// Write the manifest, base filter and third filter to the client cache, leaving one delta to fetch.
    pub(super) fn seed_partial_cache(&self, root: &Path) {
        for name in ["manifest.json", "filter1.filter", "filter3.delta"] {
            fs::write(root.join("revocation").join(name), &self.files[name]).unwrap();
        }
    }
}

pub(super) trait HttpRoot: Send + 'static {
    fn read(&self, path: &str) -> io::Result<(Vec<u8>, SystemTime)>;
}

impl HttpRoot for &'static MirrorFixture {
    fn read(&self, path: &str) -> io::Result<(Vec<u8>, SystemTime)> {
        let body = path
            .strip_prefix("revocation/")
            .and_then(|name| self.files.get(name))
            .ok_or(io::ErrorKind::NotFound)?;
        Ok((body.clone(), self.modified))
    }
}

impl HttpRoot for PathBuf {
    fn read(&self, path: &str) -> io::Result<(Vec<u8>, SystemTime)> {
        let target = self.join(path);
        Ok((fs::read(&target)?, fs::metadata(target)?.modified()?))
    }
}

/// Build an indexable V4 filter with one covered log and a seed-specific issuer.
fn test_filter(seed: u8) -> Vec<u8> {
    let mut builder = ClubcardBuilder::<4, CRLiteBuilderItem>::new();
    let issuer = [seed; 32];
    let mut approximate = builder.new_approx_builder(&issuer);
    approximate.set_universe_size(1);
    builder.collect_approx_ribbons(vec![ApproximateRibbon::from(approximate)]);
    let exact = builder.new_exact_builder(&issuer);
    builder.collect_exact_ribbons(vec![ExactRibbon::from(exact)]);

    // The builder takes Mozilla CT log metadata; the synthetic LogID is 32 bytes of 0xaa.
    let coverage = CRLiteCoverage::from_mozilla_ct_logs_json(
        br#"[
            {
                "LogID": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=",
                "MinEntry": 0,
                "MinTimestamp": 0,
                "MaxTimestamp": 2000,
                "MMD": 0
            }
        ]"#
        .as_slice(),
    );
    assert_eq!(coverage.iter().count(), 1, "expected one covered test log");
    let clubcard = builder.build::<CRLiteQuery<'_>>(coverage, ());
    CRLiteClubcard::from(clubcard)
        .to_bytes(Encoding::V4)
        .unwrap()
}

const TYPICAL_GENERATED_AT: u64 = 1_765_445_031;
