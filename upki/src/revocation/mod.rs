use core::error::Error as StdError;
#[cfg(feature = "__fetch")]
use core::iter;
use core::str::FromStr;
use core::{fmt, str};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::{fs, io};

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
pub use clubcard_crlite::IssuerSpkiHash;
use clubcard_crlite::{CRLiteClubcard, CRLiteKey};
#[cfg(feature = "__fetch")]
use index::RevocationIndexer;
use rustls_pki_types::{CertificateDer, TrustAnchor};
use serde::{Deserialize, Serialize};
#[cfg(feature = "__fetch")]
use tracing::info;

#[cfg(feature = "__fetch")]
use crate::FetchError;
#[cfg(feature = "__fetch")]
use crate::fetch::{FetchContext, Plan};
use crate::{Config, sha256};

pub(crate) mod index;
use index::{INDEX_BIN, Index};

pub use crate::data::{Manifest, ManifestFile};

/// Update the local revocation cache by fetching updates over the network.
///
/// `dry_run` means this call fetches the new manifest, but does not fetch any
/// required files; but the necessary files are printed to stdout.  Therefore
/// such a call is not completely "dry" -- perhaps "moist".
#[cfg(feature = "__fetch")]
pub(crate) async fn fetch(dry_run: bool, config: &Config) -> Result<(), FetchError> {
    let cache_dir = config.revocation_cache_dir();
    info!(
        "fetching {} into {:?}...",
        &config.revocation.fetch_url, &cache_dir,
    );

    FetchContext {
        cache_dir,
        fetch_url: &config.revocation.fetch_url,
        managed_extensions: MANAGED_EXTENSIONS,
        post_process: Some(&RevocationIndexer),
    }
    .fetch(dry_run)
    .await
}

/// Revocation data store used for querying the revocation status of certificates.
pub struct Store {
    cache_dir: PathBuf,
}

impl Store {
    /// Create a new `Store` from the given configuration.
    ///
    /// The `Store` will use the cache directory specified in the configuration.
    pub fn from_config(config: &Config) -> Self {
        Self {
            cache_dir: config.revocation_cache_dir(),
        }
    }

    /// Verify the current contents of the cache against this manifest.
    ///
    /// This performs disk IO but does not perform network IO.
    #[cfg(feature = "__fetch")]
    pub fn verify(&self) -> Result<(), FetchError> {
        let manifest = Manifest::from_cache(&self.cache_dir)?;
        manifest.introduce()?;
        let plan = Plan::construct(
            &manifest,
            None::<iter::Empty<&str>>,
            &FetchContext {
                cache_dir: self.cache_dir.clone(),
                fetch_url: "https://.../",
                managed_extensions: MANAGED_EXTENSIONS,
                post_process: Some(&RevocationIndexer),
            },
        )?;
        match plan.download_bytes() {
            0 => Ok(()),
            bytes => Err(FetchError::Outdated(bytes)),
        }
    }

    /// Perform a revocation check.
    ///
    /// This reads the index and the relevant filter files from disk on every call.
    /// For repeated checks, [`load()`](Self::load) the store into memory instead.
    pub fn check(&self, input: &RevocationCheckInput) -> Result<RevocationStatus, Error> {
        Index::from_path(&self.cache_dir)?.check(input, &self.cache_dir)
    }

    /// Load the revocation data into memory.
    ///
    /// This reads the index and every filter it names, and keeps the decoded filters
    /// (somewhat larger than the files) for the life of the [`LoadedStore`]. In
    /// exchange, [`LoadedStore::check()`] does no I/O.
    ///
    /// A fetch that replaces the index during a load is detected, and the load starts
    /// over with the new index, a bounded number of times. If loading fails anyway,
    /// the caller can keep using a previously loaded store.
    pub fn load(&self) -> Result<LoadedStore, Error> {
        LoadedStore::load_with(&self.cache_dir, index::read_filter)
    }

    /// Validate the revocation data store.
    pub fn validate(&self) -> Result<(), Error> {
        Index::from_path(&self.cache_dir).map(|_| ())
    }
}

/// Revocation data held in memory, for checks without disk I/O.
///
/// A `LoadedStore` is a snapshot of the cache directory at the time of
/// [`Store::load()`]: later fetches are not observed. A long-running process
/// should poll [`is_stale()`](Self::is_stale) and load a replacement when it
/// returns `true`.
pub struct LoadedStore {
    index: Index,
    /// One decoded filter per entry of the index's filename table, in the same order.
    filters: Vec<CRLiteClubcard>,
    index_path: PathBuf,
}

impl LoadedStore {
    /// How many attempts a load makes before giving up on an index that keeps
    /// being replaced under it. Fetches are minutes apart, so two is plenty;
    /// three leaves a margin.
    const MAX_LOAD_ATTEMPTS: usize = 3;

    /// Load from `cache_dir`, reading each filter the index names with `read_filter`.
    fn load_with(
        cache_dir: &Path,
        mut read_filter: impl FnMut(PathBuf) -> Result<CRLiteClubcard, Error>,
    ) -> Result<Self, Error> {
        for _ in 1..Self::MAX_LOAD_ATTEMPTS {
            match Self::load_once(cache_dir, &mut read_filter) {
                // A filter the index names but the disk lacks means a fetch replaced
                // the index after it was read: a fetch deletes files only after the
                // new index is written. Start over with that one.
                Err(Error::FileRead { error, .. }) if error.kind() == io::ErrorKind::NotFound => {}
                result => return result,
            }
        }
        Self::load_once(cache_dir, &mut read_filter)
    }

    fn load_once(
        cache_dir: &Path,
        read_filter: &mut impl FnMut(PathBuf) -> Result<CRLiteClubcard, Error>,
    ) -> Result<Self, Error> {
        let index = Index::load(cache_dir)?;
        let filters = index
            .filenames()
            .map(|filename| read_filter(cache_dir.join(filename?)))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            index,
            filters,
            index_path: cache_dir.join(INDEX_BIN),
        })
    }

    /// Perform a revocation check against the data held in memory.
    pub fn check(&self, input: &RevocationCheckInput) -> Result<RevocationStatus, Error> {
        self.index
            .check_with(input, |filter_index, _| Ok(&self.filters[filter_index]))
    }

    /// Whether the index file on disk differs from the one this store was loaded from.
    ///
    /// This compares the index file byte for byte, so a fetch that rewrote it
    /// unchanged does not count. Index files are small, so polling this is cheap.
    /// It fails with [`Error::NoData`] if the index file has since been removed.
    pub fn is_stale(&self) -> Result<bool, Error> {
        let on_disk = fs::read(&self.index_path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => Error::NoData {
                path: self.index_path.clone(),
            },
            _ => Error::FileRead {
                error,
                path: Some(self.index_path.clone()),
            },
        })?;

        Ok(self.index.resident_bytes() != Some(on_disk.as_slice()))
    }
}

impl fmt::Debug for LoadedStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            index,
            filters,
            index_path,
        } = self;

        f.debug_struct("LoadedStore")
            .field("index", index)
            .field("filters", &filters.len())
            .field("index_path", index_path)
            .finish()
    }
}

/// Input parameters for a revocation check.
#[derive(Debug)]
pub struct RevocationCheckInput {
    /// Big-endian bytes encoding of the end-entity certificate serial number.
    pub cert_serial: CertSerial,
    /// SHA256 hash of the `SubjectPublicKeyInfo` of the issuer of the end-entity certificate.
    pub issuer_spki_hash: IssuerSpkiHash,
    /// CT log IDs and inclusion timestamps present in the end-entity certificate.
    pub sct_timestamps: Vec<CtTimestamp>,
    issuer_serial_hash: [u8; 32],
}

impl RevocationCheckInput {
    /// Construct a `RevocationCheckInput` from a sequence of DER-encoded certificates.
    ///
    /// The first element in `certificates` **must** be the end-entity certificate.  The
    /// end-entity certificate's issuer **must** be present in the other certificates
    /// (but does not need to be in any specific position).
    ///
    /// Note this interface **only** checks the end-entity certificate for revocation.  It does
    /// **not** check any of the certificates for validity: it assumes the caller has done any
    /// required checks before calling this interface (path building, naming validation,
    /// expiry checking, etc.).
    pub fn from_certificates(certificates: &[CertificateDer<'_>]) -> Result<Self, Error> {
        let (end_entity, rest) = certificates
            .split_first()
            .ok_or(Error::TooFewCertificates)?;
        let end_entity = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|error| Error::InvalidEndEntityCertificate(Box::new(error)))?;

        let issuer = find_issuer(end_entity.issuer(), rest.iter())?;
        let issuer_spki_hash = IssuerSpkiHash(
            sha256::Digest::from(&[webpki::spki_for_anchor(&issuer).as_ref()][..]).0,
        );

        let mut sct_timestamps = vec![];
        let iter = end_entity
            .sct_log_timestamps()
            .map_err(|e| Error::InvalidEndEntityCertificate(Box::new(e)))?;

        for ts in iter {
            let ts = ts.map_err(|e| Error::InvalidSctInCertificate(Box::new(e)))?;
            sct_timestamps.push(CtTimestamp {
                log_id: ts.log_id,
                timestamp: ts.timestamp_ms,
            });
        }

        Ok(Self::new(
            CertSerial(end_entity.serial().to_vec()),
            issuer_spki_hash,
            sct_timestamps,
        ))
    }

    /// Construct a `RevocationCheckInput` from its constituent parts.
    pub fn new(
        cert_serial: CertSerial,
        issuer_spki_hash: IssuerSpkiHash,
        sct_timestamps: Vec<CtTimestamp>,
    ) -> Self {
        let mut issuer_serial_context = sha256::Context::new();
        issuer_serial_context.update(&issuer_spki_hash.0);
        issuer_serial_context.update(&cert_serial.0);
        let issuer_serial_hash = issuer_serial_context.finish().0;

        Self {
            cert_serial,
            issuer_spki_hash,
            sct_timestamps,
            issuer_serial_hash,
        }
    }

    fn key(&self) -> CRLiteKey<'_> {
        CRLiteKey::with_hash(
            &self.issuer_spki_hash,
            &self.cert_serial.0,
            self.issuer_serial_hash,
        )
    }
}

/// A certificate serial number.
#[derive(Clone, Debug)]
pub struct CertSerial(pub Vec<u8>);

impl FromStr for CertSerial {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match BASE64_STANDARD.decode(value) {
            Ok(bytes) => Ok(Self(bytes)),
            Err(e) => Err(Error::InvalidBase64 {
                error: Box::new(e),
                context: "certificate serial",
            }),
        }
    }
}

/// An issuance timestamp established in certificate transparency.
#[derive(Clone, Debug)]
pub struct CtTimestamp {
    /// CT log ID
    pub log_id: [u8; 32],
    /// Issuance timestamp
    pub timestamp: u64,
}

impl FromStr for CtTimestamp {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some((log_id, issuance_timestamp)) = value.split_once(":") else {
            return Err(Error::InvalidSctEncoding);
        };

        Ok(Self {
            log_id: BASE64_STANDARD
                .decode(log_id)
                .map_err(|e| Error::InvalidBase64 {
                    error: Box::new(e),
                    context: "CT log ID",
                })?
                .try_into()
                .map_err(|wrong: Vec<u8>| Error::InvalidLength {
                    expected: 32,
                    actual: wrong.len(),
                    context: "CT log ID",
                })?,
            timestamp: u64::from_str(issuance_timestamp).map_err(|_| Error::InvalidTimestamp {
                input: issuance_timestamp.to_string(),
                context: "CT timestamp (in ms)",
            })?,
        })
    }
}

/// The successful outcome of a revocation check.
///
/// Look at a value of this type to determine whether a certificate was revoked or not.
#[derive(Debug, PartialEq)]
#[must_use]
pub enum RevocationStatus {
    /// We couldn't determine the revocation status.
    ///
    /// Most likely, this certificate is very new and is not covered by the current filter dataset.
    NotCoveredByRevocationData,

    /// This certificate has been revoked.
    CertainlyRevoked,

    /// This certificate was covered by revocation data, and it is not currently revoked.
    NotRevoked,
}

impl RevocationStatus {
    /// Convert this revocation status to an exit code for the CLI.
    ///
    /// Also print the status to stdout.
    pub fn to_cli(&self) -> ExitCode {
        println!("{self:?}");
        match self {
            Self::NotRevoked | Self::NotCoveredByRevocationData => ExitCode::SUCCESS,
            Self::CertainlyRevoked => ExitCode::from(Self::EXIT_CODE_REVOCATION_REVOKED),
        }
    }

    const EXIT_CODE_REVOCATION_REVOKED: u8 = 2;
}

/// Details about crlite-style revocation.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RevocationConfig {
    /// Where to fetch revocation data files.
    fetch_url: String,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        Self {
            fetch_url: "https://upki.rustls.dev/revocation/".into(),
        }
    }
}

/// The files `revocation::fetch()` owns in the revocation cache directory.
#[cfg(feature = "__fetch")]
const MANAGED_EXTENSIONS: &[&str] = &["filter", "delta"];

fn find_issuer<'a>(
    name: &[u8],
    candidates: impl Iterator<Item = &'a CertificateDer<'a>>,
) -> Result<TrustAnchor<'a>, Error> {
    for (i, c) in candidates.enumerate() {
        // nb. do not copy this code. it is not correct to treat intermediate certificates
        // as trust anchors.
        let root = webpki::anchor_from_trusted_cert(c).map_err(|error| {
            Error::InvalidIntermediateCertificate {
                error: Box::new(error),
                index: i,
            }
        })?;

        if root.subject.as_ref() == name {
            return Ok(root);
        }
    }

    Err(Error::NoIssuer)
}

/// Errors for the revocation API.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// Failed to decode a file.
    FileDecode {
        /// Underlying error.
        error: Box<dyn StdError + Send + Sync>,
        /// Path to the file.
        path: Option<PathBuf>,
    },
    /// Failed to read a file.
    FileRead {
        /// Underlying error.
        error: io::Error,
        /// Path to the file.
        path: Option<PathBuf>,
    },
    /// Failed to decode the index file.
    IndexDecode(Box<dyn StdError + Send + Sync>),
    /// Invalid base64 encoding.
    InvalidBase64 {
        /// Underlying error.
        error: Box<dyn StdError + Send + Sync>,
        /// Context in which the base64 was being parsed.
        context: &'static str,
    },
    /// The end-entity certificate was invalid and could not be parsed.
    InvalidEndEntityCertificate(Box<dyn StdError + Send + Sync>),
    /// An intermediate certificate was invalid and could not be parsed.
    InvalidIntermediateCertificate {
        /// Underlying error.
        error: Box<dyn StdError + Send + Sync>,
        /// Index of the intermediate certificate in the provided chain.
        index: usize,
    },
    /// A base64-decoded value did not have the expected length.
    InvalidLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
        /// Context in which the hash was being parsed.
        context: &'static str,
    },
    /// No ':' found in [`CtTimestamp`] string representation.
    InvalidSctEncoding,
    /// An SCT in the end-entity certificate could not be parsed.
    InvalidSctInCertificate(Box<dyn StdError + Send + Sync>),
    /// A timestamp could not be parsed.
    InvalidTimestamp {
        /// Input value that failed to parse as a timestamp.
        input: String,
        /// Context in which the timestamp was being parsed.
        context: &'static str,
    },
    /// No revocation data is present in the cache.
    ///
    /// This happens before revocation data is fetched for the first time.
    /// In contrast, other errors like [`Error::FileRead`] mean the cache
    /// is present but damaged or incomplete.
    NoData {
        /// Path to the index file that was not found.
        path: PathBuf,
    },
    /// No issuer found for the end-entity certificate in the provided chain.
    NoIssuer,
    /// Certificate chains must contain at least 2 certificates.
    TooFewCertificates,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileDecode { path, .. } => match path {
                Some(path) => write!(f, "cannot decode file {path:?}"),
                None => write!(f, "cannot decode file"),
            },
            Self::FileRead { path, .. } => match path {
                Some(path) => write!(f, "cannot read file {path:?}"),
                None => write!(f, "cannot read file"),
            },
            Self::IndexDecode(_) => write!(f, "cannot decode index file"),
            Self::InvalidBase64 { context, .. } => {
                write!(f, "invalid base64 for {context}")
            }
            Self::InvalidEndEntityCertificate(_) => {
                write!(f, "invalid end-entity certificate")
            }
            Self::InvalidIntermediateCertificate { index, .. } => {
                write!(f, "invalid intermediate certificate at index {index}")
            }
            Self::InvalidLength {
                expected,
                actual,
                context,
            } => write!(
                f,
                "invalid length for {context}: expected {expected}, got {actual}"
            ),
            Self::InvalidSctEncoding => write!(f, "invalid SCT encoding: no ':' found"),
            Self::InvalidSctInCertificate(_) => {
                write!(f, "invalid SCT in certificate")
            }
            Self::InvalidTimestamp { input, context } => {
                write!(f, "invalid timestamp for {context}: '{input}'")
            }
            Self::NoData { path } => write!(f, "no revocation data found at {path:?}"),
            Self::NoIssuer => write!(f, "no issuer found for end-entity certificate"),
            Self::TooFewCertificates => {
                write!(f, "certificate chain must contain at least 2 certificates")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::FileDecode { error, .. } => Some(&**error),
            Self::FileRead { error, .. } => Some(error),
            Self::IndexDecode(error) => Some(&**error),
            Self::InvalidBase64 { error, .. } => Some(&**error),
            Self::InvalidEndEntityCertificate(error) => Some(&**error),
            Self::InvalidIntermediateCertificate { error, .. } => Some(&**error),
            Self::InvalidLength { .. } => None,
            Self::InvalidSctEncoding => None,
            Self::InvalidSctInCertificate(error) => Some(&**error),
            Self::InvalidTimestamp { .. } => None,
            Self::NoData { .. } => None,
            Self::NoIssuer => None,
            Self::TooFewCertificates => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;
    use core::error::Error as StdError;

    use tempfile::TempDir;

    use super::index::tests::{
        SERIAL, build_filter, build_index, multi_sct_input, test_input, write_file,
    };
    use super::*;

    #[test]
    fn load_without_index_is_no_data() {
        let (store, _dir) = store_in_tempdir();
        assert!(matches!(store.load().unwrap_err(), Error::NoData { .. }));
    }

    #[test]
    fn load_with_missing_filter_fails() {
        let (store, dir) = store_in_tempdir();
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[("f0.filter", &[([0xbb; 32], 0, 2000)])]),
        );

        let err = store.load().unwrap_err();
        assert!(
            matches!(&err, Error::FileRead { error, path: Some(path) }
                if error.kind() == io::ErrorKind::NotFound && path.ends_with("f0.filter")),
            "{err}"
        );
    }

    #[test]
    fn load_with_undecodable_filter_fails() {
        let (store, dir) = store_in_tempdir();
        write_file(dir.path(), "f0.filter", b"not a clubcard");
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[("f0.filter", &[([0xbb; 32], 0, 2000)])]),
        );

        let err = store.load().unwrap_err();
        assert!(matches!(&err, Error::FileDecode { .. }), "{err}");
    }

    // The filter read stands in for a fetch that completes between reading the index
    // and reading its filters: it installs a new index and filter, deletes the old
    // filter, and then fails to read it. The load must start over and succeed with
    // the new index.
    #[test]
    fn load_starts_over_with_replaced_index() -> Result<(), Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let old = build_filter(
            [0xaa; 32],
            &[&[9, 9, 9]],
            &[SERIAL],
            &[([0xbb; 32], 0, 2000)],
        );
        write_file(dir.path(), "old.filter", &old);
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[("old.filter", &[([0xbb; 32], 0, 2000)])]),
        );

        let reads = Cell::new(0);
        let loaded = LoadedStore::load_with(dir.path(), |path| {
            if reads.replace(reads.get() + 1) == 0 {
                write_revoking_cache(dir.path(), "new.filter");
                fs::remove_file(dir.path().join("old.filter")).unwrap();
            }
            index::read_filter(path)
        })?;

        assert_eq!(reads.get(), 2);
        assert_eq!(
            loaded.check(&test_input())?,
            RevocationStatus::CertainlyRevoked
        );
        assert!(!loaded.is_stale()?);

        Ok(())
    }

    // An index that keeps naming a filter the disk lacks is given up on after a
    // bounded number of attempts rather than retried forever.
    #[test]
    fn load_gives_up_after_bounded_attempts() {
        let dir = tempfile::tempdir().unwrap();
        write_file(
            dir.path(),
            INDEX_BIN,
            &build_index(&[("f0.filter", &[([0xbb; 32], 0, 2000)])]),
        );

        let reads = Cell::new(0);
        let err = LoadedStore::load_with(dir.path(), |path| {
            reads.set(reads.get() + 1);
            index::read_filter(path)
        })
        .unwrap_err();

        assert_eq!(reads.get(), LoadedStore::MAX_LOAD_ATTEMPTS);
        assert!(
            matches!(&err, Error::FileRead { error, .. } if error.kind() == io::ErrorKind::NotFound),
            "{err}"
        );
    }

    // Verdicts from memory agree with verdicts from disk for every outcome.
    #[test]
    fn loaded_verdicts_match_on_disk() -> Result<(), Box<dyn StdError>> {
        let (store, dir) = store_in_tempdir();
        let dir = dir.path();

        let (log_a, log_b, log_c) = ([0xb1; 32], [0xb2; 32], [0xb3; 32]);
        // f0 covers log_a but enrolls a different issuer -> inconclusive for us.
        let f0 = build_filter([0xcc; 32], &[&[7, 7]], &[], &[(log_a, 0, 2000)]);
        // f1 covers log_b and revokes our serial.
        let f1 = build_filter([0xaa; 32], &[SERIAL], &[], &[(log_b, 0, 2000)]);
        // f2 covers log_c, enrolls our issuer, and revokes a different serial.
        let f2 = build_filter([0xaa; 32], &[&[9, 9, 9]], &[SERIAL], &[(log_c, 0, 2000)]);
        write_file(dir, "f0.filter", &f0);
        write_file(dir, "f1.filter.delta", &f1);
        write_file(dir, "f2.filter.delta", &f2);
        write_file(
            dir,
            INDEX_BIN,
            &build_index(&[
                ("f0.filter", &[(log_a, 0, 2000)]),
                ("f1.filter.delta", &[(log_b, 0, 2000)]),
                ("f2.filter.delta", &[(log_c, 0, 2000)]),
            ]),
        );

        let loaded = store.load()?;

        for (input, expected) in [
            (
                multi_sct_input(&[(log_a, 1000), (log_b, 1000)]),
                RevocationStatus::CertainlyRevoked,
            ),
            (
                multi_sct_input(&[(log_a, 1000), (log_c, 1000)]),
                RevocationStatus::NotRevoked,
            ),
            (
                multi_sct_input(&[(log_a, 1000)]),
                RevocationStatus::NotCoveredByRevocationData,
            ),
            (
                multi_sct_input(&[(log_b, 5000)]),
                RevocationStatus::NotCoveredByRevocationData,
            ),
            (test_input(), RevocationStatus::NotCoveredByRevocationData),
        ] {
            assert_eq!(loaded.check(&input)?, expected, "{input:?}");
            assert_eq!(store.check(&input)?, expected, "{input:?}");
        }

        Ok(())
    }

    #[test]
    fn loaded_checks_survive_cache_removal() -> Result<(), Box<dyn StdError>> {
        let (store, dir) = store_in_tempdir();
        write_revoking_cache(dir.path(), "f0.filter");

        let loaded = store.load()?;
        fs::remove_dir_all(dir.path())?;

        assert!(matches!(
            store.check(&test_input()),
            Err(Error::NoData { .. })
        ));
        assert_eq!(
            loaded.check(&test_input())?,
            RevocationStatus::CertainlyRevoked
        );

        Ok(())
    }

    #[test]
    fn is_stale_compares_index_bytes() -> Result<(), Box<dyn StdError>> {
        let (store, dir) = store_in_tempdir();
        let dir = dir.path();
        write_revoking_cache(dir, "f0.filter");

        let loaded = store.load()?;
        assert!(!loaded.is_stale()?);

        // A fetch that found nothing new still rewrites the index with the same bytes.
        let same = fs::read(dir.join(INDEX_BIN))?;
        write_file(dir, INDEX_BIN, &same);
        assert!(!loaded.is_stale()?);

        write_file(
            dir,
            INDEX_BIN,
            &build_index(&[
                ("f0.filter", &[([0xbb; 32], 0, 2000)]),
                ("f1.filter", &[([0xbb; 32], 2000, 3000)]),
            ]),
        );
        assert!(loaded.is_stale()?);

        fs::remove_file(dir.join(INDEX_BIN))?;
        assert!(matches!(loaded.is_stale(), Err(Error::NoData { .. })));

        Ok(())
    }

    #[test]
    fn loaded_store_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LoadedStore>();
    }

    /// A store whose cache directory is a fresh temporary directory.
    fn store_in_tempdir() -> (Store, TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store {
            cache_dir: dir.path().to_owned(),
        };
        (store, dir)
    }

    /// Write an index naming one filter, `filename`, that revokes the certificate of
    /// [`test_input`].
    fn write_revoking_cache(dir: &Path, filename: &str) {
        let filter = build_filter([0xaa; 32], &[SERIAL], &[], &[([0xbb; 32], 0, 2000)]);
        write_file(dir, filename, &filter);
        write_file(
            dir,
            INDEX_BIN,
            &build_index(&[(filename, &[([0xbb; 32], 0, 2000)])]),
        );
    }
}
