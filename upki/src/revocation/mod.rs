use core::error::Error as StdError;
use core::fmt;
use core::str::FromStr;
use std::fs::{self, File};
use std::io::BufReader;
use std::process::ExitCode;

use aws_lc_rs::digest;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chrono::{DateTime, Utc};
use clubcard_crlite::{CRLiteClubcard, CRLiteKey, CRLiteStatus};
use eyre::{Context, ContextCompat as _, Report, eyre};
use rustls_pki_types::{CertificateDer, TrustAnchor};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::Config;

mod fetch;
use fetch::Plan;
pub use fetch::fetch;

/// The structure contained in a manifest.json
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Manifest {
    /// When this file was generated.
    ///
    /// UNIX timestamp in seconds.
    pub generated_at: u64,

    /// Some human-readable text.
    pub comment: String,

    /// List of filter files.
    pub filters: Vec<Filter>,
}

impl Manifest {
    /// Load the revocation manifest from the cache directory specified in the configuration.
    pub fn from_config(config: &Config) -> Result<Self, Report> {
        let mut file_name = config.revocation_cache_dir();
        file_name.push("manifest.json");
        serde_json::from_reader(
            File::open(&file_name)
                .map(BufReader::new)
                .wrap_err_with(|| format!("cannot open manifest JSON {file_name:?}"))?,
        )
        .wrap_err("cannot parse manifest JSON")
    }

    /// This function does a high-level revocation check.
    ///
    /// The first element in `certificates` **must** be the end-entity certificate.  The
    /// end-entity certificate's issuer **must** be present in the other certificates
    /// (but does not need to be in any specific position).
    ///
    /// Note this interface **only** checks the end-entity certificate for revocation.  It does
    /// **not** check any of the certificates for validity: it assumes the caller has done any
    /// required checks before calling this interface (path building, naming validation,
    /// expiry checking, etc.).
    ///
    /// On success, this returns a [`RevocationStatus`] saying whether the certificate
    /// is revoked, not revoked, or whether the data set cannot make that determination.
    pub fn check_certificates(
        &self,
        certificates: &[CertificateDer<'_>],
        config: &Config,
    ) -> Result<RevocationStatus, Report> {
        let (end_entity, rest) = certificates
            .split_first()
            .wrap_err("too few certificates")?;
        let end_entity = webpki::EndEntityCert::try_from(end_entity)
            .wrap_err("cannot parse end-entity certificate")?;
        let issuer = find_issuer(rest.iter(), end_entity.issuer())?;
        let issuer_spki_hash = IssuerSpkiHash(
            digest::digest(&digest::SHA256, &webpki::spki_for_anchor(&issuer))
                .as_ref()
                .try_into()
                .expect("sha256 output must be [u8;32]"),
        );

        let mut sct_timestamps = vec![];
        for ts in end_entity
            .sct_log_timestamps()
            .map_err(|e| eyre!("error decoding sct: {e:?}"))?
        {
            let ts = ts.map_err(|e| eyre!("decoding error sct: {e:?}"))?;
            sct_timestamps.push(CtTimestamp {
                log_id: ts.log_id,
                timestamp: ts.timestamp_ms,
            });
        }

        self.check(
            &RevocationCheckInput {
                cert_serial: CertSerial(end_entity.serial().into()),
                issuer_spki_hash,
                sct_timestamps,
            },
            config,
        )
    }

    /// This function does a low-level revocation check.
    ///
    /// It is assumed the caller has already done a path verification, and now wants to
    /// check the revocation status of the end-entity certificate.
    ///
    /// On success, this returns a [`RevocationStatus`] saying whether the certificate
    /// is revoked, not revoked, or whether the data set cannot make that determination.
    pub fn check(
        &self,
        input: &RevocationCheckInput,
        config: &Config,
    ) -> Result<RevocationStatus, Report> {
        let key = input.key();
        let cache_dir = config.revocation_cache_dir();
        for f in &self.filters {
            let bytes = fs::read(cache_dir.join(&f.filename))
                .wrap_err_with(|| format!("cannot read filter file {}", f.filename))?;

            let filter =
                CRLiteClubcard::from_bytes(&bytes).map_err(|_| Error::CorruptCrliteFilter)?;

            match filter.contains(
                &key,
                input
                    .sct_timestamps
                    .iter()
                    .map(|ct_ts| (&ct_ts.log_id, ct_ts.timestamp)),
            ) {
                CRLiteStatus::Revoked => return Ok(RevocationStatus::CertainlyRevoked),
                CRLiteStatus::Good => return Ok(RevocationStatus::NotRevoked),
                CRLiteStatus::NotEnrolled | CRLiteStatus::NotCovered => continue,
            }
        }

        Ok(RevocationStatus::NotCoveredByRevocationData)
    }

    /// Verify the current contents of the cache against this manifest.
    ///
    /// This performs disk IO but does not perform network IO.
    pub fn verify(&self, config: &Config) -> Result<ExitCode, Report> {
        self.introduce()?;
        let plan = Plan::construct(self, "https://.../", &config.revocation_cache_dir())?;
        match plan.download_bytes() {
            0 => Ok(ExitCode::SUCCESS),
            bytes => Err(eyre!(
                "fixing the local cache requires downloading {bytes} bytes"
            )),
        }
    }

    /// Logs metadata fields in this manifest.
    pub fn introduce(&self) -> Result<(), Report> {
        let dt = match DateTime::<Utc>::from_timestamp(self.generated_at as i64, 0) {
            Some(dt) => dt.to_rfc3339(),
            None => return Err(eyre!("manifest has invalid timestamp")),
        };

        info!(comment = self.comment, date = dt, "parsed manifest");
        Ok(())
    }
}

/// Manifest data for a single crlite filter file.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Filter {
    /// Relative filename.
    ///
    /// This is also the suggested local filename.
    pub filename: String,

    /// File size, indicative.  Allows a fetcher to predict data usage.
    pub size: usize,

    /// SHA256 hash of file contents.
    #[serde(with = "hex::serde")]
    pub hash: Vec<u8>,
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
}

impl RevocationCheckInput {
    fn key(&self) -> CRLiteKey<'_> {
        CRLiteKey::new(&self.issuer_spki_hash.0, &self.cert_serial.0)
    }
}

/// A certificate serial number.
#[derive(Clone, Debug)]
pub struct CertSerial(pub Vec<u8>);

impl FromStr for CertSerial {
    type Err = Report;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match BASE64_STANDARD.decode(value) {
            Ok(bytes) => Ok(Self(bytes)),
            Err(e) => Err(e).wrap_err("cannot parse base64 serial number"),
        }
    }
}

/// The SHA256 hash of a `SubjectPublicKeyInfoDer` belonging to a certificate's issuer.
#[derive(Clone, Debug)]
pub struct IssuerSpkiHash(pub [u8; 32]);

impl FromStr for IssuerSpkiHash {
    type Err = Report;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            BASE64_STANDARD
                .decode(value)
                .wrap_err("cannot parse issuer SPKI hash")?
                .try_into()
                .map_err(|b: Vec<u8>| {
                    eyre!("issuer SPKI hash is wrong length (was {} bytes)", b.len())
                })?,
        ))
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
    type Err = Report;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some((log_id, issuance_timestamp)) = value.split_once(":") else {
            return Err(eyre!("missing colon in CT timestamp"));
        };

        Ok(Self {
            log_id: BASE64_STANDARD
                .decode(log_id)
                .wrap_err("cannot parse CT log ID")?
                .try_into()
                .map_err(|wrong: Vec<u8>| {
                    eyre!("CT log ID is wrong length (was {} bytes)", wrong.len())
                })?,
            timestamp: issuance_timestamp
                .parse()
                .wrap_err("cannot parse CT timestamp")?,
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

#[derive(Debug)]
pub(crate) enum Error {
    /// `crlite_clubcard::CRLiteClubcard` couldn't deserialize the filter data.
    CorruptCrliteFilter,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CorruptCrliteFilter => write!(f, "corrupt CRLite filter data"),
        }
    }
}

impl StdError for Error {}

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
            fetch_url: "https://upki.rustls.dev/".into(),
        }
    }
}

fn find_issuer<'a>(
    candidates: impl Iterator<Item = &'a CertificateDer<'a>>,
    name: &[u8],
) -> Result<TrustAnchor<'a>, Report> {
    for (i, c) in candidates.enumerate() {
        // nb. do not copy this code. it is not correct to treat intermediate certificates
        // as trust anchors.
        let root = webpki::anchor_from_trusted_cert(c).wrap_err_with(|| {
            format!("cannot parse potential intermediate certificate {}", i + 1)
        })?;
        if root.subject.as_ref() == name {
            return Ok(root);
        }
    }
    Err(eyre::eyre!("cannot find issuer certificate"))
}
