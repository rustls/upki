use core::error::Error as StdError;
use core::fmt;
use core::str::FromStr;
use std::fs::{self, File};
use std::io::BufReader;
use std::process::ExitCode;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chrono::{DateTime, Utc};
use clubcard_crlite::{CRLiteClubcard, CRLiteKey, CRLiteStatus};
use eyre::{Context, Report, eyre};
use serde::{Deserialize, Serialize};
use tracing::info;

mod config;
pub use config::{Config, ConfigPath, RevocationConfig};

mod fetch;
pub use fetch::fetch;

use crate::fetch::Plan;

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

    pub fn introduce(&self) -> Result<(), Report> {
        let dt = match DateTime::<Utc>::from_timestamp(self.generated_at as i64, 0) {
            Some(dt) => dt.to_rfc3339(),
            None => return Err(eyre!("manifest has invalid timestamp")),
        };

        info!(comment = self.comment, date = dt, "parsed manifest");
        Ok(())
    }
}

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

#[derive(Clone, Debug)]
pub struct CtTimestamp {
    pub log_id: [u8; 32],
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
pub enum Error {
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
