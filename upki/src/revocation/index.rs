use core::{fmt, str};
use std::fs;
use std::path::{Path, PathBuf};

use clubcard_crlite::{CRLiteClubcard, CRLiteStatus};

use super::{Error, Manifest, RevocationCheckInput, RevocationStatus};
use crate::Config;

/// Binary-encoded index of universe metadata for all filters in a manifest.
///
/// This allows the check path to identify which filter file covers a given certificate
/// without loading every filter. Written atomically during fetch, this is the single
/// source of truth for revocation checks.
///
/// # Encoding
///
/// All integers are big-endian.
///
/// ```text
/// magic: [u8; 8]                    "upkiidx0"
/// num_filters: u32
/// For each filter:
///   filename_len: u16
///   filename: [u8; filename_len]     UTF-8
///   num_coverage_entries: u32
///   For each coverage entry:
///     log_id: [u8; 32]
///     min_timestamp: u64
///     max_timestamp: u64
/// ```
pub struct Index {
    cache_dir: PathBuf,
    filters: u32,
    data: Vec<u8>,
}

impl Index {
    /// Read the index from the cache directory specified in `config`.
    pub fn from_cache(config: &Config) -> Result<Self, Error> {
        let cache_dir = config.revocation_cache_dir();
        let path = cache_dir.join(INDEX_BIN);
        let data = fs::read(&path).map_err(|error| Error::FilterRead {
            error,
            path: Some(path),
        })?;

        let mut read = &data[..];
        let magic = try_split_at(&mut read, INDEX_MAGIC.len())?;
        if magic != INDEX_MAGIC {
            return Err(Error::IndexDecode("invalid index magic".into()));
        }

        Ok(Self {
            cache_dir,
            filters: u32::read_be(&mut read)?,
            data,
        })
    }

    /// Build index bytes by reading filter files from `dir` and extracting universe metadata.
    ///
    /// Returns `None` if any filter file cannot be read or decoded.
    pub(super) fn write(manifest: &Manifest, dir: &Path) -> Option<Vec<u8>> {
        let mut buf = Vec::new();
        buf.extend_from_slice(INDEX_MAGIC);
        buf.extend_from_slice(&(manifest.filters.len() as u32).to_be_bytes());
        for filter in &manifest.filters {
            let path = dir.join(&filter.filename);
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    tracing::warn!("skipping index: cannot read {path:?}: {error}");
                    return None;
                }
            };

            let clubcard = match CRLiteClubcard::from_bytes(&bytes) {
                Ok(c) => c,
                Err(error) => {
                    tracing::warn!("skipping index: cannot decode {path:?}: {error:?}");
                    return None;
                }
            };

            let filename = filter.filename.as_bytes();
            buf.extend_from_slice(&(filename.len() as u16).to_be_bytes());
            buf.extend_from_slice(filename);

            let entries: Vec<_> = clubcard.universe().iter().collect();
            buf.extend_from_slice(&(entries.len() as u32).to_be_bytes());
            for (log_id, (min_ts, max_ts)) in entries {
                buf.extend_from_slice(log_id);
                buf.extend_from_slice(&min_ts.to_be_bytes());
                buf.extend_from_slice(&max_ts.to_be_bytes());
            }
        }

        Some(buf)
    }

    /// Perform a revocation check using the index.
    ///
    /// Reads the index file, uses the coverage metadata to identify which filter
    /// files are relevant, then loads only those filters to check the certificate.
    pub fn check(&self, input: &RevocationCheckInput) -> Result<RevocationStatus, Error> {
        let key = input.key();
        let mut filters_left = self.filters;
        let mut data = &self.data[8 + 4..]; // Skip magic and num_filters

        let covering_path = 'outer: loop {
            if filters_left == 0 {
                break None;
            }

            let filename_len = u16::read_be(&mut data)? as usize;
            let filename = try_split_at(&mut data, filename_len)?;
            let mut entries_left = u32::read_be(&mut data)? as usize;
            loop {
                if entries_left == 0 {
                    break;
                }

                let log_id = try_split_at(&mut data, 32)?;
                let min_ts = u64::read_be(&mut data)?;
                let max_ts = u64::read_be(&mut data)?;
                for ts in &input.sct_timestamps {
                    if ts.log_id == log_id && min_ts <= ts.timestamp && ts.timestamp <= max_ts {
                        let filter = str::from_utf8(filename)
                            .map_err(|e| Error::IndexDecode(Box::new(e)))?;
                        break 'outer Some(filter);
                    }
                }

                entries_left -= 1;
            }

            filters_left -= 1;
        };

        let Some(filename) = covering_path else {
            return Ok(RevocationStatus::NotCoveredByRevocationData);
        };

        let path = self.cache_dir.join(filename);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(Error::FilterRead {
                    error,
                    path: Some(path),
                });
            }
        };

        let filter = CRLiteClubcard::from_bytes(&bytes).map_err(|error| Error::FilterDecode {
            error: format!("cannot decode crlite filter: {error:?}").into(),
            path,
        })?;

        Ok(
            match filter.contains(
                &key,
                input
                    .sct_timestamps
                    .iter()
                    .map(|ct_ts| (&ct_ts.log_id, ct_ts.timestamp)),
            ) {
                CRLiteStatus::Revoked => RevocationStatus::CertainlyRevoked,
                CRLiteStatus::Good => RevocationStatus::NotRevoked,
                CRLiteStatus::NotEnrolled | CRLiteStatus::NotCovered => {
                    RevocationStatus::NotCoveredByRevocationData
                }
            },
        )
    }
}

impl fmt::Debug for Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Index")
            .field("cache_dir", &self.cache_dir)
            .field("filters", &self.filters)
            .finish_non_exhaustive()
    }
}

fn try_split_at<'a>(data: &mut &'a [u8], mid: usize) -> Result<&'a [u8], Error> {
    match data.split_at_checked(mid) {
        Some((left, right)) => {
            *data = right;
            Ok(left)
        }
        None => Err(Error::IndexDecode("unexpected end of index data".into())),
    }
}

impl FromBeBytes<8> for u64 {
    fn from_be_bytes(bytes: &[u8; 8]) -> Self {
        Self::from_be_bytes(*bytes)
    }
}

impl FromBeBytes<4> for u32 {
    fn from_be_bytes(bytes: &[u8; 4]) -> Self {
        Self::from_be_bytes(*bytes)
    }
}

impl FromBeBytes<2> for u16 {
    fn from_be_bytes(bytes: &[u8; 2]) -> Self {
        Self::from_be_bytes(*bytes)
    }
}

trait FromBeBytes<const N: usize>: Sized {
    fn read_be(data: &mut &[u8]) -> Result<Self, Error> {
        match data.split_first_chunk::<N>() {
            Some((chunk, rest)) => {
                *data = rest;
                Ok(Self::from_be_bytes(chunk))
            }
            None => Err(Error::IndexDecode("unexpected end of index data".into())),
        }
    }

    fn from_be_bytes(bytes: &[u8; N]) -> Self;
}

pub(super) const INDEX_BIN: &str = "index.bin";
const INDEX_MAGIC: &[u8; 8] = b"upkiidx0";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation::{CertSerial, CtTimestamp, IssuerSpkiHash, RevocationConfig};

    #[test]
    fn check_empty_index() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        write_index(dir.path(), &build_index(&[]));
        assert_eq!(
            Index::from_cache(&config)
                .unwrap()
                .check(&test_input())
                .unwrap(),
            RevocationStatus::NotCoveredByRevocationData,
        );
    }

    #[test]
    fn check_no_matching_log_id() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        // Input has log_id [0xbb; 32], index has [0xcc; 32]
        let data = build_index(&[("test.filter", &[([0xcc; 32], 500, 1500)])]);
        write_index(dir.path(), &data);
        assert_eq!(
            Index::from_cache(&config)
                .unwrap()
                .check(&test_input())
                .unwrap(),
            RevocationStatus::NotCoveredByRevocationData,
        );
    }

    #[test]
    fn check_no_matching_timestamp_range() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        // Input has timestamp 1000, index range is 2000..3000
        let data = build_index(&[("test.filter", &[([0xbb; 32], 2000, 3000)])]);
        write_index(dir.path(), &data);
        assert_eq!(
            Index::from_cache(&config)
                .unwrap()
                .check(&test_input())
                .unwrap(),
            RevocationStatus::NotCoveredByRevocationData,
        );
    }

    #[test]
    fn invalid_magic() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        write_index(dir.path(), b"wrongmag\x00\x00\x00\x00");
        let err = Index::from_cache(&config).unwrap_err();
        assert!(matches!(err, Error::IndexDecode(_)));
    }

    #[test]
    fn truncated_after_magic() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        write_index(dir.path(), INDEX_MAGIC);
        let err = Index::from_cache(&config).unwrap_err();
        assert!(matches!(err, Error::IndexDecode(_)));
    }

    #[test]
    fn truncated_before_magic() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        write_index(dir.path(), b"upki");
        let err = Index::from_cache(&config).unwrap_err();
        assert!(matches!(err, Error::IndexDecode(_)));
    }

    #[test]
    fn missing_index() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let err = Index::from_cache(&config).unwrap_err();
        assert!(matches!(err, Error::FilterRead { .. }));
    }

    fn test_config(dir: &Path) -> Config {
        Config {
            cache_dir: dir.to_owned(),
            revocation: RevocationConfig::default(),
        }
    }

    fn test_input() -> RevocationCheckInput {
        RevocationCheckInput {
            cert_serial: CertSerial(vec![1, 2, 3]),
            issuer_spki_hash: IssuerSpkiHash([0xaa; 32]),
            sct_timestamps: vec![CtTimestamp {
                log_id: [0xbb; 32],
                timestamp: 1000,
            }],
        }
    }

    #[expect(clippy::type_complexity)]
    fn build_index(filters: &[(&str, &[([u8; 32], u64, u64)])]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(INDEX_MAGIC);
        buf.extend_from_slice(&(filters.len() as u32).to_be_bytes());
        for (filename, entries) in filters {
            let filename = filename.as_bytes();
            buf.extend_from_slice(&(filename.len() as u16).to_be_bytes());
            buf.extend_from_slice(filename);
            buf.extend_from_slice(&(entries.len() as u32).to_be_bytes());
            for (log_id, min_ts, max_ts) in *entries {
                buf.extend_from_slice(log_id);
                buf.extend_from_slice(&min_ts.to_be_bytes());
                buf.extend_from_slice(&max_ts.to_be_bytes());
            }
        }
        buf
    }

    fn write_index(dir: &Path, data: &[u8]) {
        let revocation_dir = dir.join("revocation");
        fs::create_dir_all(&revocation_dir).unwrap();
        fs::write(revocation_dir.join(INDEX_BIN), data).unwrap();
    }
}
