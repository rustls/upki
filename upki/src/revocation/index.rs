use core::cmp::Ordering;
use core::{fmt, str};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
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
/// All integers are big-endian. Filenames are fixed 32-byte slots, NULL-padded.
///
/// ```text
/// HEADER (first read, 13 bytes):
///   magic: [u8; 8]                    "upkiidx0"
///   num_filenames: u8
///   num_log_ids: u32
///
/// TABLES (second read):
///   Per filename:
///     filename: [u8; 32]              UTF-8, NULL-padded
///   Per log_id (sorted lexicographically):
///     log_id: [u8; 32]
///     offset: u64                      byte offset from file start
///     num_entries: u16
///
/// ENTRY SECTIONS (seek + third read):
///   Per entry:
///     filter_index: u8
///     min_timestamp: u64
///     max_timestamp: u64
/// ```
///
/// This type stores a [`File`] for on-demand reading of entry sections.
pub struct Index {
    cache_dir: PathBuf,
    num_filenames: usize,
    num_logs: usize,
    logs_offset: usize,
    /// Contains the filename table followed by the log table.
    tables: Vec<u8>,
    file: File,
}

impl Index {
    /// Read the index header from the cache directory specified in `config`.
    ///
    /// Only the header (filename table and log-ID directory) is loaded into memory.
    /// Entry sections are read on demand during [`check`](Self::check) via seeking.
    pub fn from_cache(config: &Config) -> Result<Self, Error> {
        let cache_dir = config.revocation_cache_dir();
        let index_path = cache_dir.join(INDEX_BIN);
        let mut file = File::open(&index_path).map_err(|error| Error::FileRead {
            error,
            path: Some(index_path.clone()),
        })?;

        // Read 1: magic + num_filenames + num_log_ids
        let mut header = [0u8; HEADER_SIZE];
        file.read_exact(&mut header)
            .map_err(|e| Error::IndexDecode(Box::new(e)))?;
        if header[..8] != *INDEX_MAGIC {
            return Err(Error::IndexDecode("invalid index magic".into()));
        }
        let num_filenames = header[8] as usize;
        let num_logs = u32::from_be_bytes([header[9], header[10], header[11], header[12]]) as usize;

        // Read 2: filename table + log table
        let logs_offset = num_filenames * FILENAME_SIZE;
        let tables_len = logs_offset + num_logs * LOG_DIR_ENTRY_SIZE;
        let mut tables = vec![0u8; tables_len];
        file.read_exact(&mut tables)
            .map_err(|e| Error::IndexDecode(Box::new(e)))?;

        Ok(Self {
            cache_dir,
            num_filenames,
            num_logs,
            logs_offset,
            tables,
            file,
        })
    }

    /// Build index bytes by reading filter files from `dir` and extracting universe metadata.
    ///
    /// Returns `None` if any filter file cannot be read or decoded.
    pub(super) fn write(manifest: &Manifest, dir: &Path) -> Option<Vec<u8>> {
        let mut by_log_id: BTreeMap<[u8; 32], Vec<(u8, u64, u64)>> = BTreeMap::new();

        for (filter_idx, filter) in manifest.filters.iter().enumerate() {
            if filter.filename.len() > FILENAME_SIZE {
                tracing::warn!(
                    "skipping index: filename {:?} exceeds {FILENAME_SIZE} bytes",
                    filter.filename
                );
                return None;
            }

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

            for (log_id, (min_ts, max_ts)) in clubcard.universe().iter() {
                by_log_id
                    .entry(*log_id)
                    .or_default()
                    .push((filter_idx as u8, *min_ts, *max_ts));
            }
        }

        // Compute header size to determine entry section offsets
        let header_size = HEADER_SIZE
            + manifest.filters.len() * FILENAME_SIZE
            + by_log_id.len() * LOG_DIR_ENTRY_SIZE;

        // Write header
        let mut buf = Vec::new();
        buf.extend_from_slice(INDEX_MAGIC);
        buf.push(manifest.filters.len() as u8);
        buf.extend_from_slice(&(by_log_id.len() as u32).to_be_bytes());

        // Write filename table (fixed 32-byte slots, NULL-padded)
        for filter in &manifest.filters {
            let filename = filter.filename.as_bytes();
            let mut slot = [0u8; FILENAME_SIZE];
            slot[..filename.len()].copy_from_slice(filename);
            buf.extend_from_slice(&slot);
        }

        // Pre-compute offsets for each log_id's entry section
        let mut current_offset = header_size;
        let mut dir_entries: Vec<(&[u8; 32], u64, u16)> = Vec::new();
        for (log_id, entries) in &by_log_id {
            dir_entries.push((log_id, current_offset as u64, entries.len() as u16));
            current_offset += entries.len() * ENTRY_SIZE;
        }

        // Write log_id directory
        for (log_id, offset, count) in &dir_entries {
            buf.extend_from_slice(*log_id);
            buf.extend_from_slice(&offset.to_be_bytes());
            buf.extend_from_slice(&count.to_be_bytes());
        }

        // Write entry sections
        for entries in by_log_id.values() {
            for (filter_idx, min_ts, max_ts) in entries {
                buf.push(*filter_idx);
                buf.extend_from_slice(&min_ts.to_be_bytes());
                buf.extend_from_slice(&max_ts.to_be_bytes());
            }
        }

        Some(buf)
    }

    /// Perform a revocation check using the index.
    ///
    /// Uses binary search over the log-ID directory to find relevant entries,
    /// then seeks into the index file to read only those entries. Finally loads
    /// the matching filter file and checks the certificate against it.
    pub fn check(&mut self, input: &RevocationCheckInput) -> Result<RevocationStatus, Error> {
        let key = input.key();
        let dir_data = &self.tables[self.logs_offset..];

        let covering_filter = 'filter: {
            'timestamp: for sct in &input.sct_timestamps {
                // Binary search the sorted log_id directory (stride LOG_DIR_ENTRY_SIZE)
                let mut lo = 0;
                let mut hi = self.num_logs;
                let entry_offset = loop {
                    if lo >= hi {
                        continue 'timestamp;
                    }

                    let mid = lo + (hi - lo) / 2;
                    let offset = mid * LOG_DIR_ENTRY_SIZE;
                    let log_id = &dir_data[offset..offset + 32];
                    match log_id.cmp(sct.log_id.as_slice()) {
                        Ordering::Less => lo = mid + 1,
                        Ordering::Equal => break offset,
                        Ordering::Greater => hi = mid,
                    }
                };

                let mut entry_data = &dir_data[entry_offset + 32..];
                let offset = u64::read_be(&mut entry_data)?;
                let count = u16::read_be(&mut entry_data)?;

                self.file
                    .seek(SeekFrom::Start(offset))
                    .map_err(|e| Error::IndexDecode(Box::new(e)))?;

                let mut buf = vec![0u8; count as usize * ENTRY_SIZE];
                self.file
                    .read_exact(&mut buf)
                    .map_err(|e| Error::IndexDecode(Box::new(e)))?;

                let mut data = &buf[..];
                for _ in 0..count {
                    let filter_index = u8::read_be(&mut data)? as usize;
                    let min_ts = u64::read_be(&mut data)?;
                    let max_ts = u64::read_be(&mut data)?;
                    if min_ts <= sct.timestamp && sct.timestamp <= max_ts {
                        break 'filter Some(filter_index);
                    }
                }
            }
            None
        };

        let Some(filter_index) = covering_filter else {
            return Ok(RevocationStatus::NotCoveredByRevocationData);
        };

        let filename = self.filename(filter_index)?;
        let path = self.cache_dir.join(filename);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(Error::FileRead {
                    error,
                    path: Some(path),
                });
            }
        };

        let filter = CRLiteClubcard::from_bytes(&bytes).map_err(|error| Error::FileDecode {
            error: format!("cannot decode crlite filter: {error:?}").into(),
            path: Some(path),
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

    /// Look up the `i`-th filename in the fixed-size filename table.
    fn filename(&self, index: usize) -> Result<&str, Error> {
        if index >= self.num_filenames {
            return Err(Error::IndexDecode("filter index out of bounds".into()));
        }

        let start = index * FILENAME_SIZE;
        let slot = &self.tables[start..start + FILENAME_SIZE];
        let end = slot
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(FILENAME_SIZE);
        str::from_utf8(&slot[..end]).map_err(|e| Error::IndexDecode(Box::new(e)))
    }
}

impl fmt::Debug for Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            cache_dir,
            num_filenames,
            num_logs,
            logs_offset,
            tables: _,
            file: _,
        } = self;

        f.debug_struct("Index")
            .field("cache_dir", cache_dir)
            .field("filenames", num_filenames)
            .field("num_logs", num_logs)
            .field("logs_offset", logs_offset)
            .finish_non_exhaustive()
    }
}

impl FromBeBytes<8> for u64 {
    fn from_be_bytes(bytes: &[u8; 8]) -> Self {
        Self::from_be_bytes(*bytes)
    }
}

impl FromBeBytes<2> for u16 {
    fn from_be_bytes(bytes: &[u8; 2]) -> Self {
        Self::from_be_bytes(*bytes)
    }
}

impl FromBeBytes<1> for u8 {
    fn from_be_bytes(bytes: &[u8; 1]) -> Self {
        bytes[0]
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

const HEADER_SIZE: usize = 8 + 1 + 4;
const FILENAME_SIZE: usize = 32;
const LOG_DIR_ENTRY_SIZE: usize = 32 + 8 + 2;
const ENTRY_SIZE: usize = 1 + 8 + 8;

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
        write_index(dir.path(), b"wrongmag\x00\x00\x00\x00\x00");
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
        assert!(matches!(err, Error::FileRead { .. }));
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
        // Aggregate by log_id using BTreeMap for sorted order
        let mut by_log_id: BTreeMap<[u8; 32], Vec<(u8, u64, u64)>> = BTreeMap::new();
        for (filter_idx, (_, entries)) in filters.iter().enumerate() {
            for (log_id, min_ts, max_ts) in *entries {
                by_log_id
                    .entry(*log_id)
                    .or_default()
                    .push((filter_idx as u8, *min_ts, *max_ts));
            }
        }

        // Compute header size
        let header_size =
            HEADER_SIZE + filters.len() * FILENAME_SIZE + by_log_id.len() * LOG_DIR_ENTRY_SIZE;

        // Write header
        let mut buf = Vec::new();
        buf.extend_from_slice(INDEX_MAGIC);
        buf.push(filters.len() as u8);
        buf.extend_from_slice(&(by_log_id.len() as u32).to_be_bytes());

        // Write filename table (fixed 32-byte slots, NULL-padded)
        for (filename, _) in filters {
            let bytes = filename.as_bytes();
            let mut slot = [0u8; FILENAME_SIZE];
            slot[..bytes.len()].copy_from_slice(bytes);
            buf.extend_from_slice(&slot);
        }

        // Compute offsets and write directory
        let mut current_offset = header_size;
        let mut entry_counts: Vec<usize> = Vec::new();
        for (log_id, entries) in &by_log_id {
            buf.extend_from_slice(log_id);
            buf.extend_from_slice(&(current_offset as u64).to_be_bytes());
            buf.extend_from_slice(&(entries.len() as u16).to_be_bytes());
            current_offset += entries.len() * ENTRY_SIZE;
            entry_counts.push(entries.len());
        }

        // Write entry sections
        for entries in by_log_id.values() {
            for (filter_idx, min_ts, max_ts) in entries {
                buf.push(*filter_idx);
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
