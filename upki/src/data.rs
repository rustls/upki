#[cfg(feature = "__fetch")]
use std::fs::File;
#[cfg(feature = "__fetch")]
use std::io::BufReader;
#[cfg(feature = "__fetch")]
use std::path::Path;

#[cfg(feature = "__fetch")]
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
#[cfg(feature = "__fetch")]
use tracing::info;

#[cfg(feature = "__fetch")]
use crate::FetchError;

/// The structure contained in a manifest.json
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Manifest {
    /// When this file was generated.
    ///
    /// UNIX timestamp in seconds.
    pub generated_at: u64,

    /// Some human-readable text.
    pub comment: String,

    /// List of required files.
    #[serde(alias = "filters")]
    pub files: Vec<ManifestFile>,
}

impl Manifest {
    #[cfg(feature = "__fetch")]
    pub(crate) fn from_cache(cache_dir: &Path) -> Result<Self, FetchError> {
        let file_name = cache_dir.join("manifest.json");
        let file = match File::open(&file_name) {
            Ok(f) => f,
            Err(error) => {
                return Err(FetchError::FileRead {
                    error,
                    path: Some(file_name),
                });
            }
        };

        serde_json::from_reader(BufReader::new(file)).map_err(|error| FetchError::FileDecode {
            error: Box::new(error),
            path: Some(file_name),
        })
    }

    /// Logs metadata fields in this manifest.
    #[cfg(feature = "__fetch")]
    pub(crate) fn introduce(&self) -> Result<(), FetchError> {
        let dt = i64::try_from(self.generated_at)
            .ok()
            .and_then(|secs| Timestamp::from_second(secs).ok());
        let Some(dt) = dt else {
            return Err(FetchError::InvalidTimestamp {
                input: self.generated_at.to_string(),
                context: "manifest generated (in s)",
            });
        };

        info!(
            comment = self.comment,
            date = %dt,
            "parsed manifest"
        );
        Ok(())
    }
}

/// Manifest data for a single manifest file.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestFile {
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
