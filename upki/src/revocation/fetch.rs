//! upki fetcher.
//!
//! This program synchronises a local directory with the crlite files contained on a
//! remote server.  There is a manifest file that gives the names, sizes and hashes of
//! all valid files; this is fetched first. Then a plan is formed by comparing this against
//! the local filesystem contents. Finally, the plan is executed. If that succeeds
//! the remote server contents matches the local filesystem.

use core::fmt;
use core::time::Duration;
use std::collections::HashSet;
use std::env;
#[cfg(target_family = "unix")]
use std::fs::Permissions;
use std::fs::{self, File};
use std::io::{self, Read, Write};
#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use jiff::Timestamp;
use jiff::fmt::rfc2822::DateTimePrinter;
use reqwest::StatusCode;
use reqwest::header::IF_MODIFIED_SINCE;
use tracing::{debug, info};

use super::index::INDEX_BIN;
use super::{Error, Index, Manifest, ManifestFile};
use crate::{Config, sha256};

/// Update the local revocation cache by fetching updates over the network.
///
/// `dry_run` means this call fetches the new manifest, but does not fetch any
/// required files; but the necessary files are printed to stdout.  Therefore
/// such a call is not completely "dry" -- perhaps "moist".
pub async fn fetch(dry_run: bool, config: &Config) -> Result<(), Error> {
    let cache_dir = config.revocation_cache_dir();
    info!(
        "fetching {} into {:?}...",
        &config.revocation.fetch_url, &cache_dir,
    );

    let manifest_url = format!("{}{MANIFEST_JSON}", config.revocation.fetch_url);
    #[cfg(feature = "fetch")]
    let builder = reqwest::Client::builder().use_rustls_tls();
    #[cfg(all(feature = "fetch-native-tls", not(feature = "fetch")))]
    let builder = reqwest::Client::builder().use_native_tls();

    let client = builder
        .timeout(Duration::from_secs(REQUEST_TIMEOUT))
        .user_agent(format!(
            "{}/{} ({})",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_REPOSITORY")
        ))
        .build()
        .map_err(|error| Error::HttpFetch {
            error: Box::new(error),
            url: manifest_url.clone(),
        })?;

    let old_manifest = Manifest::from_config(config).ok();
    let local_modified = old_manifest.as_ref().and_then(|_| {
        let path = cache_dir.join(MANIFEST_JSON);
        match fs::metadata(&path).and_then(|metadata| metadata.modified()) {
            Ok(modified) => Some(modified),
            Err(error) => {
                debug!("cannot read modification time of {path:?}: {error}");
                None
            }
        }
    });

    let mut request = client.get(&manifest_url);
    if let Some(date) = local_modified.and_then(http_date) {
        debug!("requesting manifest modified since {date}");
        request = request.header(IF_MODIFIED_SINCE, date);
    }

    let response = request
        .send()
        .await
        .map_err(|error| Error::HttpFetch {
            error: Box::new(error),
            url: manifest_url.clone(),
        })?
        .error_for_status()
        .map_err(|error| Error::HttpFetch {
            error: Box::new(error),
            url: manifest_url.clone(),
        })?;

    let (manifest, modified, old_manifest) = match (response.status(), old_manifest) {
        (StatusCode::NOT_MODIFIED, Some(manifest)) => (manifest, false, None),
        (_, old) => (
            response
                .json::<Manifest>()
                .await
                .map_err(|error| Error::FileDecode {
                    error: Box::new(error),
                    path: None,
                })?,
            true,
            old,
        ),
    };

    let old_manifest = match (modified, old_manifest.as_ref()) {
        // If it was modified and there was an old manifest, return the old manifest
        (true, Some(manifest)) => Some(manifest),
        // If it was modified but there was no old manifest, return None
        (true, None) => None,
        // If it was not modified, we promoted the old manifest; return it
        (false, _) => Some(&manifest),
    };

    manifest.introduce()?;

    let plan = Plan::construct(
        &manifest,
        old_manifest.as_ref().map(|m| {
            m.files
                .iter()
                .map(|f| f.filename.as_str())
        }),
        &config.revocation.fetch_url,
        &cache_dir,
    )?;

    if dry_run {
        println!(
            "{} steps required ({} bytes to download)",
            plan.steps.len(),
            plan.download_bytes()
        );
        for step in plan.steps {
            println!("- {step}");
        }
        return Ok(());
    }

    info!(
        "{} steps required ({} bytes to download).",
        plan.steps.len(),
        plan.download_bytes()
    );

    for step in plan.steps {
        step.execute(&client).await?;
    }

    info!("success");
    Ok(())
}

pub(crate) struct Plan {
    steps: Vec<PlanStep>,
}

impl Plan {
    /// Form a plan of how to synchronize with the remote server.
    ///
    /// - `manifest` describes the contents of the remote server.
    /// - `old_manifest` is an alleged current manifest, whose files are left alone.
    /// - `remote_url` is the base URL.
    /// - `local` is the path into which files are downloaded.  The caller ensures this exists.
    pub(crate) fn construct<'a>(
        manifest: &Manifest,
        old_files: Option<impl Iterator<Item = &'a str>>,
        remote_url: &str,
        local: &Path,
    ) -> Result<Self, Error> {
        let mut steps = Vec::new();

        // Collect unwanted files for deletion
        let mut unwanted_files = HashSet::new();

        if local.exists() {
            let iter = fs::read_dir(local).map_err(|error| Error::CreateDirectory {
                error,
                path: local.to_owned(),
            })?;

            for entry in iter {
                let entry = match entry {
                    Ok(e) => e,
                    Err(error) => return Err(Error::FileRead { error, path: None }),
                };

                let path = Path::new(&entry.file_name()).to_owned();
                let name = path.to_string_lossy();
                if name.ends_with(".filter") || name.ends_with(".delta") {
                    unwanted_files.insert(path);
                }
            }
        } else {
            steps.push(PlanStep::CreateDir(local.to_owned()));
        }

        for file in &manifest.files {
            unwanted_files.remove(Path::new(&file.filename));

            let path = local.join(&file.filename);
            match hash_file(&path) {
                Ok(digest) if digest.as_ref() == file.hash => continue,
                _ => {}
            }

            steps.push(PlanStep::download(file, remote_url, local));
        }

        if let Some(old_files) = old_files {
            for file in old_files {
                unwanted_files.remove(Path::new(&file));
            }
        }

        steps.push(PlanStep::SaveIndex {
            manifest: manifest.clone(),
            local_dir: local.to_owned(),
        });

        steps.push(PlanStep::SaveManifest {
            manifest: manifest.clone(),
            local_dir: local.to_owned(),
        });

        for filename in unwanted_files {
            steps.push(PlanStep::Delete(local.join(filename)));
        }

        Ok(Self { steps })
    }

    /// How many bytes will we download?
    pub(crate) fn download_bytes(&self) -> usize {
        self.steps
            .iter()
            .filter_map(|s| match s {
                PlanStep::Download { file, .. } => Some(file.size),
                _ => None,
            })
            .sum()
    }
}

/// One step moving closer to local sync with the remote contents.
enum PlanStep {
    CreateDir(PathBuf),

    /// Download `file` from `remote` to `local`
    Download {
        file: ManifestFile,
        /// URL.
        remote_url: String,
        /// Full path to output file.
        local: PathBuf,
    },

    /// Delete the given single local file.
    Delete(PathBuf),

    /// Build and save the index from filter universe metadata.
    SaveIndex {
        manifest: Manifest,
        local_dir: PathBuf,
    },

    /// Save the manifest structure
    SaveManifest {
        manifest: Manifest,
        local_dir: PathBuf,
    },
}

impl PlanStep {
    async fn execute(self, client: &reqwest::Client) -> Result<(), Error> {
        match self {
            Self::CreateDir(path) => {
                fs::create_dir_all(&path).map_err(|error| Error::CreateDirectory { error, path })?
            }
            Self::Download {
                file,
                remote_url,
                local,
            } => {
                debug!("downloading {:?}", file);

                let response = client
                    .get(&remote_url)
                    .send()
                    .await
                    .map_err(|error| Error::HttpFetch {
                        error: Box::new(error),
                        url: remote_url.clone(),
                    })?
                    .error_for_status()
                    .map_err(|error| Error::HttpFetch {
                        error: Box::new(error),
                        url: remote_url.clone(),
                    })?;

                let bytes = response
                    .bytes()
                    .await
                    .map_err(|error| Error::HttpFetch {
                        error: Box::new(error),
                        url: remote_url.clone(),
                    })?;

                atomic_write(&local, &bytes).map_err(|error| Error::FileWrite {
                    error,
                    path: local.clone(),
                })?;

                match hash_file(&local) {
                    Ok(digest) if digest.as_ref() == file.hash => {}
                    Ok(_) => return Err(Error::HashMismatch(local)),
                    Err(error) => {
                        return Err(Error::FileRead {
                            error,
                            path: Some(local),
                        });
                    }
                }

                debug!("download successful");
            }
            Self::Delete(target) => {
                debug!("deleting unreferenced file {target:?}");
                fs::remove_file(&target).map_err(|error| Error::RemoveFile {
                    error,
                    path: target,
                })?;
            }
            Self::SaveIndex {
                manifest,
                local_dir,
            } => {
                debug!("building index");
                let Some(buf) = Index::write(&manifest, &local_dir) else {
                    return Ok(());
                };

                #[cfg(target_family = "unix")]
                let temp = tempfile::Builder::new()
                    .permissions(Permissions::from_mode(0o644))
                    .suffix(".new")
                    .tempfile_in(&local_dir);
                #[cfg(not(target_family = "unix"))]
                let temp = tempfile::Builder::new()
                    .suffix(".new")
                    .tempfile_in(&local_dir);

                let mut local_temp = temp.map_err(|error| Error::FileWrite {
                    error,
                    path: local_dir.clone(),
                })?;

                local_temp
                    .as_file_mut()
                    .write_all(&buf)
                    .map_err(|error| Error::FileWrite {
                        error,
                        path: local_temp.path().to_owned(),
                    })?;

                let path = local_dir.join(INDEX_BIN);
                local_temp
                    .persist(&path)
                    .map_err(|error| Error::FileWrite {
                        error: error.error,
                        path,
                    })?;
            }
            Self::SaveManifest {
                manifest,
                local_dir,
            } => {
                debug!("saving manifest");
                let path = local_dir.join(MANIFEST_JSON);
                let data =
                    serde_json::to_vec(&manifest).map_err(|error| Error::ManifestEncode {
                        error: Box::new(error),
                        path: path.clone(),
                    })?;
                atomic_write(&path, &data).map_err(|error| Error::FileWrite { error, path })?;
            }
        }

        Ok(())
    }

    fn download(file: &ManifestFile, remote_url: &str, local: &Path) -> Self {
        Self::Download {
            file: file.clone(),
            remote_url: format!("{remote_url}{}", file.filename),
            local: local.join(&file.filename),
        }
    }
}

impl fmt::Display for PlanStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDir(path) => write!(f, "create directory {path:?}"),
            Self::Download {
                file,
                remote_url,
                local,
            } => write!(
                f,
                "download {} bytes from {remote_url} to {local:?}",
                file.size
            ),
            Self::Delete(path) => write!(f, "delete stale file {path:?}"),
            Self::SaveIndex { local_dir, .. } => {
                write!(f, "build index from filters into {local_dir:?}")
            }
            Self::SaveManifest { local_dir, .. } => {
                write!(f, "save new manifest into {local_dir:?}")
            }
        }
    }
}

/// Atomically write `data` to `path` via a temporary file and rename.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), io::Error> {
    let dir = path
        .parent()
        .expect("path must have parent");

    #[cfg(target_family = "unix")]
    let temp = tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o644))
        .tempfile_in(dir);
    #[cfg(not(target_family = "unix"))]
    let temp = tempfile::Builder::new().tempfile_in(dir);

    let mut temp = temp?;
    temp.write_all(data)?;
    temp.persist(path)
        .map_err(|error| error.error)?;
    Ok(())
}

/// Format `time` as an HTTP-date, as used for `If-Modified-Since`.
fn http_date(time: SystemTime) -> Option<String> {
    let secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let time = Timestamp::new(i64::try_from(secs).ok()?, 0).ok()?;
    HTTP_DATE
        .timestamp_to_rfc9110_string(&time)
        .ok()
}

fn hash_file(path: &Path) -> Result<sha256::Digest, io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = sha256::Context::new();
    let mut buffer = [0; 4096];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        hasher.update(&buffer[..n]);
    }

    Ok(hasher.finish())
}

const HTTP_DATE: DateTimePrinter = DateTimePrinter::new();
const MANIFEST_JSON: &str = "manifest.json";
const REQUEST_TIMEOUT: u64 = 30;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_dates() {
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(784_111_777);
        let date = http_date(time).unwrap();
        assert_eq!(date, "Sun, 06 Nov 1994 08:49:37 GMT");
    }
}
