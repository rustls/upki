use core::fmt;
use core::time::Duration;
use std::collections::HashSet;
use std::env;
use std::fs::{self, File, Permissions};
use std::io::{self, Read};
#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aws_lc_rs::digest;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::revocation::Error;

/// The structure contained in a manifest.json
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Manifest {
    /// When this file was generated.
    ///
    /// UNIX timestamp in seconds.
    pub generated_at: u64,

    /// Some human-readable text.
    pub comment: String,

    /// List of files.
    #[serde(rename = "filters")]
    pub files: Vec<ManifestFile>,
}

impl Manifest {
    /// Logs metadata fields in this manifest.
    pub fn introduce(&self) -> Result<(), Error> {
        let dt = match DateTime::<Utc>::from_timestamp(self.generated_at as i64, 0) {
            Some(dt) => dt.to_rfc3339(),
            None => {
                return Err(Error::InvalidTimestamp {
                    input: self.generated_at.to_string(),
                    context: "manifest generated (in s)",
                });
            }
        };

        info!(comment = self.comment, date = dt, "parsed manifest");
        Ok(())
    }
}

/// Manifest data for a single disk file.
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

pub(crate) async fn fetch_inner(
    dry_run: bool,
    fetch_url: &str,
    manifest_url: String,
    manifest_file_name: String,
    cache_dir: PathBuf,
) -> Result<ExitCode, Error> {
    info!("fetching {fetch_url} into {cache_dir:?}...");
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT))
        .user_agent(format!(
            "{} v{} ({})",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_REPOSITORY")
        ))
        .build()
        .map_err(|error| Error::HttpFetch {
            error: Box::new(error),
            url: manifest_url.clone(),
        })?;

    let response = client
        .get(&manifest_url)
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

    let manifest = response
        .json::<Manifest>()
        .await
        .map_err(|error| Error::ManifestDecode {
            error: Box::new(error),
            path: None,
        })?;

    manifest.introduce()?;

    let plan = Plan::construct(&manifest, fetch_url, &cache_dir, manifest_file_name)?;

    if dry_run {
        println!(
            "{} steps required ({} bytes to download)",
            plan.steps.len(),
            plan.download_bytes()
        );
        for step in plan.steps {
            println!("- {step}");
        }
        return Ok(ExitCode::SUCCESS);
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
    Ok(ExitCode::SUCCESS)
}

pub(crate) struct Plan {
    steps: Vec<PlanStep>,
}

impl Plan {
    /// Form a plan of how to synchronize with the remote server.
    ///
    /// - `manifest` describes the contents of the remote server.
    /// - `remote_url` is the base URL.
    /// - `local` is the path into which files are downloaded.  The caller ensures this exists.
    /// - `manifest_file_name` is the file name of the manifest, which will be placed into `local`.
    pub(crate) fn construct(
        manifest: &Manifest,
        remote_url: &str,
        local: &Path,
        manifest_file_name: String,
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
                    Err(error) => return Err(Error::FilterRead { error, path: None }),
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

        for filter in &manifest.files {
            unwanted_files.remove(Path::new(&filter.filename));

            let path = local.join(&filter.filename);
            match hash_file(&path) {
                Ok(digest) if digest.as_ref() == filter.hash => continue,
                _ => {}
            }

            steps.push(PlanStep::download(filter, remote_url, local));
        }

        steps.push(PlanStep::SaveManifest {
            manifest: manifest.clone(),
            local_dir: local.to_owned(),
            file_name: manifest_file_name.clone(),
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

    /// Download `filter` from `remote` to `local`
    Download {
        file: ManifestFile,
        /// URL.
        remote_url: String,
        /// Full path to output file.
        local: PathBuf,
    },

    /// Delete the given single local file.
    Delete(PathBuf),

    /// Save the manifest structure
    SaveManifest {
        manifest: Manifest,
        local_dir: PathBuf,
        file_name: String,
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

                fs::write(
                    &local,
                    response
                        .bytes()
                        .await
                        .map_err(|error| Error::HttpFetch {
                            error: Box::new(error),
                            url: remote_url.clone(),
                        })?,
                )
                .map_err(|error| Error::FileWrite {
                    error,
                    path: local.clone(),
                })?;

                match hash_file(&local) {
                    Ok(digest) if digest.as_ref() == file.hash => {}
                    Ok(_) => return Err(Error::HashMismatch(local)),
                    Err(error) => {
                        return Err(Error::FilterRead {
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
            Self::SaveManifest {
                manifest,
                local_dir,
                file_name,
            } => {
                debug!("saving manifest");
                #[cfg(target_family = "unix")]
                let temp = tempfile::Builder::new()
                    .permissions(Permissions::from_mode(0o644))
                    .suffix(".new")
                    .tempfile_in(&local_dir);
                #[cfg(not(target_family = "unix"))]
                let temp = tempfile::Builder::new()
                    .suffix(".new")
                    .tempfile_in(&local_dir);

                let mut local_temp = temp.map_err(|error| Error::ManifestWrite {
                    error,
                    path: local_dir.clone(),
                })?;

                serde_json::to_writer(local_temp.as_file_mut(), &manifest).map_err(|error| {
                    Error::ManifestEncode {
                        error: Box::new(error),
                        path: local_temp.path().to_owned(),
                    }
                })?;

                let path = local_dir.join(file_name);
                local_temp
                    .persist(&path)
                    .map_err(|error| Error::ManifestWrite {
                        error: error.error,
                        path,
                    })?;
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
            Self::SaveManifest { local_dir, .. } => {
                write!(f, "save new manifest into {local_dir:?}")
            }
        }
    }
}

fn hash_file(path: &Path) -> Result<digest::Digest, io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = digest::Context::new(&digest::SHA256);
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

const REQUEST_TIMEOUT: u64 = 30;
