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
use std::fs::{self, File, Permissions};
use std::io::{self, Read};
#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aws_lc_rs::digest;
use tracing::{debug, info};

use super::{Error, Filter, Manifest};
use crate::Config;

/// Update the local revocation cache by fetching updates over the network.
///
/// `dry_run` means this call fetches the new manifest, but does not fetch any
/// required files; but the necessary files are printed to stdout.  Therefore
/// such a call is not completely "dry" -- perhaps "moist".
pub async fn fetch(dry_run: bool, config: &Config) -> Result<ExitCode, Error> {
    let cache_dir = config.revocation_cache_dir();
    info!(
        "fetching {} into {:?}...",
        &config.revocation.fetch_url, &cache_dir,
    );

    let manifest_url = format!("{}{MANIFEST_JSON}", config.revocation.fetch_url);
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

    let plan = Plan::construct(&manifest, &config.revocation.fetch_url, &cache_dir)?;

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
    pub(crate) fn construct(
        manifest: &Manifest,
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

        for filter in &manifest.filters {
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
                PlanStep::Download { filter, .. } => Some(filter.size),
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
        filter: Filter,
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
    },
}

impl PlanStep {
    async fn execute(self, client: &reqwest::Client) -> Result<(), Error> {
        match self {
            Self::CreateDir(path) => {
                fs::create_dir_all(&path).map_err(|error| Error::CreateDirectory { error, path })?
            }
            Self::Download {
                filter,
                remote_url,
                local,
            } => {
                debug!("downloading {:?}", filter);

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
                    Ok(digest) if digest.as_ref() == filter.hash => {}
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

                let path = local_dir.join(MANIFEST_JSON);
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

    fn download(filter: &Filter, remote_url: &str, local: &Path) -> Self {
        Self::Download {
            filter: filter.clone(),
            remote_url: format!("{remote_url}{}", filter.filename),
            local: local.join(&filter.filename),
        }
    }
}

impl fmt::Display for PlanStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDir(path) => write!(f, "create directory {path:?}"),
            Self::Download {
                filter,
                remote_url,
                local,
            } => write!(
                f,
                "download {} bytes from {remote_url} to {local:?}",
                filter.size
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

const MANIFEST_JSON: &str = "manifest.json";
const REQUEST_TIMEOUT: u64 = 30;
