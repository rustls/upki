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
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use eyre::{Context, Report, eyre};
use ring::digest;
use tracing::{debug, info};
use upki::{Filter, Manifest};

pub(super) async fn fetch(local: &Path, remote_url: &str, dry_run: bool) -> Result<(), Report> {
    info!("fetching {remote_url} into {local:?}...");

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
        .wrap_err("failed to create HTTP client")?;

    let manifest_url = format!("{remote_url}{MANIFEST_JSON}");
    let response = client
        .get(&manifest_url)
        .send()
        .await
        .wrap_err("failed to fetch manifest")?
        .error_for_status()
        .wrap_err("HTTP error while fetching manifest")?;

    let manifest = response
        .json()
        .await
        .wrap_err("failed to parse manifest JSON")?;

    introduce_manifest(&manifest)?;

    let plan = Plan::construct(&manifest, remote_url, local)?;

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

pub(super) fn verify(local: &Path) -> Result<(), Report> {
    let file_name = local.join(MANIFEST_JSON);
    let manifest = serde_json::from_reader(
        File::open(&file_name)
            .map(BufReader::new)
            .wrap_err_with(|| format!("cannot open manifest JSON {file_name:?}"))?,
    )
    .wrap_err("cannot parse manifest JSON")?;
    introduce_manifest(&manifest)?;

    let plan = Plan::construct(&manifest, "https://.../", local)?;

    match plan.download_bytes() {
        0 => Ok(()),
        bytes => Err(eyre!(
            "fixing the local cache requires downloading {bytes} bytes"
        )),
    }
}

fn introduce_manifest(manifest: &Manifest) -> Result<(), Report> {
    let dt = match DateTime::<Utc>::from_timestamp(manifest.generated_at as i64, 0) {
        Some(dt) => dt.to_rfc3339(),
        None => return Err(eyre!("manifest has invalid timestamp")),
    };

    info!(comment = manifest.comment, date = dt, "parsed manifest");
    Ok(())
}

struct Plan {
    steps: Vec<PlanStep>,
}

impl Plan {
    /// Form a plan of how to synchronize with the remote server.
    ///
    /// - `manifest` describes the contents of the remote server.
    /// - `remote_url` is the base URL.
    /// - `local` is the path into which files are downloaded.  The caller ensures this exists.
    fn construct(manifest: &Manifest, remote_url: &str, local: &Path) -> Result<Self, Report> {
        let mut steps = Vec::new();

        // Collect unwanted files for deletion
        let mut unwanted_files = HashSet::new();

        if local.exists() {
            for entry in fs::read_dir(local)
                .wrap_err_with(|| format!("failed to read local directory {local:?}"))?
            {
                let path = Path::new(&entry?.file_name()).to_owned();
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

            if exists_locally(filter, &local.join(&filter.filename))? {
                continue;
            }
            steps.push(PlanStep::download(filter, remote_url, local));
        }

        for filename in unwanted_files {
            steps.push(PlanStep::Delete(local.join(filename)));
        }

        steps.push(PlanStep::SaveManifest {
            manifest: manifest.clone(),
            local: local.join(MANIFEST_JSON),
        });

        Ok(Self { steps })
    }

    /// How many bytes will we download?
    fn download_bytes(&self) -> usize {
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
        local: PathBuf,
    },
}

impl PlanStep {
    async fn execute(self, client: &reqwest::Client) -> Result<(), Report> {
        match self {
            Self::CreateDir(path) => fs::create_dir_all(path)
                .wrap_err_with(|| "failed to create local directory {path:?}")?,

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
                    .wrap_err("failed to make download request")?
                    .error_for_status()
                    .wrap_err("HTTP error while downloading")?;

                fs::write(
                    &local,
                    response
                        .bytes()
                        .await
                        .wrap_err("failed to read from response")?,
                )
                .wrap_err_with(|| format!("failed to write to {local:?}"))?;

                if !exists_locally(&filter, &local)? {
                    return Err(eyre!("failed to download {filter:?} -- is the hash wrong?"));
                }

                debug!("download successful");
            }
            Self::Delete(target) => {
                debug!("deleting unreferenced file {target:?}");
                fs::remove_file(&target).wrap_err("failed to delete file")?;
            }
            Self::SaveManifest { manifest, local } => {
                debug!("saving manifest");
                let file = File::create(local).wrap_err("failed to create manifest file")?;
                serde_json::to_writer(file, &manifest).wrap_err("failed to write manifest")?;
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
            Self::SaveManifest { local, .. } => {
                write!(f, "save new manifest to {local:?}")
            }
        }
    }
}

/// Return `Ok(true)` if we have the given filter.
///
/// This reads the file and checks its hash.
fn exists_locally(filter: &Filter, local: &Path) -> Result<bool, Report> {
    if !local.exists() {
        return Ok(false);
    }

    let mut file = File::open(local).wrap_err("failed to open local file")?;
    let mut hasher = digest::Context::new(&digest::SHA256);

    let mut buffer = [0; 4096];
    loop {
        let n = file
            .read(&mut buffer)
            .wrap_err("failed to read file")?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hasher.finish().as_ref() == filter.hash)
}

const MANIFEST_JSON: &str = "manifest.json";
const REQUEST_TIMEOUT: u64 = 30;
