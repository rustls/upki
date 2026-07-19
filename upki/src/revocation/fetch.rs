//! upki fetcher.
//!
//! This program synchronises a local directory with the crlite files contained on a
//! remote server.  There is a manifest file that gives the names, sizes and hashes of
//! all valid files; this is fetched first. Then a plan is formed by comparing this against
//! the local filesystem contents. Finally, the plan is executed. If that succeeds
//! the remote server contents matches the local filesystem.

use std::process::ExitCode;

use super::Error;
use crate::Config;
use crate::data::{MANIFEST_JSON, fetch_inner};

/// Update the local revocation cache by fetching updates over the network.
///
/// `dry_run` means this call fetches the new manifest, but does not fetch any
/// required files; but the necessary files are printed to stdout.  Therefore
/// such a call is not completely "dry" -- perhaps "moist".
pub async fn fetch(dry_run: bool, config: &Config) -> Result<ExitCode, Error> {
    let manifest_url = format!("{}{MANIFEST_JSON}", config.revocation.fetch_url);
    let old_manifest = super::Manifest::from_config(config)
        .ok()
        .map(|m| m.0);
    fetch_inner(
        dry_run,
        &config.revocation.fetch_url,
        manifest_url,
        &old_manifest,
        config.revocation_cache_dir(),
    )
    .await
}
