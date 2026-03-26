use std::process::ExitCode;

use serde::{Deserialize, Serialize};

use crate::Config;
use crate::data::fetch_inner;
use crate::revocation::Error;

/// Update the local intermediates cache by fetching updates over the network.
///
/// `dry_run` means this call fetches the new manifest, but does not fetch any
/// required files; but the necessary files are printed to stdout.  Therefore
/// such a call is not completely "dry" -- perhaps "moist".
pub async fn fetch(dry_run: bool, config: &Config) -> Result<ExitCode, Error> {
    let Some(intermediates) = &config.intermediates else {
        return Ok(ExitCode::SUCCESS);
    };
    let manifest_url = format!("{}{MANIFEST_JSON}", intermediates.fetch_url);
    fetch_inner(
        dry_run,
        &intermediates.fetch_url,
        manifest_url,
        MANIFEST_JSON.to_string(),
        config.intermediates_cache_dir(),
    )
    .await
}

pub(super) const MANIFEST_JSON: &str = "v1-intermediates.json";

/// Details about intermediate preloading.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct IntermediatesConfig {
    /// Whether to fetch things at all.
    enabled: bool,
    /// Where to fetch intermediate certificates.
    fetch_url: String,
}

impl Default for IntermediatesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fetch_url: "https://upki.rustls.dev/".into(),
        }
    }
}
