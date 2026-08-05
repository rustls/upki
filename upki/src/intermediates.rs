#[cfg(feature = "__fetch")]
use core::iter;

use serde::{Deserialize, Serialize};
#[cfg(feature = "__fetch")]
use tracing::info;

#[cfg(feature = "__fetch")]
use crate::data::Manifest;
#[cfg(feature = "__fetch")]
use crate::fetch::{FetchContext, Plan};
#[cfg(feature = "__fetch")]
use crate::{Config, FetchError};

/// Details about intermediate preloading.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
#[non_exhaustive]
pub struct IntermediatesConfig {
    /// Where to fetch intermediate certificates.
    pub fetch_url: String,
}

impl Default for IntermediatesConfig {
    fn default() -> Self {
        Self {
            fetch_url: "https://upki.rustls.dev/intermediates/".into(),
        }
    }
}

/// Update the local intermediates cache by fetching updates over the network.
///
/// `dry_run` means this call fetches the new manifest, but does not fetch any
/// required files; but the necessary files are printed to stdout.
#[cfg(feature = "__fetch")]
pub(crate) async fn fetch(dry_run: bool, config: &Config) -> Result<(), FetchError> {
    let Some(IntermediatesConfig { fetch_url }) = &config.intermediates else {
        return Ok(());
    };

    let cache_dir = config.intermediates_cache_dir();
    info!("fetching intermediates from {fetch_url} into {cache_dir:?}...",);

    FetchContext {
        cache_dir,
        fetch_url,
        managed_extensions: MANAGED_EXTENSIONS,
        post_process: None,
    }
    .fetch(dry_run)
    .await
}

/// Verify the current contents of the intermediates cache against its manifest.
///
/// This does nothing if intermediate fetching is not enabled.
///
/// This performs disk IO but does not perform network IO.
#[cfg(feature = "__fetch")]
pub fn verify(config: &Config) -> Result<(), FetchError> {
    if config.intermediates.is_none() {
        return Ok(());
    }

    let cache_dir = config.intermediates_cache_dir();
    let manifest = Manifest::from_cache(&cache_dir)?;
    manifest.introduce()?;
    let plan = Plan::construct(
        &manifest,
        None::<iter::Empty<&str>>,
        &FetchContext {
            cache_dir,
            fetch_url: "https://.../",
            managed_extensions: MANAGED_EXTENSIONS,
            post_process: None,
        },
    )?;
    match plan.download_bytes() {
        0 => Ok(()),
        bytes => Err(FetchError::Outdated(bytes)),
    }
}

#[cfg(feature = "__fetch")]
const MANAGED_EXTENSIONS: &[&str] = &["pem"];
