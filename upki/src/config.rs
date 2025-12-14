use std::fs;
use std::path::{Path, PathBuf};

use eyre::{Context, OptionExt, Report};
use serde::{Deserialize, Serialize};

/// `upki` configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    /// Configuration for crlite-style revocation.
    pub revocation: Revocation,
}

impl Config {
    /// Load the configuration data from a file at `path`.
    pub fn load_from_file(path: &Path) -> Result<Self, Report> {
        let config_content = fs::read_to_string(path)?;
        toml::from_str(&config_content).wrap_err("cannot parse configuration file")
    }

    /// Look for an existing configuration file.
    ///
    /// Returns:
    /// - `Ok(Some(path))` giving the found configuration file path.
    /// - `Ok(None)` if no such configuration file exists.
    /// - `Err(...)` if we couldn't determine if such a file exists (eg, `$HOME` is not set, or another XDG
    ///   environment variable is malformed)
    pub fn find_config_file() -> Result<Option<PathBuf>, Report> {
        Ok(xdg::BaseDirectories::with_prefix(PREFIX).find_config_file(CONFIG_FILE))
    }

    /// Returns the path to a good place to put a configuration file.
    ///
    /// This function does not require or ensure that the returned path exists.
    ///
    /// Any parent directories that are necessary are created.
    pub fn create_preferred_config_path() -> Result<PathBuf, Report> {
        xdg::BaseDirectories::with_prefix(PREFIX)
            .place_config_file(CONFIG_FILE)
            .wrap_err("cannot create preferred configuration path")
    }

    /// Return a sensible default configuration.
    pub fn try_default() -> Result<Self, Report> {
        let cache_dir = xdg::BaseDirectories::with_prefix(PREFIX)
            .get_cache_home()
            .ok_or_eyre("cannot determine default cache directory")?;

        Ok(Self {
            revocation: Revocation {
                cache_dir,
                fetch_url: "https://upki.rustls.dev/".into(),
            },
        })
    }
}

/// Details about crlite-style revocation.
#[derive(Debug, Deserialize, Serialize)]
pub struct Revocation {
    /// Where to store revocation data files.
    pub cache_dir: PathBuf,

    /// Where to fetch revocation data files.
    pub fetch_url: String,
}

const PREFIX: &str = "upki";
const CONFIG_FILE: &str = "config.toml";
