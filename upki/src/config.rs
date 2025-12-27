use std::fs;
use std::path::{Path, PathBuf};

use eyre::{Context, Report};
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
        platform::find_config_file()
    }

    /// Returns the path to a good place to put a configuration file.
    ///
    /// This function does not require or ensure that the returned path exists.
    ///
    /// Any parent directories that are necessary are created.
    pub fn create_preferred_config_path() -> Result<PathBuf, Report> {
        platform::create_preferred_config_path()
    }

    /// Return a sensible default configuration.
    pub fn try_default() -> Result<Self, Report> {
        Ok(Self {
            revocation: Revocation {
                cache_dir: platform::default_cache_dir()?,
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

#[cfg(target_os = "linux")]
mod platform {
    use eyre::OptionExt;
    use xdg::BaseDirectories;

    use super::*;

    pub(super) fn find_config_file() -> Result<Option<PathBuf>, Report> {
        Ok(BaseDirectories::with_prefix(PREFIX).find_config_file(CONFIG_FILE))
    }

    pub(super) fn create_preferred_config_path() -> Result<PathBuf, Report> {
        BaseDirectories::with_prefix(PREFIX)
            .place_config_file(CONFIG_FILE)
            .wrap_err("cannot create preferred configuration path")
    }

    pub(super) fn default_cache_dir() -> Result<PathBuf, Report> {
        BaseDirectories::with_prefix(PREFIX)
            .get_cache_home()
            .ok_or_eyre("cannot determine default cache directory")
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use directories::ProjectDirs;

    use super::*;

    pub(super) fn find_config_file() -> Result<Option<PathBuf>, Report> {
        let path = project_dirs()?
            .config_dir()
            .join(CONFIG_FILE);
        match path.exists() {
            true => Ok(Some(path)),
            false => Ok(None),
        }
    }

    pub(super) fn create_preferred_config_path() -> Result<PathBuf, Report> {
        let path = project_dirs()?
            .config_dir()
            .join(CONFIG_FILE);
        fs::create_dir_all(&path).wrap_err("cannot create preferred configuration path")?;
        Ok(path)
    }

    pub(super) fn default_cache_dir() -> Result<PathBuf, Report> {
        Ok(project_dirs()?.cache_dir().to_owned())
    }

    fn project_dirs() -> Result<ProjectDirs, Report> {
        ProjectDirs::from("dev", "rustls", PREFIX)
            .ok_or_else(|| eyre::eyre!("cannot determine project directory"))
    }
}

const PREFIX: &str = "upki";
const CONFIG_FILE: &str = "config.toml";
