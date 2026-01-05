use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};

use eyre::{Context, Report};
use serde::{Deserialize, Serialize};

use crate::Manifest;

/// `upki` configuration.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// Configuration for crlite-style revocation.
    pub revocation: RevocationConfig,
}

impl Config {
    /// Load the configuration data from a file at `path`.
    ///
    /// If no file exists at `path`, a default configuration is returned.
    pub fn from_file_or_default(path: &ConfigPath) -> Result<Self, Report> {
        match path {
            ConfigPath::Default(path) if path.exists() => Self::from_file(path),
            ConfigPath::Default(_) => Self::try_default(),
            ConfigPath::Specified(path) => Self::from_file(path),
        }
    }

    /// Load the configuration data from a file at `path`.
    pub fn from_file(path: &Path) -> Result<Self, Report> {
        let config_content = fs::read_to_string(path)
            .wrap_err_with(|| format!("cannot load configuration file from {path:?}"))?;
        toml::from_str(&config_content)
            .wrap_err_with(|| format!("cannot parse configuration file at {path:?}"))
    }

    /// Return a sensible default configuration.
    pub fn try_default() -> Result<Self, Report> {
        Ok(Self {
            revocation: RevocationConfig {
                cache_dir: platform::default_cache_dir()?,
                fetch_url: "https://upki.rustls.dev/".into(),
            },
        })
    }
}

/// Details about crlite-style revocation.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RevocationConfig {
    /// Where to store revocation data files.
    pub cache_dir: PathBuf,

    /// Where to fetch revocation data files.
    pub fetch_url: String,
}

impl RevocationConfig {
    pub fn manifest(&self) -> Result<Manifest, Report> {
        let file_name = self.cache_dir.join("manifest.json");
        serde_json::from_reader(
            File::open(&file_name)
                .map(BufReader::new)
                .wrap_err_with(|| format!("cannot open manifest JSON {file_name:?}"))?,
        )
        .wrap_err("cannot parse manifest JSON")
    }
}

pub enum ConfigPath {
    Specified(PathBuf),
    Default(PathBuf),
}

impl ConfigPath {
    /// Return the path of a configuration file.
    ///
    /// If `specified` is supplied, this path is returned -- no searching is performed
    /// and this function does not return an error.
    ///
    /// This function prefers to return paths to existing files.  If no files exist
    /// according to the (platform-specific) search logic, then a suggested location
    /// is returned where a configuration file can be created if desired.
    ///
    /// This function fails for platform-specific reasons, typically if `$HOME` is not
    /// set, or another XDG environment variable is malformed.
    pub fn new(specified: Option<PathBuf>) -> Result<Self, Report> {
        match specified {
            Some(f) => Ok(Self::Specified(f)),
            None => platform::find_config_file().map(ConfigPath::Default),
        }
    }
}

impl AsRef<Path> for ConfigPath {
    fn as_ref(&self) -> &Path {
        match self {
            Self::Specified(path) => path.as_ref(),
            Self::Default(path) => path.as_ref(),
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use eyre::OptionExt;
    use xdg::BaseDirectories;

    use super::*;

    pub(super) fn find_config_file() -> Result<PathBuf, Report> {
        let bd = BaseDirectories::with_prefix(PREFIX);
        bd.find_config_file(CONFIG_FILE)
            .or_else(|| bd.get_config_file(CONFIG_FILE))
            .ok_or_eyre("cannot determine config file location")
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

    pub(super) fn find_config_file() -> Result<PathBuf, Report> {
        Ok(project_dirs()?
            .config_dir()
            .join(CONFIG_FILE))
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
