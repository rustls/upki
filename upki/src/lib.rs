#![doc = include_str!("../../README.md")]
#![warn(missing_docs)]

use core::error::Error as StdError;
use std::path::{Path, PathBuf};
use std::{fmt, fs, io};

use serde::{Deserialize, Serialize};

use crate::revocation::RevocationConfig;

/// `upki` configuration.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    /// Where to store cache files.
    cache_dir: PathBuf,

    /// Configuration for crlite-style revocation.
    pub revocation: RevocationConfig,
}

impl Config {
    /// Load the configuration data from a file at `path`.
    ///
    /// If no file exists at `path`, a default configuration is returned.
    pub fn from_file_or_default(path: &ConfigPath) -> Result<Self, Error> {
        match path {
            ConfigPath::Default(path) if path.exists() => Self::from_file(path),
            ConfigPath::Default(_) => Self::try_default(),
            ConfigPath::Specified(path) => Self::from_file(path),
        }
    }

    /// Load the configuration data from a file at `path`.
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let config_content = fs::read_to_string(path).map_err(|error| Error::FileRead {
            error,
            path: path.to_owned(),
        })?;

        toml::from_str(&config_content).map_err(|error| Error::ConfigError {
            error: Box::new(error),
            path: path.to_owned(),
        })
    }

    /// Return a sensible default configuration.
    pub fn try_default() -> Result<Self, Error> {
        Ok(Self {
            cache_dir: platform::default_cache_dir()?,
            revocation: RevocationConfig::default(),
        })
    }

    pub(crate) fn revocation_cache_dir(&self) -> PathBuf {
        self.cache_dir.join("revocation")
    }
}

/// How the path to a configuration file was decided upon.
pub enum ConfigPath {
    /// The path was directly specified by a user.
    Specified(PathBuf),
    /// The path was determined automatically.
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
    pub fn new(specified: Option<PathBuf>) -> Result<Self, Error> {
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
    use xdg::BaseDirectories;

    use super::*;

    pub(super) fn find_config_file() -> Result<PathBuf, Error> {
        let bd = BaseDirectories::with_prefix(PREFIX);
        bd.find_config_file(CONFIG_FILE)
            .or_else(|| bd.get_config_file(CONFIG_FILE))
            .ok_or(Error::NoConfigDirectoryFound)
    }

    pub(super) fn default_cache_dir() -> Result<PathBuf, Error> {
        BaseDirectories::with_prefix(PREFIX)
            .get_cache_home()
            .ok_or(Error::NoCacheDirectoryFound)
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use directories::ProjectDirs;

    use super::*;

    pub(super) fn find_config_file() -> Result<PathBuf, Error> {
        Ok(project_dirs()?
            .config_dir()
            .join(CONFIG_FILE))
    }

    pub(super) fn default_cache_dir() -> Result<PathBuf, Error> {
        Ok(project_dirs()?.cache_dir().to_owned())
    }

    fn project_dirs() -> Result<ProjectDirs, Error> {
        ProjectDirs::from("dev", "rustls", PREFIX).ok_or(Error::NoValidHomeDirectory)
    }
}

/// Errors for the upki library API.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// Failed to decode configuration file at `path`.
    ConfigError {
        /// Underlying error.
        error: Box<dyn StdError + Send + Sync>,
        /// Path to the configuration file.
        path: PathBuf,
    },
    /// Failed to read configuration file at `path`.
    FileRead {
        /// Underlying error.
        error: io::Error,
        /// Path to the configuration file.
        path: PathBuf,
    },
    /// No cache directory could be found.
    NoCacheDirectoryFound,
    /// No configuration directory could be found.
    NoConfigDirectoryFound,
    /// The user's home directory could not be determined.
    NoValidHomeDirectory,
    /// Error from the revocation API.
    Revocation(revocation::Error),
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::ConfigError { error, .. } => Some(error.as_ref()),
            Self::FileRead { error, .. } => Some(error),
            Self::NoCacheDirectoryFound
            | Self::NoConfigDirectoryFound
            | Self::NoValidHomeDirectory => None,
            Self::Revocation(err) => Some(err),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigError { path, .. } => {
                write!(f, "failed to parse config file at {}", path.display())
            }
            Self::FileRead { path, .. } => {
                write!(f, "failed to read config file at {}", path.display())
            }
            Self::NoCacheDirectoryFound => write!(f, "no cache directory could be found"),
            Self::NoConfigDirectoryFound => write!(f, "no configuration directory could be found"),
            Self::NoValidHomeDirectory => write!(f, "could not determine user's home directory"),
            Self::Revocation(_) => write!(f, "revocation error"),
        }
    }
}

const PREFIX: &str = "upki";
const CONFIG_FILE: &str = "config.toml";

/// Determining revocation status of publicly trusted certificates.
pub mod revocation;
