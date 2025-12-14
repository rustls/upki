use core::error::Error;
use std::path::{Path, PathBuf};

/// Return a sensible default location to read crlite filters from.
///
/// The returned path exists.
pub fn readable_default_dir() -> Result<PathBuf, Box<dyn Error + Send + Sync + 'static>> {
    let local = match writable_default_dir() {
        Ok(local) if local.exists() => return Ok(local),
        local => local,
    };

    for system in SYSTEM_DIRS {
        let system = Path::new(system);
        if system.exists() {
            return Ok(system.to_owned());
        }
    }

    Err(format!("cannot find upki cache location (local {local:?} system {SYSTEM_DIRS:?}").into())
}

/// Return a sensible default location to write crlite filters to.
///
/// The returned path may not exist, and may need to be created by the caller.
///
/// The returned path is always a user-local one; this function never suggests
/// paths that are unwritable by a normal user on a well-configured system.
pub fn writable_default_dir() -> Result<PathBuf, Box<dyn Error + Send + Sync + 'static>> {
    match directories::ProjectDirs::from("dev", "rustls", "upki") {
        Some(dirs) => Ok(dirs.data_local_dir().to_owned()),
        None => Err("cannot determine home directory".into()),
    }
}

const SYSTEM_DIRS: &[&str] = &["/var/cache/upki"];
