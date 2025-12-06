//! upki command-line entrypoint.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use eyre::{Report, eyre};

mod fetch;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Report> {
    let args = Args::parse();
    if args.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .compact()
            .init();
    }

    let local = match args.cache_dir {
        Some(dir) => dir,
        None => match directories::ProjectDirs::from("dev", "rustls", "upki") {
            Some(dirs) => dirs.data_local_dir().to_owned(),
            None => return Err(eyre!("cannot determine home directory")),
        },
    };
    tracing::info!("local directory is {local:?}");

    match args.command {
        Command::Fetch { url, dry_run } => fetch::fetch(&local, &url, dry_run).await?,
        Command::Verify => fetch::verify(&local)?,
        Command::ShowCacheDir => println!("{}", local.display()),
    }

    Ok(())
}

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,

    /// Where to find and save the local files.
    ///
    /// If not specified, this tool uses a platform-standard, local data directory.
    #[arg(long)]
    cache_dir: Option<PathBuf>,

    /// Emit logging output.
    #[arg(long)]
    verbose: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Update the local cache of crlite filters, downloading them as needed.
    ///
    /// If the `--cache-dir` path does not exist, this tool creates it and parent directories.
    ///
    /// This also deletes filters that become unreferenced.
    Fetch {
        /// The remote URL.
        #[arg(default_value = "https://upki.rustls.dev/")]
        url: String,

        /// Download the new manifest, and then describe what actions are needed to
        /// synchronize with the remote server.
        #[arg(long)]
        dry_run: bool,
    },

    /// Verifies the local cache of crlite filters.
    ///
    /// Exits zero if the manifest and all referenced filters are present.
    ///
    /// Exits non-zero if the manifest if any filter file is missing or corrupt.
    ///
    /// This command does no network I/O.  It does not say anything whether the files are up-to-date or recent.
    Verify,

    /// Print the location of the local cache directory.
    ShowCacheDir,
}
