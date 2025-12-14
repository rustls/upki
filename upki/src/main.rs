//! upki command-line entrypoint.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use eyre::{Context, Report};
use upki::config::{Config, ConfigPath};

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

    let config_path =
        ConfigPath::new(args.config_file).wrap_err("cannot find configuration path")?;

    if let Command::ShowConfigPath = args.command {
        println!("{}", config_path.as_ref().display());
        return Ok(());
    }

    let config = Config::from_file_or_default(&config_path)?;

    match args.command {
        Command::Fetch { dry_run } => fetch::fetch(&config.revocation, dry_run).await?,
        Command::Verify => fetch::verify(&config.revocation.cache_dir)?,
        Command::ShowConfigPath => unreachable!(),
        Command::ShowConfig => {
            print!(
                "{}",
                toml::to_string_pretty(&config).wrap_err("cannot format configuration")?
            )
        }
    };
    Ok(())
}

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,

    /// Use this specific configuration file.  This must exist.
    ///
    /// If not specified, this tool looks for its configuration file in a platform-standard local directory.
    #[arg(long)]
    config_file: Option<PathBuf>,

    /// Emit logging output.
    #[arg(long)]
    verbose: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Update the local cache of crlite filters, downloading them as needed.
    ///
    /// If the `revocation.cache_dir` path does not exist, this tool creates it and parent directories.
    ///
    /// This also deletes filters that become unreferenced.
    Fetch {
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

    /// Print the location of the configuration file.
    ShowConfigPath,

    /// Print the configuration that will be used.
    ShowConfig,
}
