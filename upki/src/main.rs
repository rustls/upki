//! upki command-line entrypoint.

use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::exit;

use clap::{Parser, Subcommand};
use eyre::{Context, Report, eyre};
use upki::RevocationStatus;

mod fetch;
mod revocation;

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

    let command_wants_to_write_cache = matches!(
        args.command,
        Command::Fetch { .. } | Command::ShowCacheDir { read: false }
    );

    let local = match args.cache_dir {
        Some(dir) => dir,
        None => match command_wants_to_write_cache {
            true => upki::cache::writable_default_dir(),
            false => upki::cache::readable_default_dir(),
        }
        .map_err(|e| eyre!(e))
        .wrap_err("cannot determine default cache directory")?,
    };
    tracing::info!("local directory is {local:?}");

    match args.command {
        Command::Fetch { url, dry_run } => fetch::fetch(&local, &url, dry_run).await?,
        Command::Verify => fetch::verify(&local)?,
        Command::ShowCacheDir { .. } => println!("{}", local.display()),
        Command::RevocationCheck {
            cert_serial,
            issuer_spki_hash,
            ct_timestamps,
            error_if_uncovered,
        } => {
            let filters = load_filters(&local)?;

            match revocation::low_level_revocation_check(
                &cert_serial,
                &issuer_spki_hash,
                ct_timestamps.iter().map(|x| x.as_str()),
                filters.iter().map(|x| x.as_slice()),
            )? {
                status @ RevocationStatus::NotCoveredByRevocationData if error_if_uncovered => {
                    println!("{status:?}");
                    exit(EXITCODE_REVOCATION_ERROR)
                }
                status @ RevocationStatus::CertainlyRevoked => {
                    println!("{status:?}");
                    exit(EXITCODE_REVOCATION_REVOKED)
                }
                RevocationStatus::NotRevoked | RevocationStatus::NotCoveredByRevocationData => {}
            }
        }
    }

    Ok(())
}

fn load_filters(local: &Path) -> Result<Vec<Vec<u8>>, Report> {
    let file_name = local.join("manifest.json");
    let manifest: upki::Manifest = serde_json::from_reader(
        File::open(&file_name)
            .map(BufReader::new)
            .wrap_err_with(|| format!("cannot open manifest JSON {file_name:?}"))?,
    )
    .wrap_err("cannot parse manifest JSON")?;

    let mut filters = vec![];
    for f in manifest.filters {
        filters.push(
            fs::read(local.join(&f.filename))
                .wrap_err_with(|| format!("cannot read filter file {}", f.filename))?,
        );
    }
    Ok(filters)
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
    ShowCacheDir {
        /// Assuming we're only going to read files.
        #[arg(long)]
        read: bool,
    },

    /// Checks the revocation status of a certificate.
    ///
    /// This is the low-level API, assuming the caller has the ability to parse the
    /// below fields.
    ///
    /// # Exit codes
    /// - `0`: the certificate is not revoked.
    /// - `1`: the revocation check completed and the certificate is revoked.
    /// - `2`: an error prevented the revocation check.
    RevocationCheck {
        /// The serial number of the end-entity certificate to check.
        ///
        /// This must be the base64 encoding of a big-endian integer, with
        /// any necessary leading byte to ensure the top-bit is unset.
        cert_serial: String,

        /// The SHA256 hash of the issuer's SubjectPublicKeyInfo structure.
        ///
        /// This must be the base64 encoding of precisely 32 bytes.
        issuer_spki_hash: String,

        /// The Certificate Transparency logs and inclusion timestamps extracted
        /// from the end-entity certificate.
        ///
        /// Ths option should be supplied once for each log.
        ///
        /// The format should be the base64 encoding of the CT log id, followed by
        /// a colon, followed by the decimal encoding of the timestamp.
        ct_timestamps: Vec<String>,

        /// Return an error, and exit with code 2, if the certificate is not covered
        /// by the filter set.
        ///
        /// The default behaviour is to treat the certificate as unrevoked.
        #[arg(long)]
        error_if_uncovered: bool,
    },
}

const EXITCODE_REVOCATION_REVOKED: i32 = 1;
const EXITCODE_REVOCATION_ERROR: i32 = 2;
