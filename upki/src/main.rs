//! upki command-line entrypoint.

use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::exit;

use clap::{Parser, Subcommand};
use eyre::{Context, Report};
use upki::config::{Config, ConfigPath};
use upki::{CertSerial, CtTimestamp, IssuerSpkiHash, RevocationStatus};

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
        Command::RevocationCheck {
            cert_serial,
            issuer_spki_hash,
            ct_timestamps,
        } => {
            let filters = load_filters(&config.revocation.cache_dir)?;
            let ct_timestamps = ct_timestamps
                .into_iter()
                .map(|item| (item.log_id, item.timestamp))
                .collect::<Vec<_>>();

            match upki::revocation_check(
                filters.iter().map(|f| f.as_slice()),
                &cert_serial.0,
                issuer_spki_hash.0,
                &ct_timestamps,
            ) {
                Ok(status @ RevocationStatus::CertainlyRevoked) => {
                    println!("{status:?}");
                    exit(EXIT_CODE_REVOCATION_REVOKED)
                }
                Ok(
                    status @ (RevocationStatus::NotRevoked
                    | RevocationStatus::NotCoveredByRevocationData),
                ) => {
                    println!("{status:?}");
                }
                Err(e) => {
                    println!("{e:?}");
                    exit(EXIT_CODE_REVOCATION_ERROR);
                }
            }
        }
    };
    Ok(())
}

fn load_filters(local: &Path) -> Result<Vec<Vec<u8>>, Report> {
    let file_name = local.join("manifest.json");
    let manifest = serde_json::from_reader::<_, upki::Manifest>(
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
        cert_serial: CertSerial,

        /// The SHA256 hash of the issuer's SubjectPublicKeyInfo structure.
        ///
        /// This must be the base64 encoding of precisely 32 bytes.
        issuer_spki_hash: IssuerSpkiHash,

        /// The Certificate Transparency logs and inclusion timestamps extracted
        /// from the end-entity certificate.
        ///
        /// Ths option should be supplied once for each log.
        ///
        /// The format should be the base64 encoding of the CT log id, followed by
        /// a colon, followed by the decimal encoding of the timestamp.
        ct_timestamps: Vec<CtTimestamp>,
    },
    /// Print the location of the configuration file.
    ShowConfigPath,

    /// Print the configuration that will be used.
    ShowConfig,
}

const EXIT_CODE_REVOCATION_REVOKED: i32 = 1;
const EXIT_CODE_REVOCATION_ERROR: i32 = 2;
