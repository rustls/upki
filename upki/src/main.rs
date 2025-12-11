//! upki command-line entrypoint.

use core::str::FromStr;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::exit;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use clap::{Parser, Subcommand};
use eyre::{Context, Report, eyre};
use upki::RevocationStatus;
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
                    exit(EXITCODE_REVOCATION_REVOKED)
                }
                Ok(
                    status @ (RevocationStatus::NotRevoked
                    | RevocationStatus::NotCoveredByRevocationData),
                ) => {
                    println!("{status:?}");
                }
                Err(e) => {
                    println!("{e:?}");
                    exit(EXITCODE_REVOCATION_ERROR);
                }
            }
        }
    };
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

#[derive(Clone, Debug)]
struct CertSerial(Vec<u8>);

impl FromStr for CertSerial {
    type Err = Report;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        BASE64_STANDARD
            .decode(value)
            .wrap_err("cannot parse serial number")
            .map(Self)
    }
}

#[derive(Clone, Debug)]
struct IssuerSpkiHash([u8; 32]);

impl FromStr for IssuerSpkiHash {
    type Err = Report;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = BASE64_STANDARD
            .decode(value)
            .wrap_err("cannot parse issuer SPKI hash")?;
        Ok(Self(bytes.try_into().map_err(|b: Vec<u8>| {
            eyre!("issuer SPKI hash is wrong length (was {} bytes)", b.len())
        })?))
    }
}

#[derive(Clone, Debug)]
struct CtTimestamp {
    log_id: [u8; 32],
    timestamp: u64,
}

impl FromStr for CtTimestamp {
    type Err = Report;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some((log_id, issuance_timestamp)) = value.split_once(":") else {
            return Err(eyre!("missing colon in CT timestamp"));
        };

        let log_id = BASE64_STANDARD
            .decode(log_id)
            .wrap_err("cannot parse CT log ID")?
            .try_into()
            .map_err(|wrong: Vec<u8>| {
                eyre!("CT log ID is wrong length (was {} bytes)", wrong.len())
            })?;

        let timestamp = issuance_timestamp
            .parse()
            .wrap_err("cannot parse CT timestamp")?;

        Ok(Self { log_id, timestamp })
    }
}

const EXITCODE_REVOCATION_REVOKED: i32 = 1;
const EXITCODE_REVOCATION_ERROR: i32 = 2;
