//! upki command-line entrypoint.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use eyre::{Context, Report};
use upki::{
    CertSerial, Config, ConfigPath, CtTimestamp, IssuerSpkiHash, Manifest, RevocationCheckInput,
    RevocationStatus,
};

mod fetch;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<ExitCode, Report> {
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
        return Ok(ExitCode::SUCCESS);
    }

    let config = Config::from_file_or_default(&config_path)?;

    match args.command {
        Command::Fetch { dry_run } => fetch::fetch(&config.revocation, dry_run).await,
        Command::Verify => fetch::verify(&config.revocation.cache_dir),
        Command::ShowConfigPath => unreachable!(),
        Command::ShowConfig => {
            print!(
                "{}",
                toml::to_string_pretty(&config).wrap_err("cannot format configuration")?
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::RevocationCheck {
            cert_serial,
            issuer_spki_hash,
            sct_timestamps,
        } => {
            let manifest = Manifest::from_config(&config.revocation)?;
            let input = RevocationCheckInput {
                cert_serial,
                issuer_spki_hash,
                sct_timestamps,
            };

            match manifest.check(&input, &config.revocation) {
                Ok(status @ RevocationStatus::CertainlyRevoked) => {
                    println!("{status:?}");
                    Ok(ExitCode::from(EXIT_CODE_REVOCATION_REVOKED))
                }
                Ok(
                    status @ (RevocationStatus::NotRevoked
                    | RevocationStatus::NotCoveredByRevocationData),
                ) => {
                    println!("{status:?}");
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    println!("{e:?}");
                    Ok(ExitCode::from(EXIT_CODE_REVOCATION_ERROR))
                }
            }
        }
    }
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
        sct_timestamps: Vec<CtTimestamp>,
    },
    /// Print the location of the configuration file.
    ShowConfigPath,

    /// Print the configuration that will be used.
    ShowConfig,
}

const EXIT_CODE_REVOCATION_REVOKED: u8 = 2;
const EXIT_CODE_REVOCATION_ERROR: u8 = 1;
