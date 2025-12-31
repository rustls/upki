//! upki command-line entrypoint.

use std::io::{BufReader, stdin};
use std::path::PathBuf;
use std::process::ExitCode;

use aws_lc_rs::digest;
use clap::{Parser, Subcommand};
use eyre::{Context, ContextCompat, Report, eyre};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, TrustAnchor};
use upki::revocation::{
    CertSerial, CtTimestamp, IssuerSpkiHash, Manifest, RevocationCheckInput, RevocationStatus,
    fetch,
};
use upki::{Config, ConfigPath};

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
        Command::Fetch { dry_run } => fetch(dry_run, &config).await,
        Command::Verify => Manifest::from_config(&config)?.verify(&config),
        Command::ShowConfigPath => unreachable!(),
        Command::ShowConfig => {
            print!(
                "{}",
                toml::to_string_pretty(&config).wrap_err("cannot format configuration")?
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::RevocationCheck(RevocationCheck::High) => {
            let mut certs = vec![];

            for cert in CertificateDer::pem_reader_iter(&mut BufReader::new(stdin())) {
                certs.push(cert.wrap_err("cannot read certificate from stdin")?);
            }

            let (end_entity, rest) = certs
                .split_first()
                .wrap_err("not enough certificates received in stdin")?;
            let end_entity = webpki::EndEntityCert::try_from(end_entity)
                .wrap_err("cannot parse end-entity certificate")?;
            let issuer = find_issuer(rest.iter(), end_entity.issuer())?;
            let issuer_spki_hash = IssuerSpkiHash(
                digest::digest(&digest::SHA256, &webpki::spki_for_anchor(&issuer))
                    .as_ref()
                    .try_into()
                    .expect("sha256 output must be [u8;32]"),
            );

            let mut sct_timestamps = vec![];
            for ts in end_entity
                .sct_log_timestamps()
                .map_err(|e| eyre!("error decoding sct: {e:?}"))?
            {
                let ts = ts.map_err(|e| eyre!("decoding error sct: {e:?}"))?;
                sct_timestamps.push(CtTimestamp {
                    log_id: ts.log_id,
                    timestamp: ts.timestamp_ms,
                });
            }

            revocation_check(
                &RevocationCheckInput {
                    cert_serial: CertSerial(end_entity.serial().into()),
                    issuer_spki_hash,
                    sct_timestamps,
                },
                &config,
            )
        }
        Command::RevocationCheck(RevocationCheck::Detail {
            cert_serial,
            issuer_spki_hash,
            sct_timestamps,
        }) => revocation_check(
            &RevocationCheckInput {
                cert_serial,
                issuer_spki_hash,
                sct_timestamps,
            },
            &config,
        ),
    }
}

fn revocation_check(input: &RevocationCheckInput, config: &Config) -> Result<ExitCode, Report> {
    let manifest = Manifest::from_config(config)?;

    match manifest.check(input, config) {
        Ok(status @ RevocationStatus::CertainlyRevoked) => {
            println!("{status:?}");
            Ok(ExitCode::from(EXIT_CODE_REVOCATION_REVOKED))
        }
        Ok(
            status @ (RevocationStatus::NotRevoked | RevocationStatus::NotCoveredByRevocationData),
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
    /// # Exit codes
    /// - `0`: the certificate is not revoked.
    /// - `1`: the revocation check completed and the certificate is revoked.
    /// - `2`: an error prevented the revocation check.
    #[clap(subcommand)]
    RevocationCheck(RevocationCheck),

    /// Print the location of the configuration file.
    ShowConfigPath,

    /// Print the configuration that will be used.
    ShowConfig,
}

#[derive(Debug, Subcommand)]
enum RevocationCheck {
    /// A "high-level" revocation check operation.
    ///
    /// This interface reads a sequence of PEM-encoded certificates from standard input.
    /// The first **must** be the end-entity certificate.  The end-entity certificate's issuer
    /// **must** be present in the other certificates (but does not need to be in any specific
    /// position).
    ///
    /// Note this interface **only** checks the end-entity certificate for revocation.  It does
    /// **not** check any of the certificates for validity: it assumes the caller has done any
    /// required checks **before** calling this interface (path building, naming validation,
    /// expiry checking, etc.).
    High,

    /// A "low-level" revocation check operation.
    ///
    /// This interface requires the callers to have an X509 parser that can extract
    /// all the required details.  In exchange, it is faster because it involves less IO.
    Detail {
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
}

fn find_issuer<'a>(
    candidates: impl Iterator<Item = &'a CertificateDer<'a>>,
    name: &[u8],
) -> Result<TrustAnchor<'a>, Report> {
    for (i, c) in candidates.enumerate() {
        // nb. do not copy this code. it is not correct to treat intermediate certificates
        // as trust anchors.
        let root = webpki::anchor_from_trusted_cert(c).wrap_err_with(|| {
            format!("cannot parse potential intermediate certificate {}", i + 1)
        })?;
        if root.subject.as_ref() == name {
            return Ok(root);
        }
    }
    Err(eyre::eyre!("cannot find issuer certificate"))
}

const EXIT_CODE_REVOCATION_REVOKED: u8 = 2;
const EXIT_CODE_REVOCATION_ERROR: u8 = 1;
