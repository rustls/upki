use core::str::FromStr;
use std::borrow::Cow;
use std::fs::File;
use std::sync::Arc;

use eyre::{Report, Result};
use http::Uri;
use revoke_test::{CertificateDetail, RevocationTestSite, RevocationTestSites};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::Resumption;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, crypto};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Report> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );

    let provider = Arc::new(crypto::aws_lc_rs::default_provider());
    let mut tls_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| eyre::eyre!("failed to set protocol versions: {e}"))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    tls_config.resumption = Resumption::disabled();
    let tls_connector = TlsConnector::from(Arc::new(tls_config));

    let mut sites = Vec::new();
    let metadata = webpki_ccadb::fetch_ccadb_roots().await;
    for metadata in metadata.into_values() {
        let mut site = RevocationTestSite {
            ca_sha256_fingerprint: metadata.sha256_fingerprint,
            ca_label: metadata.common_name_or_certificate_name,
            test_website_revoked: metadata.test_website_revoked,
            error: None,
            detail: None,
        };

        let url = &site.test_website_revoked;
        println!("processing URL: {url}");
        match dissect(url, &tls_connector).await {
            Ok(detail) => site.detail = Some(detail),
            Err(e) => {
                println!("failed: {e}");
                site.error = Some(e.to_string())
            }
        };

        sites.push(site);
    }

    sites.sort_by(|a, b| {
        a.ca_sha256_fingerprint
            .cmp(&b.ca_sha256_fingerprint)
    });

    serde_json::to_writer_pretty(
        File::create("test-sites.json")?,
        &RevocationTestSites {
            sites: Cow::Borrowed(&sites),
        },
    )?;

    Ok(())
}

async fn dissect(url: &str, tls_connector: &TlsConnector) -> Result<CertificateDetail> {
    if ENTRUST_SUCKS.contains(&url) {
        eyre::bail!("entrust cannot run a website");
    }

    // Parse URL to extract host and port
    let url_parsed = Uri::from_str(url)?;
    let host = url_parsed
        .host()
        .ok_or_else(|| eyre::eyre!("no host in URL"))?;
    let port = match url_parsed.port() {
        Some(port) => port.as_u16(),
        None => 443,
    };

    // Connect via TCP
    let tcp_stream = TcpStream::connect(format!("{host}:{port}")).await?;

    // Perform TLS handshake
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|e| eyre::eyre!("invalid server name: {e}"))?;
    let tls_stream = tls_connector
        .connect(server_name, tcp_stream)
        .await?;

    // Get peer certificates from the connection
    let (_io, conn) = tls_stream.get_ref();
    let peer_certs = conn
        .peer_certificates()
        .ok_or_else(|| eyre::eyre!("no peer certificates"))?;

    CertificateDetail::from_chain(peer_certs)
}

const ENTRUST_SUCKS: &[&str] = &["https://entrustrootcertificationauthorityec1.sectigo.com:444"];
