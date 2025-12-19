use core::str::FromStr;
use std::fs::File;
use std::sync::Arc;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use eyre::{Report, Result};
use http::Uri;
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::Resumption;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, crypto};
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::Oid;
use x509_parser::oid_registry::asn1_rs::oid;
use x509_parser::prelude::FromDer;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Report> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );

    let provider = Arc::new(crypto::ring::default_provider());
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
            Err(e) => site.error = Some(e.to_string()),
        };

        sites.push(site);
    }

    sites.sort_by(|a, b| {
        a.ca_sha256_fingerprint
            .cmp(&b.ca_sha256_fingerprint)
    });

    serde_json::to_writer_pretty(
        File::create("test-sites.json")?,
        &RevocationTestSites { sites: &sites },
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

#[derive(Debug, Serialize)]
struct RevocationTestSites<'a> {
    sites: &'a [RevocationTestSite],
}

#[derive(Debug, Clone, Serialize)]
struct RevocationTestSite {
    ca_sha256_fingerprint: String,
    ca_label: String,
    test_website_revoked: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<CertificateDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertificateDetail {
    end_entity_cert: String,
    issuer_cert: String,
    serial: String,
    issuer_spki_sha256: String,
    scts: Vec<Sct>,
}

impl CertificateDetail {
    fn from_chain(certs: &[CertificateDer<'_>]) -> Result<Self> {
        if certs.len() < 2 {
            eyre::bail!("no issuer");
        }

        let (_, end_entity) = X509Certificate::from_der(&certs[0])?;
        let sct_ext = end_entity
            .extensions()
            .iter()
            .find(|ext| ext.oid == SCT_OID)
            .ok_or_else(|| eyre::eyre!("missing from ct"))?;

        let sct_list = parse_octet_string(sct_ext.value)?;
        if sct_list.len() < 2 {
            let len = sct_list.len();
            eyre::bail!("SCT list too short: {len} bytes");
        }

        let list_len = u16::from_be_bytes(sct_list[0..2].try_into().unwrap()) as usize;
        let mut offset = 2;
        let mut scts = Vec::new();
        while offset < sct_list.len() && offset < list_len + 2 {
            if offset + 2 > sct_list.len() {
                break;
            }

            scts.push(Sct::from_der(sct_list, &mut offset)?);
        }

        let (_, issuer) = X509Certificate::from_der(&certs[1])?;
        Ok(Self {
            end_entity_cert: BASE64_STANDARD.encode(&certs[0]),
            issuer_cert: BASE64_STANDARD.encode(&certs[1]),
            serial: BASE64_STANDARD.encode(end_entity.serial.to_bytes_be()),
            issuer_spki_sha256: BASE64_STANDARD
                .encode(digest(&SHA256, issuer.public_key().raw).as_ref()),
            scts,
        })
    }
}

fn parse_octet_string(data: &[u8]) -> Result<&[u8]> {
    if data.is_empty() {
        eyre::bail!("empty data");
    } else if data[0] != 0x04 {
        eyre::bail!("not an OCTET STRING");
    }

    let (length, length_bytes) = parse_asn1_length(&data[1..])?;
    let content_start = 1 + length_bytes;
    if content_start + length > data.len() {
        eyre::bail!("OCTET STRING length exceeds data");
    }

    Ok(&data[content_start..content_start + length])
}

fn parse_asn1_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        eyre::bail!("empty length");
    } else if data[0] & 0x80 == 0 {
        return Ok((data[0] as usize, 1));
    }

    let num_octets = (data[0] & 0x7f) as usize;
    if num_octets > 4 || data.len() < 1 + num_octets {
        eyre::bail!("invalid ASN.1 length");
    }

    let mut length = 0usize;
    for i in 0..num_octets {
        length = (length << 8) | (data[1 + i] as usize);
    }

    Ok((length, 1 + num_octets))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Sct {
    log_id: String,
    timestamp: i64,
}

impl Sct {
    fn from_der(sct_list: &[u8], offset: &mut usize) -> Result<Self> {
        let sct_len = u16::from_be_bytes(
            sct_list[*offset..*offset + 2]
                .try_into()
                .unwrap(),
        ) as usize;
        *offset += 2;

        if *offset + sct_len > sct_list.len() {
            let total_len = sct_list.len();
            eyre::bail!(
                "invalid SCT length: offset={offset} sct_len={sct_len} total_len={total_len}"
            );
        }

        let sct_data = &sct_list[*offset..*offset + sct_len];
        if sct_data.len() < 41 {
            eyre::bail!("SCT too short");
        }

        *offset += sct_len;
        Ok(Self {
            log_id: BASE64_STANDARD.encode(&sct_data[1..33]),
            timestamp: i64::from_be_bytes(sct_data[33..41].try_into().unwrap()),
        })
    }
}

const SCT_OID: Oid<'static> = oid!(1.3.6.1.4.1.11129.2.4.2);
const ENTRUST_SUCKS: &[&str] = &["https://entrustrootcertificationauthorityec1.sectigo.com:444"];
