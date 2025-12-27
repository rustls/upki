use core::str::FromStr;
use std::borrow::Cow;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use eyre::{Report, Result};
use http::Uri;
use ring::digest::{SHA256, digest};
use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
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

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| eyre::eyre!("failed to set protocol versions: {e}"))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    tls_config.resumption = Resumption::disabled();
    let tls_connector = TlsConnector::from(Arc::new(tls_config));

    let file = File::open("plain.json")?;
    let reader = BufReader::new(file);
    let input = serde_json::from_reader::<_, TestSites<'_, InputSite>>(reader)?;

    let mut output = Vec::new();
    for input in input.sites.iter() {
        let mut site = OutputSite {
            ca_sha256_fingerprint: input.ca_sha256_fingerprint.clone(),
            ca_label: input.ca_label.clone(),
            test_website_revoked: input.test_website_revoked.clone(),
            error: None,
            detail: None,
        };

        let url = &input.test_website_revoked;
        println!("processing URL: {url}");
        match dissect(url, &tls_connector).await {
            Ok(detail) => site.detail = Some(detail),
            Err(e) => site.error = Some(e.to_string()),
        };

        output.push(site);
        serde_json::to_writer_pretty(
            File::create("decorated.json")?,
            &TestSites {
                sites: Cow::Borrowed(&output),
            },
        )?;
    }

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

    if peer_certs.len() < 2 {
        eyre::bail!("no issuer");
    }
    let (_, end_entity) = X509Certificate::from_der(&peer_certs[0])?;
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

    let list_len = u16::from_be_bytes([sct_list[0], sct_list[1]]) as usize;
    let mut offset = 2;
    let mut scts = Vec::new();

    while offset < sct_list.len() && offset < list_len + 2 {
        if offset + 2 > sct_list.len() {
            break;
        }

        let sct_len = u16::from_be_bytes([sct_list[offset], sct_list[offset + 1]]) as usize;
        offset += 2;

        if offset + sct_len > sct_list.len() {
            let total_len = sct_list.len();
            eyre::bail!(
                "invalid SCT length: offset={offset} sct_len={sct_len} total_len={total_len} list_len={list_len}"
            );
        }

        let sct_data = &sct_list[offset..offset + sct_len];

        if sct_data.len() < 41 {
            eyre::bail!("SCT too short");
        }

        let _version = sct_data[0];
        let log_id = &sct_data[1..33];
        let timestamp_bytes = &sct_data[33..41];
        let timestamp = i64::from_be_bytes([
            timestamp_bytes[0],
            timestamp_bytes[1],
            timestamp_bytes[2],
            timestamp_bytes[3],
            timestamp_bytes[4],
            timestamp_bytes[5],
            timestamp_bytes[6],
            timestamp_bytes[7],
        ]);

        scts.push(Sct {
            log_id: BASE64_STANDARD.encode(log_id),
            timestamp,
        });

        offset += sct_len;
    }

    let (_, issuer) = X509Certificate::from_der(&peer_certs[1])?;
    Ok(CertificateDetail {
        end_entity_cert: BASE64_STANDARD.encode(&peer_certs[0]),
        issuer_cert: BASE64_STANDARD.encode(&peer_certs[1]),
        serial: BASE64_STANDARD.encode(end_entity.serial.to_bytes_be()),
        issuer_spki_sha256: BASE64_STANDARD
            .encode(digest(&SHA256, issuer.public_key().raw).as_ref()),
        scts,
    })
}

fn parse_octet_string(data: &[u8]) -> Result<&[u8]> {
    if data.is_empty() {
        eyre::bail!("empty data");
    }

    if data[0] != 0x04 {
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

#[derive(Debug, Deserialize, Serialize)]
struct TestSites<'a, T: Clone> {
    sites: Cow<'a, [T]>,
}

#[derive(Debug, Clone, Deserialize)]
struct InputSite {
    ca_sha256_fingerprint: String,
    ca_label: String,
    test_website_revoked: String,
}

#[derive(Debug, Clone, Serialize)]
struct OutputSite {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Sct {
    log_id: String,
    timestamp: i64,
}

const SCT_OID: Oid<'static> = oid!(1.3.6.1.4.1.11129.2.4.2);
const ENTRUST_SUCKS: &[&str] = &["https://entrustrootcertificationauthorityec1.sectigo.com:444"];
