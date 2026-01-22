use std::borrow::Cow;

use aws_lc_rs::digest::{SHA256, digest};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use eyre::Result;
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::pki_types::CertificateDer;
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::Oid;
use x509_parser::oid_registry::asn1_rs::oid;
use x509_parser::prelude::FromDer;

#[derive(Debug, Deserialize, Serialize)]
pub struct RevocationTestSites<'a> {
    pub sites: Cow<'a, [RevocationTestSite]>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RevocationTestSite {
    pub ca_sha256_fingerprint: String,
    pub ca_label: String,
    pub test_website_revoked: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<CertificateDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateDetail {
    pub end_entity_cert: String,
    pub issuer_cert: String,
    pub serial: String,
    pub issuer_spki_sha256: String,
    pub scts: Vec<Sct>,
}

impl CertificateDetail {
    pub fn from_chain(certs: &[CertificateDer<'_>]) -> Result<Self> {
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
            serial: BASE64_STANDARD.encode(end_entity.raw_serial()),
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
pub struct Sct {
    pub log_id: String,
    pub timestamp: i64,
}

impl Sct {
    pub fn from_der(sct_list: &[u8], offset: &mut usize) -> Result<Self> {
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
