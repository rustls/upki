use base64::Engine;
use eyre::{Context, Report, eyre};
use upki::RevocationStatus;

pub(super) fn low_level_revocation_check<'a>(
    cert_serial: &str,
    issuer_spki_hash: &str,
    ct_timestamps: impl Iterator<Item = &'a str>,
    filters: impl Iterator<Item = &'a [u8]>,
) -> Result<RevocationStatus, Report> {
    let cert_serial =
        base64_decode(cert_serial).wrap_err("cannot parse certificate serial number")?;
    let issuer_spki_hash: [u8; 32] = base64_decode(issuer_spki_hash)
        .wrap_err("cannot parse issuer SPKI hash")?
        .try_into()
        .map_err(|wrong: Vec<u8>| {
            eyre!("issuer SPKI is wrong length (was {} bytes)", wrong.len())
        })?;
    let ct_timestamps = ct_timestamps
        .map(ct_timestamp)
        .collect::<Result<Vec<_>, Report>>()?;

    upki::revocation_check(filters, &cert_serial, issuer_spki_hash, &ct_timestamps)
        .map_err(|e| eyre!("{e:?}"))
}
fn base64_decode(str: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(str.as_bytes())
}

fn ct_timestamp(str: &str) -> Result<([u8; 32], u64), Report> {
    let Some((log_id, issuance_timestamp)) = str.split_once(":") else {
        return Err(eyre!("missing colon in CT timestamp"));
    };

    let log_id = base64_decode(log_id)
        .wrap_err("cannot parse CT log ID")?
        .try_into()
        .map_err(|wrong: Vec<u8>| eyre!("CT log ID is wrong length (was {} bytes)", wrong.len()))?;

    let timestamp = issuance_timestamp
        .parse()
        .wrap_err("cannot parse CT issuance time")?;
    Ok((log_id, timestamp))
}
