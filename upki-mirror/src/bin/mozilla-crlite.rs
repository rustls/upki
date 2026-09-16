use core::time::Duration;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use aws_lc_rs::digest::{SHA256, digest};
use clap::{Parser, ValueEnum};
use clubcard_crlite::{CRLiteClubcard, Encoding};
use eyre::{Context, Report, anyhow};
use upki::data::{Manifest, ManifestFile};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Report> {
    let opts = Opts::try_parse()?;
    let source = Source::from(opts.mozilla_backend);

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(Duration::from_secs(opts.http_timeout_secs))
        .user_agent(format!(
            "{}/{} ({})",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_REPOSITORY")
        ))
        .build()
        .wrap_err("failed to create HTTP client")?;

    let response = client
        .get(source.records_url)
        .send()
        .await
        .wrap_err("records request failed")?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "HTTP error for records request: {}",
            response.status()
        ));
    }

    let incoming_manifest = response
        .json::<mozilla::Manifest>()
        .await
        .wrap_err("failed to parse records JSON")?;

    let by_parent: HashMap<String, &mozilla::Item> = HashMap::from_iter(
        incoming_manifest
            .data
            .iter()
            .filter_map(|it| {
                if it.channel != opts.channel {
                    return None;
                }
                Some((it.parent.as_ref()?.clone(), it))
            }),
    );

    // Walk the DAG of filters, starting from the root full filter.
    let root = incoming_manifest
        .data
        .iter()
        .find(|it| !it.incremental && it.parent.is_none() && it.channel == opts.channel)
        .ok_or_else(|| anyhow!("no full filter found for channel {:?}", opts.channel))?;
    let mut next = Some(root);
    let mut download_plan = Vec::new();

    while let Some(item) = next {
        next = by_parent.get(&item.id).copied();
        download_plan.push(item);
    }

    let mut files = Vec::new();

    for p in download_plan {
        let attachment_url = source.attachment_host.to_string() + &p.attachment.location;
        let response = client
            .get(&attachment_url)
            .send()
            .await
            .wrap_err_with(|| format!("download request failed for {attachment_url}"))?;
        let bytes = response.bytes().await?;

        files.push(
            write_filter(
                &opts.output_dir,
                &p.attachment,
                &bytes,
                opts.encoding.into(),
            )
            .wrap_err_with(|| format!("cannot mirror item {} from {attachment_url}", p.id))?,
        );
    }

    let manifest = Manifest {
        generated_at: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        comment: opts.manifest_comment.clone(),
        files,
    };
    let output_filename = opts.output_dir.join("manifest.json");
    fs::write(
        output_filename,
        serde_json::to_string(&manifest)
            .wrap_err("cannot encode JSON manifest")?
            .as_bytes(),
    )
    .wrap_err_with(|| "cannot write manifest to {output_filename:?}")?;

    Ok(())
}

fn write_filter(
    output_dir: &Path,
    attachment: &mozilla::Attachment,
    bytes: &[u8],
    encoding: Encoding,
) -> Result<ManifestFile, Report> {
    // Check the downloaded bytes against Mozilla's metadata.
    let actual_hash = digest(&SHA256, bytes);
    if attachment.hash != actual_hash.as_ref() {
        return Err(anyhow!("downloaded filter does not have correct hash"));
    }

    // A size mismatch is impossible if the hash is correct, but should make us
    // distrust the data.
    if attachment.size != bytes.len() {
        return Err(anyhow!("downloaded filter does not have correct size"));
    }

    let filter = CRLiteClubcard::from_bytes(bytes).wrap_err("cannot decode CRLite filter")?;
    let bytes = if bytes[0] == encoding as u8 {
        Cow::Borrowed(bytes)
    } else {
        Cow::Owned(encode_filter(&filter, encoding)?)
    };

    let output_filename = output_dir.join(&attachment.filename);
    fs::write(&output_filename, &bytes)
        .wrap_err_with(|| format!("cannot write filter data to {output_filename:?}"))?;

    Ok(ManifestFile {
        filename: attachment.filename.clone(),
        size: bytes.len(),
        hash: digest(&SHA256, &bytes)
            .as_ref()
            .to_vec(),
    })
}

fn encode_filter(filter: &CRLiteClubcard, encoding: Encoding) -> Result<Vec<u8>, Report> {
    let mut bytes = filter
        .to_bytes(encoding)
        .wrap_err_with(|| format!("cannot encode CRLite filter as {encoding:?}"))?;

    // clubcard-crlite serializes coverage in HashMap iteration order. Sort the
    // encoded entries by log ID so unchanged filters retain the same hash.
    // Both encodings start with a two-byte version header and a coverage count
    // (u64 in v3's bincode format, u16 in v4), followed by fixed-size entries:
    // a 32-byte log ID and two u64 timestamps. The remaining data is ordered.
    const COVERAGE_ENTRY_SIZE: usize = 32 + 8 + 8;
    let offset = 2 + match encoding {
        Encoding::V3 => 8,
        Encoding::V4 => 2,
    };
    let len = filter.universe().iter().count() * COVERAGE_ENTRY_SIZE;
    let coverage = &mut bytes[offset..offset + len];
    let mut entries: Vec<[u8; COVERAGE_ENTRY_SIZE]> = coverage
        .chunks_exact(COVERAGE_ENTRY_SIZE)
        .map(|entry| entry.try_into().unwrap())
        .collect();
    entries.sort_unstable();
    for (entry, dest) in entries
        .iter()
        .zip(coverage.chunks_exact_mut(COVERAGE_ENTRY_SIZE))
    {
        dest.copy_from_slice(entry);
    }

    Ok(bytes)
}

#[derive(Debug, Parser)]
struct Opts {
    /// Where to write output files.  This must exist.
    output_dir: PathBuf,

    /// Which Mozilla settings backend to fetch from.
    #[clap(default_value_t = MozillaBackend::Production)]
    #[arg(value_enum)]
    mozilla_backend: MozillaBackend,

    /// CRLite channel to mirror (default, compat, other).
    #[clap(long, default_value = "default")]
    channel: mozilla::Channel,

    /// Encoding for mirrored filters.
    #[clap(long, value_enum, default_value = "v4")]
    encoding: FilterEncoding,

    /// Timeout in seconds for all HTTP requests.
    #[clap(long, default_value_t = 10)]
    http_timeout_secs: u64,

    /// Comment included in output manifest.
    #[clap(long, default_value = "")]
    manifest_comment: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum MozillaBackend {
    Production,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FilterEncoding {
    V3,
    V4,
}

impl From<FilterEncoding> for Encoding {
    fn from(value: FilterEncoding) -> Self {
        match value {
            FilterEncoding::V3 => Self::V3,
            FilterEncoding::V4 => Self::V4,
        }
    }
}

struct Source {
    records_url: &'static str,
    attachment_host: &'static str,
}

impl From<MozillaBackend> for Source {
    fn from(value: MozillaBackend) -> Self {
        match value {
            MozillaBackend::Production => MOZILLA_PROD,
        }
    }
}

const MOZILLA_PROD: Source = Source {
    records_url: "https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/cert-revocations/records",
    attachment_host: "https://firefox-settings-attachments.cdn.mozilla.net/",
};

/// JSON structures used in the Mozilla preferences service.
mod mozilla {
    use core::str::FromStr;

    use serde::Deserialize;
    use serde::de::value::{Error, StrDeserializer};

    #[derive(Debug, Deserialize)]
    pub(crate) struct Manifest {
        pub(crate) data: Vec<Item>,
    }

    #[derive(Clone, Debug, Deserialize)]
    pub(crate) struct Item {
        pub(crate) attachment: Attachment,
        pub(crate) channel: Channel,
        pub(crate) id: String,
        pub(crate) incremental: bool,
        pub(crate) parent: Option<String>,
    }

    #[derive(Clone, Debug, Deserialize, PartialEq)]
    #[serde(rename_all = "snake_case")]
    pub(crate) enum Channel {
        Default,
        Compat,
        #[serde(untagged)]
        Other(String),
    }

    impl FromStr for Channel {
        type Err = Error;

        fn from_str(value: &str) -> Result<Self, Self::Err> {
            Self::deserialize(StrDeserializer::new(value))
        }
    }

    #[derive(Clone, Debug, Deserialize)]
    pub(crate) struct Attachment {
        #[serde(with = "hex::serde")]
        pub hash: Vec<u8>,
        pub size: usize,
        pub filename: String,
        pub location: String,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use aws_lc_rs::digest::{SHA256, digest};
    use base64::Engine;
    use clubcard::builder::{ApproximateRibbon, ClubcardBuilder, ExactRibbon};
    use clubcard_crlite::builder::CRLiteBuilderItem;
    use clubcard_crlite::{
        CRLiteClubcard, CRLiteCoverage, CRLiteKey, CRLiteQuery, CRLiteStatus, Encoding,
        IssuerSpkiHash, LogId, Timestamp,
    };
    use serde_json::{Value, json};

    use super::mozilla::{Attachment, Channel, Item, Manifest};
    use super::write_filter;

    #[test]
    fn v3_filters_are_written_as_v4() {
        let original = build_filter(1);
        let bytes = original.to_bytes(Encoding::V3).unwrap();
        let attachment = attachment(&bytes);
        let dir = tempfile::tempdir().unwrap();

        let file = write_filter(dir.path(), &attachment, &bytes, Encoding::V4).unwrap();
        let output = fs::read(dir.path().join(&file.filename)).unwrap();
        assert_eq!(&output[..2], &[4, 0]);
        assert_eq!(file.filename, attachment.filename);
        assert_eq!(file.size, output.len());
        assert_eq!(file.hash, digest(&SHA256, &output).as_ref());
        assert_ne!(file.size, attachment.size);
        assert_ne!(file.hash, attachment.hash);

        let converted = CRLiteClubcard::from_bytes(&output).unwrap();
        // This fixture has one coverage entry, so its v3 encoding is deterministic.
        assert_eq!(
            converted
                .to_bytes(Encoding::V3)
                .unwrap(),
            bytes
        );
        for (serial, expected) in [(0, CRLiteStatus::Revoked), (1, CRLiteStatus::Good)] {
            let serial = [serial];
            let key = CRLiteKey::new(&ISSUER, &serial);
            assert_eq!(
                converted.contains(&key, [(LogId([0; 32]), Timestamp(1000))].into_iter()),
                expected,
            );
        }
    }

    #[test]
    fn v4_filters_are_preserved() {
        let bytes = build_filter(16)
            .to_bytes(Encoding::V4)
            .unwrap();
        let attachment = attachment(&bytes);
        let dir = tempfile::tempdir().unwrap();

        let file = write_filter(dir.path(), &attachment, &bytes, Encoding::V4).unwrap();
        assert_eq!(fs::read(dir.path().join(&file.filename)).unwrap(), bytes);
        assert_eq!(file.filename, attachment.filename);
        assert_eq!(file.size, attachment.size);
        assert_eq!(file.hash, attachment.hash);
    }

    #[test]
    fn legacy_v3_filters_are_preserved() {
        let bytes = build_filter(16)
            .to_bytes(Encoding::V3)
            .unwrap();
        let attachment = attachment(&bytes);
        let dir = tempfile::tempdir().unwrap();

        let file = write_filter(dir.path(), &attachment, &bytes, Encoding::V3).unwrap();
        assert_eq!(fs::read(dir.path().join(&file.filename)).unwrap(), bytes);
        assert_eq!(file.size, attachment.size);
        assert_eq!(file.hash, attachment.hash);
    }

    #[test]
    fn v4_filters_can_be_written_as_legacy_v3() {
        let bytes = build_filter(1)
            .to_bytes(Encoding::V4)
            .unwrap();
        let attachment = attachment(&bytes);
        let dir = tempfile::tempdir().unwrap();

        let file = write_filter(dir.path(), &attachment, &bytes, Encoding::V3).unwrap();
        let output = fs::read(dir.path().join(&file.filename)).unwrap();
        assert_eq!(&output[..2], &[3, 0]);
        assert_eq!(file.size, output.len());
        assert_eq!(file.hash, digest(&SHA256, &output).as_ref());
        let converted = CRLiteClubcard::from_bytes(&output).unwrap();
        assert_eq!(
            converted
                .to_bytes(Encoding::V4)
                .unwrap(),
            bytes
        );
    }

    #[test]
    fn conversion_is_deterministic() {
        for (input, output) in [(Encoding::V3, Encoding::V4), (Encoding::V4, Encoding::V3)] {
            let bytes = build_filter(16)
                .to_bytes(input)
                .unwrap();
            let attachment = attachment(&bytes);
            let dir = tempfile::tempdir().unwrap();

            let first = write_filter(dir.path(), &attachment, &bytes, output).unwrap();
            let expected = fs::read(dir.path().join(&first.filename)).unwrap();
            for _ in 0..8 {
                let next = write_filter(dir.path(), &attachment, &bytes, output).unwrap();
                assert_eq!(next.hash, first.hash);
                assert_eq!(fs::read(dir.path().join(&next.filename)).unwrap(), expected);
            }

            let converted = CRLiteClubcard::from_bytes(&expected).unwrap();
            let mut coverage: Vec<_> = converted
                .universe()
                .iter()
                .map(|(log, interval)| (log.0, interval.low.0, interval.high.0))
                .collect();
            coverage.sort_unstable();
            let expected: Vec<_> = (0u8..16)
                .map(|log| ([log; 32], u64::from(log), 2000 + u64::from(log)))
                .collect();
            assert_eq!(coverage, expected);
        }
    }

    #[test]
    fn invalid_filters_are_not_written() {
        for bytes in [b"".as_slice(), &[3, 0], &[4, 0], &[5, 0], &[3, 1], &[4, 1]] {
            let attachment = attachment(bytes);
            let dir = tempfile::tempdir().unwrap();
            let err = write_filter(dir.path(), &attachment, bytes, Encoding::V4).unwrap_err();
            assert!(
                err.to_string()
                    .contains("cannot decode CRLite filter")
            );
            assert!(
                !dir.path()
                    .join(&attachment.filename)
                    .exists()
            );
        }
    }

    #[test]
    fn downloaded_integrity_is_checked_before_conversion() {
        let bytes = build_filter(1)
            .to_bytes(Encoding::V3)
            .unwrap();
        let valid = attachment(&bytes);
        let dir = tempfile::tempdir().unwrap();

        let mut wrong_hash = valid.clone();
        wrong_hash.hash[0] ^= 1;
        let err = write_filter(dir.path(), &wrong_hash, &bytes, Encoding::V4).unwrap_err();
        assert!(err.to_string().contains("correct hash"));

        let mut wrong_size = valid.clone();
        wrong_size.size += 1;
        let err = write_filter(dir.path(), &wrong_size, &bytes, Encoding::V4).unwrap_err();
        assert!(err.to_string().contains("correct size"));

        assert!(
            !dir.path()
                .join(&valid.filename)
                .exists()
        );
    }

    fn attachment(bytes: &[u8]) -> Attachment {
        Attachment {
            hash: digest(&SHA256, bytes).as_ref().to_vec(),
            size: bytes.len(),
            filename: "test.filter".into(),
            location: "security-state/test".into(),
        }
    }

    fn build_filter(log_count: u8) -> CRLiteClubcard {
        let mut builder = ClubcardBuilder::new();
        let mut approx = builder.new_approx_builder(&ISSUER.0);
        approx.insert(CRLiteBuilderItem::revoked(ISSUER, vec![0]));
        approx.set_universe_size(256);
        builder.collect_approx_ribbons(vec![ApproximateRibbon::from(approx)]);

        let mut exact = builder.new_exact_builder(&ISSUER.0);
        exact.insert(CRLiteBuilderItem::revoked(ISSUER, vec![0]));
        for serial in 1..=u8::MAX {
            exact.insert(CRLiteBuilderItem::not_revoked(ISSUER, vec![serial]));
        }
        builder.collect_exact_ribbons(vec![ExactRibbon::from(exact)]);

        let logs: Vec<_> = (0..log_count)
            .map(|log| {
                json!({
                    "LogID": base64::prelude::BASE64_STANDARD.encode([log; 32]),
                    "MinTimestamp": u64::from(log),
                    "MaxTimestamp": 2000 + u64::from(log),
                    "MMD": 0,
                    "MinEntry": 0,
                })
            })
            .collect();
        let coverage = CRLiteCoverage::from_mozilla_ct_logs_json(
            serde_json::to_vec(&logs)
                .unwrap()
                .as_slice(),
        );
        CRLiteClubcard::from(builder.build::<CRLiteQuery<'_>>(coverage, ()))
    }

    #[test]
    fn known_channels() {
        let manifest = serde_json::from_value::<Manifest>(json!({
            "data": [record("default", "full", None), record("compat", "compat-full", None)],
        }))
        .unwrap();

        assert_eq!(manifest.data[0].channel, Channel::Default);
        assert_eq!(manifest.data[1].channel, Channel::Compat);
    }

    #[test]
    fn unknown_channels_do_not_reject_manifest() {
        let manifest = serde_json::from_value::<Manifest>(json!({
            "data": [
                record("future-v4", "future-full", None),
                record("default", "full", None),
                record("another-channel", "another-full", None),
            ],
        }))
        .unwrap();

        assert_eq!(manifest.data.len(), 3);
        assert_eq!(manifest.data[0].id, "future-full");
        assert_eq!(manifest.data[0].channel, Channel::Other("future-v4".into()));
        assert_eq!(manifest.data[1].channel, Channel::Default);
        assert_eq!(manifest.data[2].id, "another-full");
        assert_eq!(
            manifest.data[2].channel,
            Channel::Other("another-channel".into()),
        );
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let mut item = record("default", "full", None);
        item["new_record_field"] = json!({"nested": [1, "new value"]});
        item["attachment"]["new_attachment_field"] = json!([false, null]);
        let manifest = serde_json::from_value::<Manifest>(json!({
            "data": [item],
            "new_manifest_field": {"version": 42},
        }))
        .unwrap();

        assert_eq!(manifest.data.len(), 1);
        assert_eq!(manifest.data[0].id, "full");
        assert_eq!(manifest.data[0].attachment.filename, "full.filter");
    }

    #[test]
    fn parent_can_be_absent() {
        let mut item = record("default", "full", None);
        item.as_object_mut()
            .unwrap()
            .remove("parent");
        let item = serde_json::from_value::<Item>(item).unwrap();
        assert!(item.parent.is_none());
    }

    #[test]
    fn invalid_required_fields_are_rejected() {
        for channel in [json!(null), json!(42), json!({"name": "default"})] {
            let mut item = record("default", "full", None);
            item["channel"] = channel;
            assert!(serde_json::from_value::<Item>(item).is_err());
        }

        let mut item = record("default", "full", None);
        item["attachment"]["hash"] = json!("not hex");
        assert!(serde_json::from_value::<Item>(item).is_err());

        let mut item = record("default", "full", None);
        item.as_object_mut()
            .unwrap()
            .remove("attachment");
        assert!(serde_json::from_value::<Item>(item).is_err());
    }

    fn record(channel: &str, id: &str, parent: Option<&str>) -> Value {
        json!({
            "attachment": {
                "hash": "00".repeat(32),
                "size": 123,
                "filename": format!("{id}.filter"),
                "location": format!("security-state/{id}"),
            },
            "channel": channel,
            "id": id,
            "incremental": parent.is_some(),
            "parent": parent,
        })
    }

    const ISSUER: IssuerSpkiHash = IssuerSpkiHash([0xaa; 32]);
}
