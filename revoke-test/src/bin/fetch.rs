use eyre::Report;
use serde::Serialize;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Report> {
    let mut sites = RevocationTestSites {
        sites: webpki_ccadb::fetch_ccadb_roots()
            .await
            .into_values()
            .map(|item| RevocationTestSite {
                ca_sha256_fingerprint: item.sha256_fingerprint,
                ca_label: item.common_name_or_certificate_name,
                test_website_revoked: item.test_website_revoked,
            })
            .collect(),
    };
    sites.sites.sort_by(|a, b| {
        a.ca_sha256_fingerprint
            .cmp(&b.ca_sha256_fingerprint)
    });
    serde_json::to_writer_pretty(&std::io::stdout(), &sites)?;
    Ok(())
}

#[derive(Debug, Serialize)]
struct RevocationTestSites {
    sites: Vec<RevocationTestSite>,
}

#[derive(Debug, Serialize)]
struct RevocationTestSite {
    ca_sha256_fingerprint: String,
    ca_label: String,
    test_website_revoked: String,
}
