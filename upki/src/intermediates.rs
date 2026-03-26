use serde::{Deserialize, Serialize};

/// Details about intermediate preloading.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields, default)]
#[non_exhaustive]
pub struct IntermediatesConfig {
    /// Where to fetch intermediate certificates.
    pub fetch_url: String,
}

impl Default for IntermediatesConfig {
    fn default() -> Self {
        Self {
            fetch_url: "https://upki.rustls.dev/intermediates/".into(),
        }
    }
}
