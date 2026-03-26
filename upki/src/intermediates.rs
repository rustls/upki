use serde::{Deserialize, Serialize};

/// Details about intermediate preloading.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct IntermediatesConfig {
    /// Whether to fetch things at all.
    enabled: bool,
    /// Where to fetch intermediate certificates.
    fetch_url: String,
}

impl Default for IntermediatesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fetch_url: "https://upki.rustls.dev/".into(),
        }
    }
}
