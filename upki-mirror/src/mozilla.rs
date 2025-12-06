//! JSON structures used in the Mozilla preferences service.

use serde::Deserialize;

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
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Attachment {
    #[serde(with = "hex::serde")]
    pub hash: Vec<u8>,
    pub size: usize,
    pub filename: String,
    pub location: String,
}
