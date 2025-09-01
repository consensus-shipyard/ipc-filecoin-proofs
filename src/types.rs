// Copyright 2022-2024 Protocol Labs
// SPDX-License-Identifier: MIT

use cid::Cid;
use serde::{Deserialize, Serialize};

/// Helper struct to interact with lotus node
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct CIDMap {
    #[serde(rename = "/")]
    pub cid: String,
}

impl From<Cid> for CIDMap {
    fn from(cid: Cid) -> Self {
        Self {
            cid: cid.to_string(),
        }
    }
}

impl From<&str> for CIDMap {
    fn from(cid: &str) -> Self {
        Self {
            cid: cid.to_string(),
        }
    }
}

impl TryFrom<&CIDMap> for Cid {
    type Error = anyhow::Error;

    fn try_from(cid_map: &CIDMap) -> Result<Self, Self::Error> {
        Ok(Cid::try_from(cid_map.cid.as_str())?)
    }
}

impl TryFrom<CIDMap> for Cid {
    type Error = anyhow::Error;

    fn try_from(cid_map: CIDMap) -> Result<Self, Self::Error> {
        Ok(Cid::try_from(cid_map.cid.as_str())?)
    }
}
