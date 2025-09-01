// Copyright 2022-2024 Protocol Labs
// SPDX-License-Identifier: MIT

use cid::Cid;
use fvm_ipld_encoding::RawBytes;
use fvm_shared::error::ExitCode;
use fvm_shared::receipt::Receipt as MessageReceipt;
use serde::{Deserialize, Serialize};

// Lotus JSON types for RPC communication
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ApiReceipt {
    pub exit_code: u32, // ExitCode value
    #[serde(rename = "Return")]
    pub return_data: String, // Base64 encoded RawBytes
    pub gas_used: u64,
    pub events_root: Option<CIDMap>,
}

// Conversion from ApiReceipt to FVM Receipt for AMT operations
impl From<ApiReceipt> for MessageReceipt {
    fn from(api_receipt: ApiReceipt) -> Self {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        let return_data = BASE64.decode(&api_receipt.return_data).unwrap_or_default();

        MessageReceipt {
            exit_code: ExitCode::new(api_receipt.exit_code),
            return_data: RawBytes::new(return_data),
            gas_used: api_receipt.gas_used,
            events_root: api_receipt
                .events_root
                .and_then(|cid_map| Cid::try_from(cid_map.cid.as_str()).ok()),
        }
    }
}

// Tipset types for ChainGetTipSetByHeight
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ApiTipset {
    pub cids: Vec<CIDMap>,
    pub blocks: Vec<ApiBlockHeader>,
    pub height: i64,
}

// Simplified block header with only essential fields
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ApiBlockHeader {
    pub miner: String,                   // Miner address
    pub parents: Vec<CIDMap>,            // Parent tipset CIDs
    pub parent_state_root: CIDMap,       // State root
    pub parent_message_receipts: CIDMap, // Message receipts root
    pub messages: CIDMap,                // Messages root
    pub height: i64,                     // Block height
}

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
