// Copyright 2022-2024 Protocol Labs
// SPDX-License-Identifier: MIT
mod client;
mod proofs;
mod types;

use crate::client::LotusClient;
use anyhow::Ok;
use cid::Cid;
use fvm_ipld_amt::Amtv0 as Amt;
use fvm_ipld_blockstore::{Blockstore, MemoryBlockstore};
use fvm_ipld_encoding::{CborStore, DAG_CBOR};
use serde::{Deserialize, Serialize};
use serde_json::json;
use types::CIDMap;

// FVM types for AMT operations
use fvm_ipld_encoding::RawBytes;
use fvm_shared::error::ExitCode;
use fvm_shared::receipt::Receipt as MessageReceipt;
// use fvm_shared::event::
use proofs::{generate_bundle_for_subnet, make_check_event_evm, verify_bundle_offline};

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

// ApiTipsetKey is Option<Vec<CIDMap>> (null for null tipset)
pub type ApiTipsetKey = Option<Vec<CIDMap>>;

// BlockMessages types for ChainGetBlockMessages (using Forest's real types)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct BlockMessages {
    #[serde(rename = "BlsMessages")]
    pub bls_msg: Vec<Message>,
    #[serde(rename = "SecpkMessages")]
    pub secp_msg: Vec<SignedMessage>,
    #[serde(rename = "Cids")]
    pub cids: Vec<CIDMap>,
}

// Forest's Message type (from shim/message.rs)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Message {
    pub version: u64,
    pub to: String,
    pub from: String,
    pub nonce: u64,
    pub value: String,
    pub gas_limit: u64,
    pub gas_fee_cap: String,
    pub gas_premium: String,
    pub method: u64,
    pub params: String,
    #[serde(rename = "CID")]
    pub cid: CIDMap,
}

// Forest's SignedMessage type (from message/signed_message.rs)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SignedMessage {
    pub message: Message,
    pub signature: Signature,
    #[serde(rename = "CID")]
    pub cid: CIDMap,
}

// Forest's Signature type
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Signature {
    pub r#type: u8,
    pub data: String,
}

// CBOR 2-tuple [bls_root, secp_root] for TxMeta
#[derive(Serialize)]
struct TxMeta(Cid, Cid);

// Helper struct for extracting CIDs from messages
#[derive(Debug)]
struct MsgWithCid {
    cid: Option<CIDMap>,
    message: Option<Message>,
}

// F3 Finality Certificate types (aligned with Forest implementation)
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FinalityCertificate {
    #[serde(rename = "GPBFTInstance")]
    pub instance: u64,
    #[serde(rename = "ECChain")]
    pub ec_chain: Vec<ECTipSet>,
    pub supplemental_data: SupplementalData,
    pub signers: Vec<u8>,   // BitField as Vec<u8>
    pub signature: Vec<u8>, // Vec<u8>
    pub power_table_delta: Vec<PowerTableDelta>,
}

// TipsetKey as a newtype wrapper (matching Forest's implementation)
// Forest uses SmallCidNonEmptyVec(NonEmpty<SmallCid>) for space optimization
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TipsetKey(pub Vec<CIDMap>); // Simplified version for RPC compatibility

impl TipsetKey {
    /// Returns an iterator of CIDs in the tipset key
    pub fn iter(&self) -> impl Iterator<Item = &CIDMap> {
        self.0.iter()
    }

    /// Returns the number of CIDs in the tipset key
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the tipset key is empty (should never be true in practice)
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the first CID in the tipset key
    pub fn first(&self) -> Option<&CIDMap> {
        self.0.first()
    }

    /// Returns all CIDs as a slice
    pub fn as_slice(&self) -> &[CIDMap] {
        &self.0
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ECTipSet {
    pub key: TipsetKey,       // TipsetKey as newtype wrapper
    pub epoch: i64,           // ChainEpoch
    pub power_table: CIDMap,  // Cid (simplified)
    pub commitments: Vec<u8>, // Vec<u8>
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SupplementalData {
    pub commitments: Vec<u8>, // Vec<u8>
    pub power_table: CIDMap,  // Cid (simplified)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct PowerTableDelta {
    #[serde(rename = "ParticipantID")]
    pub participant_id: u64, // ActorID
    pub power_delta: String, // BigInt as string
    pub signing_key: String, // Vec<u8> as base64 string
}
use url::Url;

fn create_mock_finality_certificate() -> FinalityCertificate {
    FinalityCertificate {
        instance: 1,
        ec_chain: vec![ECTipSet {
            key: TipsetKey(vec![
                CIDMap::from("bafy2bzaceaesqcrmw5payqsgxqptjfmglb25hv5ldawqgf74oryfh4bbnhs2e"),
                CIDMap::from("bafy2bzaceczzcfgsqtdaz6awlvsdupcanl6chqync2olijapwxmagvao5eanc"),
            ]),
            epoch: 2930879,
            power_table: CIDMap::from(
                "bafy2bzacea7vkttjrv3pvia2yhahwi3qgss4ujozels5oxkgkupyvcej7zbdw",
            ),
            commitments: b"commitments epoch 2930879".to_vec(),
        }],
        supplemental_data: SupplementalData {
            commitments: b"supplemental commitments".to_vec(),
            power_table: CIDMap::from(
                "bafy2bzacea7vkttjrv3pvia2yhahwi3qgss4ujozels5oxkgkupyvcej7zbdw",
            ),
        },
        signers: vec![1, 2, 3, 4], // BitField as Vec<u8>
        signature: b"signature data".to_vec(),
        power_table_delta: vec![PowerTableDelta {
            participant_id: 1001,
            power_delta: "1000000000000000000".to_string(),
            signing_key: "c2lnbmluZyBrZXk=".to_string(), // "signing key" in base64
        }],
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = LotusClient::new(
        Url::parse("https://api.calibration.node.glif.io/rpc/v1").unwrap(),
        None,
    );

    let H = 2980106;

    let parent: ApiTipset = client
        .request("Filecoin.ChainGetTipSetByHeight", json!([H, null]))
        .await?;
    let child: ApiTipset = client
        .request("Filecoin.ChainGetTipSetByHeight", json!([H + 1, null]))
        .await?;

    let proof_bundle = generate_bundle_for_subnet(
        &client,
        &parent,
        &child,
        "NewTopDownMessage(bytes32,uint256)",
        "calib-subnet-1",
    )
    .await?;

    // TODO: add real trusted parent ts and child header - this should use the verified F3 certificate
    let is_trusted_parent_ts = |_: i64, _: &[Cid]| true;
    let is_trusted_child_header = |_: i64, _: &Cid| true;

    let check_event = make_check_event_evm("NewTopDownMessage(bytes32,uint256)", "calib-subnet-1");

    let res = verify_bundle_offline(
        &proof_bundle,
        &is_trusted_parent_ts,
        &is_trusted_child_header,
        Some(&check_event),
    )?;

    println!("Verification Result: {:?}", res);

    Ok(())
}
