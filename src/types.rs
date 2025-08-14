// Copyright 2022-2024 Protocol Labs
// SPDX-License-Identifier: MIT

use cid::Cid;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The network version of lotus network.
pub type NetworkVersion = u32;

// ===== Common Types =====

/// F3 Certificate (mocked for now - verifier accepts any bytes)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct F3CertificateBytes(pub Vec<u8>);

/// Block header bundle containing CID and raw DAG-CBOR bytes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeaderBundle {
    pub cid: Cid,     // block header CID (from tipset h+1)
    pub raw: Vec<u8>, // exact DAG-CBOR bytes of that header
}

/// A single IPLD block used in a proof path
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofNode {
    pub cid: Cid,
    pub raw: Vec<u8>, // exact raw bytes (DAG-CBOR)
}

// ===== Receipt Proof Types =====

/// Receipt leaf data from AMT
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptLeaf {
    #[serde(rename = "ExitCode")]
    pub exit_code: i64,
    #[serde(rename = "GasUsed")]
    pub gas_used: u64,
    #[serde(rename = "Return")]
    pub return_data: Vec<u8>,
}

/// AMT proof for receipt inclusion
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptAmtProof {
    pub root: Cid,             // header.ParentMessageReceipts (AMT root)
    pub index: u64,            // position of your message in parent messages
    pub nodes: Vec<ProofNode>, // path nodes root→…→leaf (only those)
    pub leaf: ReceiptLeaf,     // receipt at `index`
}

/// Complete receipt submission with F3 cert, header, and AMT proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptSubmission {
    pub f3_cert: F3CertificateBytes, // mocked
    pub header: BlockHeaderBundle,   // from finalized tipset h+1
    pub amt: ReceiptAmtProof,
}

// ===== Storage Proof Types =====

/// HAMT proof for actor in state tree
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HamtActorProof {
    pub state_root: Cid,          // header.ParentStateRoot
    pub id_address: u64,          // ActorID (resolved at h+1)
    pub nodes: Vec<ProofNode>,    // HAMT path nodes (state tree)
    pub actor_value_raw: Vec<u8>, // raw Actor value bytes (from HAMT leaf)
    pub actor_head: Cid,          // decoded from actor_value_raw: Head
    pub actor_code: Option<Cid>,  // decoded Code CID (optional sanity)
}

/// KAMT proof for storage value in EVM contract
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KamtStorageProof {
    pub root: Cid,              // EVM State.ContractState (KAMT root)
    pub key: [u8; 32],          // 32-byte EVM storage key
    pub nodes: Vec<ProofNode>,  // KAMT path nodes
    pub value: [u8; 32],        // value read at `key`
    pub evm_state_raw: Vec<u8>, // raw bytes of the EVM state object at `actor_head`
}

/// Complete storage submission with F3 cert, header, HAMT and KAMT proofs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageSubmission {
    pub f3_cert: F3CertificateBytes, // mocked
    pub header: BlockHeaderBundle,   // any block of tipset h+1
    pub hamt: HamtActorProof,
    pub kamt: KamtStorageProof,
}

// ===== Lotus RPC Response Types =====

/// Helper struct to interact with lotus node
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct CIDMap {
    #[serde(rename = "/")]
    pub cid: String,
}

/// Response for ChainGetMessage
#[derive(Debug, Deserialize, Clone)]
pub struct ChainGetMessageResponse {
    #[serde(rename = "Version")]
    pub version: u64,
    #[serde(rename = "To")]
    pub to: String,
    #[serde(rename = "From")]
    pub from: String,
    #[serde(rename = "Nonce")]
    pub nonce: u64,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "GasLimit")]
    pub gas_limit: u64,
    #[serde(rename = "GasFeeCap")]
    pub gas_fee_cap: String,
    #[serde(rename = "GasPremium")]
    pub gas_premium: String,
    #[serde(rename = "Method")]
    pub method: u64,
    #[serde(rename = "Params")]
    pub params: String,
    #[serde(rename = "CID")]
    pub cid: CIDMap,
}

/// Response for MpoolGetByCid
#[derive(Debug, Deserialize, Clone)]
pub struct MpoolGetByCidResponse {
    #[serde(rename = "Message")]
    pub message: Message,
    #[serde(rename = "Signature")]
    pub signature: SignatureData,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SignatureData {
    #[serde(rename = "Type")]
    pub sig_type: u8,
    #[serde(rename = "Data")]
    pub data: String,
}

/// Filecoin message structure
#[derive(Debug, Deserialize, Clone)]
pub struct Message {
    #[serde(rename = "Version")]
    pub version: u64,
    #[serde(rename = "To")]
    pub to: String,
    #[serde(rename = "From")]
    pub from: String,
    #[serde(rename = "Nonce")]
    pub nonce: u64,
    #[serde(rename = "Value")]
    pub value: String,
    #[serde(rename = "GasLimit")]
    pub gas_limit: u64,
    #[serde(rename = "GasFeeCap")]
    pub gas_fee_cap: String,
    #[serde(rename = "GasPremium")]
    pub gas_premium: String,
    #[serde(rename = "Method")]
    pub method: u64,
    #[serde(rename = "Params")]
    pub params: Vec<u8>,
}

impl From<Cid> for CIDMap {
    fn from(cid: Cid) -> Self {
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

/// Response for reading state from an actor
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ReadStateResponse<State> {
    pub balance: String,
    pub code: CIDMap,
    pub state: State,
}

/// Message receipt structure
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct MessageReceipt {
    pub exit_code: i64,
    #[serde(rename = "Return")]
    pub return_value: String,
    pub gas_used: u64,
}

/// Response for ChainHead
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ChainHeadResponse {
    pub cids: Vec<CIDMap>,
    pub blocks: Vec<Value>,
    pub height: u64,
}

/// Response for ChainGetTipSetByHeight
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetTipSetByHeightResponse {
    pub cids: Vec<CIDMap>,
    pub blocks: Vec<BlockHeader>,
    pub height: u64,
}

/// Minimal block header structure (we only decode fields we need)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BlockHeader {
    pub parent_state_root: CIDMap,
    pub parent_message_receipts: CIDMap,
}

/// Response for ChainGetTipSet
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetTipSetResponse {
    pub cids: Vec<CIDMap>,
    pub blocks: Vec<Value>,
    pub height: u64,
}

/// Response for EthGetMessageCidByTransactionHash
#[derive(Debug, Deserialize)]
pub struct EthGetMessageCidByTransactionHashResponse {
    pub cid: Option<CIDMap>,
}

/// Response for StateSearchMsg
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct StateSearchMsgResponse {
    pub message: CIDMap,
    pub receipt: MessageReceipt,
    pub tip_set: Vec<CIDMap>,
    pub height: u64,
}

/// Response for ChainGetBlockMessages
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ChainGetBlockMessagesResponse {
    pub bls_messages: Vec<Value>,
    pub secpk_messages: Vec<Value>,
    pub cids: Vec<CIDMap>,
}

/// Response for ChainGetParentReceipts
#[derive(Debug, Deserialize)]
pub struct ChainGetParentReceiptsResponse(pub Vec<MessageReceipt>);

/// Response for ChainGetParentMessages
#[derive(Debug, Deserialize)]
pub struct ChainGetParentMessagesResponse(pub Vec<ParentMessage>);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ParentMessage {
    pub cid: CIDMap,
    pub message: Value,
}

/// Response for ChainReadObj
#[derive(Debug, Deserialize)]
pub enum ChainReadObjResponse {
    #[serde(untagged)]
    Direct(String),
    #[serde(untagged)]
    Wrapped { data: String },
}

/// Response for StateLookupID
#[derive(Debug, Deserialize)]
pub struct StateLookupIDResponse(pub String);

/// Ethereum log event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub block_number: String,
    pub transaction_hash: String,
    pub transaction_index: String,
    pub block_hash: String,
    pub log_index: String,
    pub removed: bool,
}

/// Ethereum transaction receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthTransactionReceipt {
    pub transaction_hash: String,
    pub transaction_index: String,
    pub block_hash: String,
    pub block_number: String,
    pub from: String,
    pub to: Option<String>,
    pub cumulative_gas_used: String,
    pub gas_used: String,
    pub contract_address: Option<String>,
    pub logs: Vec<EthLog>,
    pub logs_bloom: String,
    pub root: Option<String>,
    pub status: String,
}

/// Message execution information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageExecutionInfo {
    pub message_cid: Cid,
    pub execution_tipset: Vec<Cid>,
    pub inclusion_height: u64,
    pub receipt: MessageReceipt,
}

/// Proof configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofConfig {
    pub lotus_rpc: String,
    pub eth_rpc: Option<String>,
    pub chain_id: u64,
}
