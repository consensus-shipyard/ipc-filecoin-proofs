use crate::proofs::common::bundle::ProofBlock;
use serde::{Deserialize, Serialize};

/// Event data extracted from an ActorEvent for on-chain execution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventData {
    pub emitter: u64,        // actor ID that emitted the event
    pub topics: Vec<String>, // hex-encoded topics (event signature, indexed params)
    pub data: String,        // hex-encoded event data (often ABCI encoded for cross-chain)
}

/// Event proof claim that proves a specific event occurred in a block
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventProof {
    pub parent_epoch: i64,
    pub child_epoch: i64,
    pub parent_tipset_cids: Vec<String>, // ordered tipset key of H
    pub child_block_cid: String,         // block header CID of H+1
    pub message_cid: String,             // the message that produced the event
    pub exec_index: u64,                 // index of the execution in the parent tipset
    pub event_index: u64,                // index of the event in the receipt
    pub event_data: EventData,           // the actual event content for on-chain execution
}

/// Bundle containing event proofs and all necessary witness blocks for verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventProofBundle {
    pub proofs: Vec<EventProof>,
    pub blocks: Vec<ProofBlock>, // deduped raw IPLD blocks needed for verification
}
