use crate::proofs::common::bundle::ProofBlock;
use serde::{Deserialize, Serialize};

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
}

/// Bundle containing event proofs and all necessary witness blocks for verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventProofBundle {
    pub proofs: Vec<EventProof>,
    pub blocks: Vec<ProofBlock>, // deduped raw IPLD blocks needed for verification
}
