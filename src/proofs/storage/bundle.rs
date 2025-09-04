use serde::{Deserialize, Serialize};

/// Storage proof claim that proves a specific storage slot value at a given block
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StorageProof {
    pub child_epoch: i64,
    pub child_block_cid: String,   // block header CID of H+1
    pub parent_state_root: String, // from child header
    pub actor_id: u64,             // the ID address of the actor
    pub actor_state_cid: String,   // the EVM actor state 'Head' CID
    pub storage_root: String,      // storage HAMT root CID
    pub slot: String,              // 0x...32 bytes
    pub value: String,             // 0x...32-byte value
}
