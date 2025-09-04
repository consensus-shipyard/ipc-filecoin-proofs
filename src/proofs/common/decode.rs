use anyhow::{Context, Result};
use cid::Cid;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::from_slice;
use fvm_ipld_hamt::{BytesKey, Hamt};
use fvm_shared::{
    address::Address,
    state::{ActorState, StateRoot},
    HAMT_BIT_WIDTH,
};
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor;
use serde_tuple::Deserialize_tuple;

/// Load an actor state from the state tree root
pub fn get_actor_state<BS: Blockstore>(
    store: &BS,
    state_root_cid: &Cid,
    id_addr: Address, // must be an ID address (f0…)
) -> Result<ActorState> {
    // 1) decode the StateRoot
    let state_raw = store
        .get(state_root_cid)?
        .ok_or_else(|| anyhow::anyhow!("missing StateRoot {state_root_cid}"))?;
    let sr: StateRoot = from_slice(&state_raw).context("decode StateRoot")?;

    // 2) open the actors HAMT at sr.actors (use the protocol's default bitwidth)
    let actors =
        Hamt::<_, ActorState>::load_with_bit_width(&sr.actors, store, HAMT_BIT_WIDTH as u32)
            .context("open actors HAMT")?;

    // 3) lookup by key = raw bytes of the ID address
    let key = BytesKey::from(id_addr.to_bytes());
    let actor = actors
        .get(&key)
        .context("actors HAMT get")?
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("actor not found for {id_addr}"))?;

    Ok(actor)
}

/// Strict 32-byte hash (keccak)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytecodeHash(#[serde(with = "fvm_ipld_encoding::strict_bytes")] pub [u8; 32]);

/// Newer layout: [bytecode_cid, bytecode_hash, contract_state_cid, reserved?, nonce, tombstone?]
#[derive(Debug, Deserialize_tuple)]
pub struct EvmStateV6 {
    pub bytecode: Cid,                 // 0
    pub bytecode_hash: BytecodeHash,   // 1 (32 bytes)
    pub contract_state: Cid,           // 2  <-- storage root
    pub reserved: Option<IgnoredAny>,  // 3 (null in your dump)
    pub nonce: u64,                    // 4 (0x01 in your dump)
    pub tombstone: Option<IgnoredAny>, // 5 (null in your dump)
}

/// Older layout: [bytecode_cid, bytecode_hash, contract_state_cid, nonce, tombstone?]
#[derive(Debug, Deserialize_tuple)]
pub struct EvmStateV5 {
    pub bytecode: Cid,                 // 0
    pub bytecode_hash: BytecodeHash,   // 1
    pub contract_state: Cid,           // 2  <-- storage root
    pub nonce: u64,                    // 3
    pub tombstone: Option<IgnoredAny>, // 4
}

/// Simplified EVM state for use in proofs
#[derive(Debug)]
pub struct EvmStateLite {
    pub bytecode: Cid,
    pub bytecode_hash: [u8; 32],
    pub contract_state: Cid,
    pub nonce: u64,
}

/// Parse EVM actor state from raw CBOR bytes
pub fn parse_evm_state(raw: &[u8]) -> Result<EvmStateLite> {
    // Try 6-field first (newer version), then fall back to 5-field.
    if let Ok(v6) = fvm_ipld_encoding::from_slice::<EvmStateV6>(raw) {
        return Ok(EvmStateLite {
            bytecode: v6.bytecode,
            bytecode_hash: v6.bytecode_hash.0,
            contract_state: v6.contract_state,
            nonce: v6.nonce,
        });
    }
    let v5: EvmStateV5 =
        fvm_ipld_encoding::from_slice(raw).context("decode EVM state (5-field)")?;
    Ok(EvmStateLite {
        bytecode: v5.bytecode,
        bytecode_hash: v5.bytecode_hash.0,
        contract_state: v5.contract_state,
        nonce: v5.nonce,
    })
}

/// Lightweight header structure for verification
#[derive(Debug, Deserialize_tuple)]
pub struct HeaderLite {
    _miner: IgnoredAny,               // 0
    _ticket: IgnoredAny,              // 1
    _election_proof: IgnoredAny,      // 2
    _beacon_entries: IgnoredAny,      // 3
    _winpost_proof: IgnoredAny,       // 4
    pub parents: Vec<Cid>,            // 5
    _parent_weight: IgnoredAny,       // 6
    pub height: i64,                  // 7
    pub parent_state_root: Cid,       // 8
    pub parent_message_receipts: Cid, // 9
    pub messages: Cid,                // 10
    _bls_aggregate: IgnoredAny,       // 11
    pub timestamp: u64,               // 12
    _block_sig: IgnoredAny,           // 13
    pub fork_signaling: u64,          // 14
    _parent_base_fee: IgnoredAny,     // 15
}

/// Extract ParentStateRoot from a child header's raw CBOR data
pub fn extract_parent_state_root(raw: &[u8]) -> Result<Cid> {
    let header: HeaderLite = serde_ipld_dagcbor::from_slice(&raw)?;
    Ok(header.parent_state_root)
}
