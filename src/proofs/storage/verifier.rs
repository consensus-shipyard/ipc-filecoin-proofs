use anyhow::{anyhow, Context, Result};
use cid::Cid;
use fvm_ipld_blockstore::{Blockstore, MemoryBlockstore};
use fvm_shared::address::Address;
use hex;

use crate::proofs::common::{
    bundle::ProofBlock,
    decode::{extract_parent_state_root, get_actor_state, parse_evm_state},
    evm::left_pad_32,
    witness::parse_cid,
};
use crate::proofs::storage::{bundle::StorageProof, decode::read_storage_slot};

/// Verify a storage proof offline using the provided witness blocks
///
/// # Arguments
/// * `proof` - The storage proof to verify
/// * `blocks` - Witness blocks containing all necessary data
/// * `is_trusted_child_header` - Function to verify if a child header is trusted/finalized
///
/// # Returns
/// `true` if the proof is valid, `false` otherwise
pub fn verify_storage_proof(
    proof: &StorageProof,
    blocks: &[ProofBlock],
    is_trusted_child_header: &dyn Fn(i64, &Cid) -> bool,
) -> Result<bool> {
    // Step 1: Load witness blocks into local store
    let blockstore = load_witness_store(blocks)?;

    // Step 2: Verify trust anchor (child header is finalized)
    if !verify_trust_anchor(proof, is_trusted_child_header)? {
        return Ok(false);
    }

    // Step 3: Verify parent state root from child header
    let child_cid = parse_cid(&proof.child_block_cid, "child block")?;
    if !verify_parent_state_root(&blockstore, &child_cid, &proof.parent_state_root)? {
        return Ok(false);
    }

    // Step 4: Verify actor state exists in state tree
    let parent_state_root = parse_cid(&proof.parent_state_root, "parent state root")?;
    if !verify_actor_state(
        &blockstore,
        &parent_state_root,
        proof.actor_id,
        &proof.actor_state_cid,
    )? {
        return Ok(false);
    }

    // Step 5: Verify storage root from EVM state
    let actor_state_cid = parse_cid(&proof.actor_state_cid, "actor state")?;
    if !verify_storage_root(&blockstore, &actor_state_cid, &proof.storage_root)? {
        return Ok(false);
    }

    // Step 6: Verify storage value at slot
    let storage_root = parse_cid(&proof.storage_root, "storage root")?;
    verify_storage_value(&blockstore, &storage_root, &proof.slot, &proof.value)
}

// --- Helper Functions ---

/// Load witness blocks into an isolated memory blockstore
fn load_witness_store(blocks: &[ProofBlock]) -> Result<MemoryBlockstore> {
    let blockstore = MemoryBlockstore::new();

    for block in blocks {
        blockstore
            .put_keyed(&block.cid, &block.data)
            .context("Failed to load witness block")?;
    }

    Ok(blockstore)
}

/// Verify that the child header is trusted/finalized
fn verify_trust_anchor(
    proof: &StorageProof,
    is_trusted_child_header: &dyn Fn(i64, &Cid) -> bool,
) -> Result<bool> {
    let child_cid = parse_cid(&proof.child_block_cid, "child block")?;

    if !is_trusted_child_header(proof.child_epoch, &child_cid) {
        return Ok(false);
    }

    Ok(true)
}

/// Verify that the parent state root matches what's in the child header
fn verify_parent_state_root(
    blockstore: &MemoryBlockstore,
    child_cid: &Cid,
    expected_parent_state_root: &str,
) -> Result<bool> {
    // Get child header from witness store
    let child_header_raw = blockstore
        .get(child_cid)?
        .ok_or_else(|| anyhow!("missing child header {} in witness", child_cid))?;

    // Extract parent state root from header
    let parent_state_from_header = extract_parent_state_root(&child_header_raw)
        .context("Failed to extract ParentStateRoot from child header")?;

    // Compare with expected value
    Ok(parent_state_from_header.to_string() == expected_parent_state_root)
}

/// Verify that the actor state matches what's in the state tree
fn verify_actor_state(
    blockstore: &MemoryBlockstore,
    parent_state_root: &Cid,
    actor_id: u64,
    expected_actor_state_cid: &str,
) -> Result<bool> {
    // Load actor from state tree
    let actor_address = Address::new_id(actor_id);
    let actor_object = get_actor_state(blockstore, parent_state_root, actor_address)
        .context("Failed to load actor state from state tree")?;

    // Compare state CID
    Ok(actor_object.state.to_string() == expected_actor_state_cid)
}

/// Verify that the storage root matches what's in the EVM state
fn verify_storage_root(
    blockstore: &MemoryBlockstore,
    actor_state_cid: &Cid,
    expected_storage_root: &str,
) -> Result<bool> {
    // Load EVM state
    let evm_state_raw = blockstore
        .get(actor_state_cid)?
        .ok_or_else(|| anyhow!("missing EVM state {} in witness", actor_state_cid))?;

    // Parse EVM state to get storage root
    let evm_state = parse_evm_state(&evm_state_raw).context("Failed to parse EVM state")?;

    // Compare storage root
    Ok(evm_state.contract_state.to_string() == expected_storage_root)
}

/// Verify that the storage value matches what's at the given slot
fn verify_storage_value(
    blockstore: &MemoryBlockstore,
    storage_root: &Cid,
    slot_hex: &str,
    expected_value: &str,
) -> Result<bool> {
    // Parse slot from hex string
    let mut slot_bytes = [0u8; 32];
    hex::decode_to_slice(slot_hex.trim_start_matches("0x"), &mut slot_bytes)
        .context("Invalid slot hex format - must be 32 bytes")?;

    // Read value from storage
    let raw_value = read_storage_slot(blockstore, storage_root, &slot_bytes)
        .context("Failed to read storage slot")?
        .unwrap_or_default(); // Missing key means zero

    // Left-pad and format as hex
    let padded_value = left_pad_32(&raw_value);
    let actual_value_hex = format!("0x{}", hex::encode(padded_value));

    // Case-insensitive comparison for hex values
    Ok(actual_value_hex.eq_ignore_ascii_case(expected_value))
}
