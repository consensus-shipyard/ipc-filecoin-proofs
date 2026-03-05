use anyhow::{anyhow, Result};
use cid::Cid;
use ethereum_types::H256;
use fvm_ipld_blockstore::Blockstore;
use fvm_shared::address::Address;
use hex;

use crate::client::types::ApiTipset;
use crate::proofs::common::{
    blockstore::RecordingBlockStore,
    bundle::ProofBlock,
    decode::{extract_parent_state_root, get_actor_state, parse_evm_state},
    evm::left_pad_32,
    witness::{parse_cid, WitnessCollector},
};
use crate::proofs::storage::{bundle::StorageProof, decode::read_storage_slot};

/// Generate a storage proof for a specific actor's storage slot
///
/// # Arguments
/// * `net` - Network blockstore containing state data
/// * `parent` - Parent tipset (H, finalized)
/// * `child` - Child tipset (H+1, finalized)
/// * `actor_id` - Actor ID to read storage from
/// * `slot_h256` - Storage slot to read
///
/// # Returns
/// Tuple of storage proof and witness blocks for offline verification
pub async fn generate_storage_proof<BS: Blockstore>(
    net: &BS,
    _parent: &ApiTipset,
    child: &ApiTipset,
    actor_id: u64,
    slot_h256: H256,
) -> Result<(StorageProof, Vec<ProofBlock>)> {
    // Step 1: Extract and verify parent state root from child header
    let (child_cid, parent_state_root) = extract_and_verify_parent_state(net, child)?;

    // Step 2: Setup witness collection
    let mut collector = WitnessCollector::new(net);
    collector.add_cid(child_cid);
    collector.add_cid(parent_state_root);

    // Step 3: Load actor state and record path
    let (actor_state_cid, storage_root) =
        load_actor_and_storage_root(net, &mut collector, parent_state_root, actor_id)?;

    // Step 4: Read storage value and record path
    let value = read_storage_value(net, &mut collector, storage_root, slot_h256)?;

    // Step 5: Materialize witness blocks
    let blocks = collector.materialize()?;

    // Step 6: Create proof claim
    let proof = create_proof_claim(
        child,
        child_cid,
        parent_state_root,
        actor_id,
        actor_state_cid,
        storage_root,
        slot_h256,
        value,
    );

    Ok((proof, blocks))
}

// --- Helper Functions ---

/// Extract parent state root from child header and verify consistency
fn extract_and_verify_parent_state<BS: Blockstore>(
    net: &BS,
    child: &ApiTipset,
) -> Result<(Cid, Cid)> {
    // Choose first block in tipset (assume agreement)
    let child_cid = parse_cid(&child.cids[0].cid, "child block")?;

    // Load child header with recording
    let header_recorder = RecordingBlockStore::new(net);
    let child_header_raw = header_recorder
        .get(&child_cid)?
        .ok_or_else(|| anyhow!("missing child header {}", child_cid))?;

    // Extract parent state root from CBOR header
    let parent_state_from_header = extract_parent_state_root(&child_header_raw)?;

    // Cross-check with JSON representation
    let parent_state_from_json = parse_cid(
        &child.blocks[0].parent_state_root.cid,
        "parent state root from JSON",
    )?;

    if parent_state_from_header != parent_state_from_json {
        return Err(anyhow!(
            "ParentStateRoot mismatch: header {} vs JSON {}",
            parent_state_from_header,
            parent_state_from_json
        ));
    }

    Ok((child_cid, parent_state_from_header))
}

/// Load actor state and extract storage root
fn load_actor_and_storage_root<BS: Blockstore>(
    net: &BS,
    collector: &mut WitnessCollector<'_, BS>,
    parent_state_root: Cid,
    actor_id: u64,
) -> Result<(Cid, Cid)> {
    // Record state tree traversal
    let state_recorder = RecordingBlockStore::new(net);

    // Load actor object from state tree
    let actor_address = Address::new_id(actor_id);
    let actor_object = get_actor_state(&state_recorder, &parent_state_root, actor_address)?;
    let actor_state_cid = actor_object.state;

    // Load EVM state to extract storage root
    let evm_state_raw = state_recorder
        .get(&actor_state_cid)?
        .ok_or_else(|| anyhow!("missing EVM state {}", actor_state_cid))?;

    let evm_state = parse_evm_state(&evm_state_raw)?;
    let storage_root = evm_state.contract_state;

    // Add to witness collection
    collector.add_cid(actor_state_cid);
    collector.add_cid(storage_root);
    collector.collect_from_recording(&state_recorder);

    Ok((actor_state_cid, storage_root))
}

/// Read storage value at specified slot
fn read_storage_value<BS: Blockstore>(
    net: &BS,
    collector: &mut WitnessCollector<'_, BS>,
    storage_root: Cid,
    slot_h256: H256,
) -> Result<[u8; 32]> {
    // Record storage HAMT traversal
    let storage_recorder = RecordingBlockStore::new(net);

    // Read slot value (missing key means zero)
    let raw_value =
        read_storage_slot(&storage_recorder, &storage_root, &slot_h256.into())?.unwrap_or_default();

    // Add storage traversal to witness
    collector.collect_from_recording(&storage_recorder);

    // Left-pad to 32 bytes
    Ok(left_pad_32(&raw_value))
}

/// Create the storage proof claim
fn create_proof_claim(
    child: &ApiTipset,
    child_cid: Cid,
    parent_state_root: Cid,
    actor_id: u64,
    actor_state_cid: Cid,
    storage_root: Cid,
    slot_h256: H256,
    value: [u8; 32],
) -> StorageProof {
    StorageProof {
        child_epoch: child.height,
        child_block_cid: child_cid.to_string(),
        parent_state_root: parent_state_root.to_string(),
        actor_id,
        actor_state_cid: actor_state_cid.to_string(),
        storage_root: storage_root.to_string(),
        slot: format!("0x{}", hex::encode(slot_h256.0)),
        value: format!("0x{}", hex::encode(value)),
    }
}
