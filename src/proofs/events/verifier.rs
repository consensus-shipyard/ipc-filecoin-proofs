use anyhow::{anyhow, Result};
use cid::Cid;
use fvm_ipld_amt::{Amt, Amtv0};
use fvm_ipld_blockstore::{Blockstore, MemoryBlockstore};
use fvm_shared::event::{ActorEvent, StampedEvent};
use fvm_shared::receipt::Receipt as MessageReceipt;
use hex;
use serde_ipld_dagcbor;

use crate::proofs::common::{
    decode::HeaderLite,
    evm::{ascii_to_bytes32, extract_evm_log, hash_event_signature},
    witness::parse_cids,
};
use crate::proofs::events::{
    bundle::{EventData, EventProofBundle},
    utils::reconstruct_execution_order,
};

/// Create an event filter function for matching EVM events
///
/// # Arguments
/// * `event_sig` - Event signature (e.g., "NewTopDownMessage(bytes32,uint256)")
/// * `subnet_id` - Subnet identifier to match in topic1
///
/// # Returns
/// A closure that checks if an event matches the criteria
pub fn create_event_filter(event_sig: &str, subnet_id: &str) -> impl Fn(&ActorEvent) -> bool {
    let t0: [u8; 32] = hash_event_signature(event_sig);
    let t1: [u8; 32] = ascii_to_bytes32(subnet_id);

    move |ev| {
        if let Some(log) = extract_evm_log(ev) {
            log.topics.len() >= 2 && log.topics[0] == t0 && log.topics[1] == t1
        } else {
            false
        }
    }
}

/// Verify an event proof bundle offline
///
/// # Arguments
/// * `bundle` - The event proof bundle to verify
/// * `is_trusted_parent_ts` - Function to verify parent tipset is trusted
/// * `is_trusted_child_header` - Function to verify child header is trusted
/// * `check_event` - Optional semantic check on event contents
///
/// # Returns
/// Vector of boolean results for each proof in the bundle
pub fn verify_event_proof(
    bundle: &EventProofBundle,
    is_trusted_parent_ts: &dyn Fn(i64, &[Cid]) -> bool,
    is_trusted_child_header: &dyn Fn(i64, &Cid) -> bool,
    check_event: Option<&dyn Fn(&ActorEvent) -> bool>,
) -> Result<Vec<bool>> {
    // Step 1: Load witness blocks into local store
    let blockstore = load_witness_store(&bundle.blocks)?;

    // Step 2: Verify each proof
    let mut results = Vec::with_capacity(bundle.proofs.len());
    for proof in &bundle.proofs {
        let is_valid = verify_single_proof(
            &blockstore,
            proof,
            is_trusted_parent_ts,
            is_trusted_child_header,
            check_event,
        )?;
        results.push(is_valid);
    }

    Ok(results)
}

// --- Helper Functions ---

/// Load witness blocks into memory store
fn load_witness_store(
    blocks: &[crate::proofs::common::bundle::ProofBlock],
) -> Result<MemoryBlockstore> {
    let blockstore = MemoryBlockstore::new();

    for block in blocks {
        blockstore.put_keyed(&block.cid, &block.data)?;
    }

    Ok(blockstore)
}

/// Verify a single event proof
fn verify_single_proof(
    blockstore: &MemoryBlockstore,
    proof: &crate::proofs::events::bundle::EventProof,
    is_trusted_parent_ts: &dyn Fn(i64, &[Cid]) -> bool,
    is_trusted_child_header: &dyn Fn(i64, &Cid) -> bool,
    check_event: Option<&dyn Fn(&ActorEvent) -> bool>,
) -> Result<bool> {
    // Step 1: Verify trust anchors
    if !verify_trust_anchors(proof, is_trusted_parent_ts, is_trusted_child_header)? {
        return Ok(false);
    }

    // Step 2: Verify header consistency
    let (child_cid, parent_cids) = if !verify_header_consistency(blockstore, proof)? {
        return Ok(false);
    } else {
        // Extract for use in later steps
        let child_cid = Cid::try_from(proof.child_block_cid.as_str())?;
        let parent_cids = parse_cids(&proof.parent_tipset_cids, "parent tipset")?;
        (child_cid, parent_cids)
    };

    // Step 3: Verify execution order
    if !verify_execution_order(blockstore, &parent_cids, proof)? {
        return Ok(false);
    }

    // Step 4: Verify receipt and event
    verify_receipt_and_event(blockstore, child_cid, proof, check_event)
}

/// Verify that the trust anchors are valid
fn verify_trust_anchors(
    proof: &crate::proofs::events::bundle::EventProof,
    is_trusted_parent_ts: &dyn Fn(i64, &[Cid]) -> bool,
    is_trusted_child_header: &dyn Fn(i64, &Cid) -> bool,
) -> Result<bool> {
    // Parse CIDs
    let parent_cids = parse_cids(&proof.parent_tipset_cids, "parent tipset")?;
    let child_cid = Cid::try_from(proof.child_block_cid.as_str())?;

    // Check parent tipset trust
    if !is_trusted_parent_ts(proof.parent_epoch, &parent_cids) {
        return Ok(false);
    }

    // Check child header trust
    if !is_trusted_child_header(proof.child_epoch, &child_cid) {
        return Ok(false);
    }

    Ok(true)
}

/// Verify header consistency (epochs and parent links)
fn verify_header_consistency(
    blockstore: &MemoryBlockstore,
    proof: &crate::proofs::events::bundle::EventProof,
) -> Result<bool> {
    let child_cid = Cid::try_from(proof.child_block_cid.as_str())?;
    let parent_cids = parse_cids(&proof.parent_tipset_cids, "parent tipset")?;

    // Decode child header
    let child_raw = blockstore
        .get(&child_cid)?
        .ok_or_else(|| anyhow!("missing child header in witness"))?;
    let child_hdr: HeaderLite = serde_ipld_dagcbor::from_slice(&child_raw)?;

    // Check parent links
    if child_hdr.parents != parent_cids {
        return Ok(false);
    }

    // Check child epoch
    if child_hdr.height != proof.child_epoch {
        return Ok(false);
    }

    // Check parent epoch (verify one parent header)
    let parent_header_raw = blockstore
        .get(&parent_cids[0])?
        .ok_or_else(|| anyhow!("missing parent header in witness"))?;
    let parent_header: HeaderLite = serde_ipld_dagcbor::from_slice(&parent_header_raw)?;

    if parent_header.height != proof.parent_epoch {
        return Ok(false);
    }

    Ok(true)
}

/// Verify that the message is in the expected execution position
fn verify_execution_order(
    blockstore: &MemoryBlockstore,
    parent_cids: &[Cid],
    proof: &crate::proofs::events::bundle::EventProof,
) -> Result<bool> {
    // Reconstruct execution order
    let exec = reconstruct_execution_order(blockstore, parent_cids)?;

    // Find message in execution order
    let msg_cid = Cid::try_from(proof.message_cid.as_str())?;
    let Some(i) = exec.iter().position(|c| c == &msg_cid) else {
        return Ok(false);
    };

    // Verify execution index matches
    if i as u64 != proof.exec_index {
        return Ok(false);
    }

    Ok(true)
}

/// Verify the receipt and event at the specified indices
fn verify_receipt_and_event(
    blockstore: &MemoryBlockstore,
    child_cid: Cid,
    proof: &crate::proofs::events::bundle::EventProof,
    check_event: Option<&dyn Fn(&ActorEvent) -> bool>,
) -> Result<bool> {
    // Get child header to access receipts root
    let child_raw = blockstore
        .get(&child_cid)?
        .ok_or_else(|| anyhow!("missing child header"))?;
    let child_hdr: HeaderLite = serde_ipld_dagcbor::from_slice(&child_raw)?;

    // Load receipts AMT
    let receipts_amt =
        Amtv0::<MessageReceipt, _>::load(&child_hdr.parent_message_receipts, blockstore)?;

    // Get receipt at execution index
    let Some(receipt) = receipts_amt.get(proof.exec_index)? else {
        return Ok(false);
    };

    // Check if receipt has events
    let Some(events_root) = receipt.events_root else {
        return Ok(false);
    };

    // Load events AMT
    let events_amt = Amt::<StampedEvent, _>::load(&events_root, blockstore)?;

    // Get event at specified index
    let Some(stamped_event) = events_amt.get(proof.event_index)? else {
        return Ok(false);
    };

    // Verify stored event data matches actual event
    if !verify_event_data_matches(&stamped_event, &proof.event_data)? {
        return Ok(false);
    }

    // Apply optional semantic check
    if let Some(predicate) = check_event {
        if !predicate(&stamped_event.event) {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Verify that the stored event data matches the actual event
fn verify_event_data_matches(
    stamped_event: &StampedEvent,
    stored_data: &EventData,
) -> Result<bool> {
    // Check emitter matches
    if stamped_event.emitter != stored_data.emitter {
        return Ok(false);
    }

    // Extract EVM log to compare topics and data
    let Some(log) = extract_evm_log(&stamped_event.event) else {
        return Ok(false);
    };

    // Check topics match (compare hex strings case-insensitively)
    if log.topics.len() != stored_data.topics.len() {
        return Ok(false);
    }

    for (actual_topic, stored_topic) in log.topics.iter().zip(&stored_data.topics) {
        let actual_hex = format!("0x{}", hex::encode(actual_topic));
        if !actual_hex.eq_ignore_ascii_case(stored_topic) {
            return Ok(false);
        }
    }

    // Check data matches (compare hex strings case-insensitively)
    let actual_data_hex = format!("0x{}", hex::encode(&log.data));
    if !actual_data_hex.eq_ignore_ascii_case(&stored_data.data) {
        return Ok(false);
    }

    Ok(true)
}
