use anyhow::{anyhow, Result};
use cid::Cid;
// Amt for events Amtv0 for receipts/txmeta
use fvm_ipld_amt::{Amt, Amtv0};

use fvm_ipld_blockstore::{Blockstore, MemoryBlockstore};
use fvm_shared::event::{ActorEvent, StampedEvent};

use fvm_shared::receipt::Receipt as MessageReceipt;
use serde_ipld_dagcbor;

use crate::proofs::common::evm::{ascii_to_bytes32, extract_evm_log, hash_event_signature};
use crate::proofs::common::decode::HeaderLite;
use crate::proofs::events::{
    bundle::EventProofBundle,
    utils::reconstruct_execution_order,
};

/// Create an event filter function for matching EVM events
pub fn create_event_filter(
    event_sig: &str,
    subnet_id: &str,
) -> impl Fn(&fvm_shared::event::ActorEvent) -> bool {
    let t0: [u8; 32] = hash_event_signature(event_sig);
    let t1: [u8; 32] = ascii_to_bytes32(subnet_id);
    move |ev| {
        if let Some(log) = extract_evm_log(ev) {
            if log.topics.len() < 2 {
                return false;
            }
            // topics[0] == hash(sig), topics[1] == bytes32(subnetId)
            log.topics[0] == t0 && log.topics[1] == t1
        } else {
            false
        }
    }
}

/// Verify an event proof bundle offline
pub fn verify_event_proof(
    bundle: &EventProofBundle,
    // Trust anchors: the caller must assert these headers are finalized.
    is_trusted_parent_ts: &dyn Fn(i64, &[Cid]) -> bool,
    is_trusted_child_header: &dyn Fn(i64, &Cid) -> bool,
    // Optional semantic check on the event contents
    check_event: Option<&dyn Fn(&ActorEvent) -> bool>,
) -> Result<Vec<bool>> {
    // Load bundle blocks into an isolated store
    let bs = MemoryBlockstore::new();
    for wb in &bundle.blocks {
        bs.put_keyed(&wb.cid, &wb.data)?;
    }

    let mut results = Vec::with_capacity(bundle.proofs.len());

    for proof in &bundle.proofs {
        // trust anchors
        let p_cids: Vec<Cid> = proof
            .parent_tipset_cids
            .iter()
            .map(|s| Cid::try_from(s.as_str()).unwrap())
            .collect();
        if !is_trusted_parent_ts(proof.parent_epoch, &p_cids) {
            results.push(false);
            continue;
        }
        let child_cid = Cid::try_from(proof.child_block_cid.as_str())?;
        if !is_trusted_child_header(proof.child_epoch, &child_cid) {
            results.push(false);
            continue;
        }

        // decode child header (DAG-CBOR)
        let child_raw = bs
            .get(&child_cid)?
            .ok_or_else(|| anyhow!("missing child header"))?;
        let child_hdr: HeaderLite = serde_ipld_dagcbor::from_slice(&child_raw)?;

        // explicit anchor checks:
        if child_hdr.parents != p_cids {
            results.push(false);
            continue;
        }
        if child_hdr.height != proof.child_epoch {
            results.push(false);
            continue;
        }

        // check one parent header height
        let p0_raw = bs
            .get(&p_cids[0])?
            .ok_or_else(|| anyhow!("missing parent header"))?;
        let p0_hdr: HeaderLite = serde_ipld_dagcbor::from_slice(&p0_raw)?;
        if p0_hdr.height != proof.parent_epoch {
            results.push(false);
            continue;
        }

        // compute canonical exec order (with TxMeta recompute assert)
        let exec = reconstruct_execution_order(&bs, &p_cids)?;
        let msg_cid = Cid::try_from(proof.message_cid.as_str())?;
        let Some(i) = exec.iter().position(|c| c == &msg_cid) else {
            results.push(false);
            continue;
        };
        if i as u64 != proof.exec_index {
            results.push(false);
            continue;
        }

        // (prove receipt[i] under child's receipts root
        let r_root = child_hdr.parent_message_receipts;
        let r_amt = Amtv0::<MessageReceipt, _>::load(&r_root, &bs)?;
        let Some(rcpt) = r_amt.get(i as u64)? else {
            results.push(false);
            continue;
        };

        // prove event[j] under rcpt.events_root
        let Some(ev_root) = rcpt.events_root else {
            results.push(false);
            continue;
        };
        let e_amt = Amt::<StampedEvent, _>::load(&ev_root, &bs)?;
        let Some(se) = e_amt.get(proof.event_index)? else {
            results.push(false);
            continue;
        };

        // semantic predicate (topics/ABI) if provided
        if let Some(pred) = check_event {
            if !pred(&se.event) {
                results.push(false);
                continue;
            }
        }

        results.push(true);
    }

    Ok(results)
}
