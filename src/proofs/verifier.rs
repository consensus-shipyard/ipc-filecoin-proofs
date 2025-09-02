// SPDX-License-Identifier: MIT
// Glue to generate & verify event-in-receipt proofs for FEVM logs.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use cid::Cid;
// Amt for events Amtv0 for receipts/txmeta
use fvm_ipld_amt::{Amt, Amtv0};

use fvm_ipld_blockstore::{Blockstore, MemoryBlockstore};
use fvm_shared::event::{ActorEvent, StampedEvent};

use fvm_ipld_encoding::CborStore;
use fvm_shared::receipt::Receipt as MessageReceipt;
use serde::de::IgnoredAny;
use serde_ipld_dagcbor;
use serde_tuple::Deserialize_tuple;

use crate::proofs::bundle::ProofBundle;
use crate::proofs::evm::{bytes32_from_ascii, evm_log_from_actor_event, keccak_event_sig};

// ---------- Verifier (offline) ----------
#[derive(Debug, Deserialize_tuple)]
struct HeaderLite {
    _miner: IgnoredAny,           // 0
    _ticket: IgnoredAny,          // 1
    _election_proof: IgnoredAny,  // 2
    _beacon_entries: IgnoredAny,  // 3
    _winpost_proof: IgnoredAny,   // 4
    parents: Vec<Cid>,            // 5
    _parent_weight: IgnoredAny,   // 6
    height: i64,                  // 7
    parent_state_root: Cid,       // 8
    parent_message_receipts: Cid, // 9  <-- what you want
    messages: Cid,                // 10 <-- what you want
    _bls_aggregate: IgnoredAny,   // 11
    timestamp: u64,               // 12
    _block_sig: IgnoredAny,       // 13
    fork_signaling: u64,          // 14
    _parent_base_fee: IgnoredAny, // 15
}

pub fn make_check_event_evm(
    event_sig: &str,
    subnet_id: &str,
) -> impl Fn(&fvm_shared::event::ActorEvent) -> bool {
    let t0: [u8; 32] = keccak_event_sig(event_sig);
    let t1: [u8; 32] = bytes32_from_ascii(subnet_id);
    move |ev| {
        if let Some(log) = evm_log_from_actor_event(ev) {
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

// Helper: rebuild exec from headers → TxMeta → AMTs
fn exec_from_headers(bs: &MemoryBlockstore, parent_hdr_cids: &[Cid]) -> Result<Vec<Cid>> {
    let mut out = Vec::<Cid>::new();
    let mut seen = HashSet::<Cid>::new();

    for pcid in parent_hdr_cids {
        // load & decode the parent header from dag-cbor
        let raw = bs
            .get(pcid)?
            .ok_or_else(|| anyhow!("missing parent header {}", pcid))?;
        let hdr: HeaderLite = serde_ipld_dagcbor::from_slice(&raw)?;

        // TxMeta block (CBOR 2-tuple of (bls_root, secp_root))
        let tx_cid = hdr.messages;
        let tx_raw = bs
            .get(&tx_cid)?
            .ok_or_else(|| anyhow!("missing TxMeta {}", tx_cid))?;
        let (bls_root, secp_root): (Cid, Cid) = serde_ipld_dagcbor::from_slice(&tx_raw)?;

        // recompute TxMeta CID and compare
        let recomputed_tx_cid = bs.put_cbor(
            &(bls_root, secp_root),
            multihash_codetable::Code::Blake2b256,
        )?;
        if recomputed_tx_cid != tx_cid {
            return Err(anyhow!(
                "TxMeta mismatch: header {} vs recomputed {}",
                tx_cid,
                recomputed_tx_cid
            ));
        }

        // walk AMTs by CID links; dedupe into canonical VM exec order
        let bls_amt = Amtv0::<Cid, _>::load(&bls_root, bs)?;
        bls_amt.for_each(|_, c| {
            if seen.insert(*c) {
                out.push(*c)
            };
            Ok(())
        })?;

        let secp_amt = Amtv0::<Cid, _>::load(&secp_root, bs)?;
        secp_amt.for_each(|_, c| {
            if seen.insert(*c) {
                out.push(*c)
            };
            Ok(())
        })?;
    }

    Ok(out)
}

pub fn verify_bundle(
    bundle: &ProofBundle,
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

    let mut results = Vec::with_capacity(bundle.claims.len());

    for cl in &bundle.claims {
        // trust anchors
        let p_cids: Vec<Cid> = cl
            .parent_tipset_cids
            .iter()
            .map(|s| Cid::try_from(s.as_str()).unwrap())
            .collect();
        if !is_trusted_parent_ts(cl.parent_epoch, &p_cids) {
            results.push(false);
            continue;
        }
        let child_cid = Cid::try_from(cl.child_block_cid.as_str())?;
        if !is_trusted_child_header(cl.child_epoch, &child_cid) {
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
        if child_hdr.height != cl.child_epoch {
            results.push(false);
            continue;
        }

        // check one parent header height
        let p0_raw = bs
            .get(&p_cids[0])?
            .ok_or_else(|| anyhow!("missing parent header"))?;
        let p0_hdr: HeaderLite = serde_ipld_dagcbor::from_slice(&p0_raw)?;
        if p0_hdr.height != cl.parent_epoch {
            results.push(false);
            continue;
        }

        // compute canonical exec order (with TxMeta recompute assert)
        let exec = exec_from_headers(&bs, &p_cids)?;
        let msg_cid = Cid::try_from(cl.message_cid.as_str())?;
        let Some(i) = exec.iter().position(|c| c == &msg_cid) else {
            results.push(false);
            continue;
        };
        if i as u64 != cl.exec_index {
            results.push(false);
            continue;
        }

        // (prove receipt[i] under child’s receipts root
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
        let Some(se) = e_amt.get(cl.event_index)? else {
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
