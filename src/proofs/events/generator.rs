use std::collections::{BTreeSet, HashMap};

use anyhow::{anyhow, Result};
use cid::Cid;
// Amt for events Amtv0 for receipts/txmeta
use fvm_ipld_amt::{Amt, Amtv0};

use fvm_ipld_blockstore::{Blockstore, MemoryBlockstore};
use fvm_shared::event::StampedEvent;
use fvm_shared::receipt::Receipt as MessageReceipt;
use serde_ipld_dagcbor;

use crate::client::{LotusClient, RpcBlockstore};
use crate::proofs::common::{
    blockstore::RecordingBlockStore,
    bundle::ProofBlock,
    evm::{ascii_to_bytes32, extract_evm_log, hash_event_signature},
};
use crate::proofs::events::{
    bundle::{EventProof, EventProofBundle},
    utils::build_execution_order,
};
use crate::types::{ApiReceipt, ApiTipset, CIDMap};

// Note: Contract filtering removed - fetching all messages is already inefficient,
// so filtering by address doesn't improve performance. If filtering is needed,
// it should be done at the RPC level.

/// Generate an event proof bundle for events matching the specified signature and topic
pub async fn generate_event_proof(
    client: &LotusClient,
    parent: &ApiTipset, // H (finalized)
    child: &ApiTipset,  // H+1 (finalized)
    ev_signature: &str, // e.g., "NewTopDownMessage(bytes32,uint256)"
    topic_1: &str,      // e.g., subnet ID
) -> Result<EventProofBundle> {
    let t0: [u8; 32] = hash_event_signature(ev_signature);
    let t1: [u8; 32] = ascii_to_bytes32(topic_1);
    let child_cid = Cid::try_from(child.cids[0].cid.as_str())?;
    let receipts_root = Cid::try_from(child.blocks[0].parent_message_receipts.cid.as_str())?;

    // --- 0) base needed set: headers + receipts root + (optionally) txmeta CIDs
    let net = RpcBlockstore::new(client);
    let mut needed = BTreeSet::<Cid>::new();
    for cm in &parent.cids {
        needed.insert(Cid::try_from(cm.cid.as_str())?); // parent headers
    }
    needed.insert(child_cid); // child header
    needed.insert(receipts_root); // receipts root
    for h in &parent.blocks {
        needed.insert(Cid::try_from(h.messages.cid.as_str())?); // TxMeta (the 2-tuple)
    }

    // --- 1) RECORD the full BLS/SECP AMTs referenced by each parent TxMeta
    // Use a recording blockstore so every node we touch is captured.
    let rec_exec = RecordingBlockStore::new(&net);

    for hdr in &parent.blocks {
        // Load TxMeta with the recording store
        let tx_cid = Cid::try_from(hdr.messages.cid.as_str())?;
        let tx_raw = rec_exec
            .get(&tx_cid)?
            .ok_or_else(|| anyhow!("missing TxMeta {}", tx_cid))?;

        // TxMeta is a DAG-CBOR 2-tuple of (bls_root, secp_root)
        let (bls_root, secp_root): (Cid, Cid) = serde_ipld_dagcbor::from_slice(&tx_raw)?;

        // Walk BOTH AMTs FULLY (this records every internal/leaf node)
        let bls_amt = Amtv0::<Cid, _>::load(&bls_root, &rec_exec)?;
        bls_amt.for_each(|_, _| Ok(()))?;
        let secp_amt = Amtv0::<Cid, _>::load(&secp_root, &rec_exec)?;
        secp_amt.for_each(|_, _| Ok(()))?;
    }

    // Add every block touched while traversing TxMeta AMTs
    for c in rec_exec.take_seen() {
        needed.insert(c);
    }

    // --- 2) Build canonical exec list (any way you like).
    // (This can still use RPC since proofs come from the roots and recorded AMTs.)
    let exec = build_execution_order(client, parent).await?;
    let mut exec_index = HashMap::<Cid, usize>::new();
    for (i, c) in exec.iter().enumerate() {
        exec_index.insert(*c, i);
    }

    // --- 3) Find matching receipts/events, and RECORD minimal paths for each (i, j)
    // Receipts: load from child's receipts_root with a recording store to capture path nodes
    let rec_receipts = RecordingBlockStore::new(&net);
    let r_amt = Amtv0::<MessageReceipt, _>::load(&receipts_root, &rec_receipts)?;

    let rpcs = client
        .request::<Vec<ApiReceipt>>(
            "Filecoin.ChainGetParentReceipts",
            serde_json::json!([CIDMap::from(child_cid.to_string().as_str())]),
        )
        .await?;

    let mut proofs = Vec::<EventProof>::new();

    for (i, api_r) in rpcs.iter().enumerate() {
        let Some(msg_cid) = exec.get(i) else {
            continue;
        };

        // Touch receipts[i] so the path gets recorded
        if r_amt.get(i as u64)?.is_none() {
            continue;
        }

        if let Some(er_map) = &api_r.events_root {
            let ev_root = Cid::try_from(er_map.cid.as_str())?;
            needed.insert(ev_root);

            // For events, also use a recorder so only the path to each matched j is captured
            let rec_events = RecordingBlockStore::new(&net);
            let e_amt = Amt::<StampedEvent, _>::load(&ev_root, &rec_events)?;
            e_amt.for_each(|j, se| {
                if let Some(log) = extract_evm_log(&se.event) {
                    if log.topics.len() >= 2 && log.topics[0] == t0 && log.topics[1] == t1 {
                        proofs.push(EventProof {
                            parent_epoch: parent.height,
                            child_epoch: child.height,
                            parent_tipset_cids: parent.cids.iter().map(|m| m.cid.clone()).collect(),
                            child_block_cid: child.cids[0].cid.clone(),
                            message_cid: msg_cid.to_string(),
                            exec_index: i as u64,
                            event_index: j,
                        });
                    }
                }
                Ok(())
            })?;

            // keep only what we touched under this events root
            for c in rec_events.take_seen() {
                needed.insert(c);
            }
        }
    }

    // Add the receipts-path nodes we touched (all i's we read)
    for c in rec_receipts.take_seen() {
        needed.insert(c);
    }

    // --- 4) Materialize bundle blocks (raw IPLD bytes for every CID in `needed`)
    let mut blocks = Vec::<ProofBlock>::new();
    let bs = MemoryBlockstore::new();
    for c in needed {
        let raw = net.get(&c)?.ok_or_else(|| anyhow!("missing block {}", c))?;
        bs.put_keyed(&c, &raw)?; // sanity rehash
        blocks.push(ProofBlock { cid: c, data: raw });
    }

    Ok(EventProofBundle { proofs, blocks })
}
