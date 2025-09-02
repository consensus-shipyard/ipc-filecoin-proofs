use std::collections::{BTreeSet, HashMap, HashSet};

use anyhow::{anyhow, Result};
use cid::Cid;
// Amt for events Amtv0 for receipts/txmeta
use fvm_ipld_amt::{Amt, Amtv0};

use fvm_ipld_blockstore::{Blockstore, MemoryBlockstore};
use fvm_shared::event::StampedEvent;

use fvm_shared::receipt::Receipt as MessageReceipt;
use serde_ipld_dagcbor;

use crate::client::LotusClient;
use crate::proofs::blockstore::{RecordingBlockStore, RpcBlockstore};
use crate::proofs::bundle::{EventClaim, ProofBundle, WitnessBlock};
use crate::proofs::evm::{bytes32_from_ascii, evm_log_from_actor_event, keccak_event_sig};
use crate::types::{ApiReceipt, ApiTipset, CIDMap};

// Expand committed VM order from headers only (trustless)
async fn canonical_exec_list_from_headers(
    client: &LotusClient,
    parent: &ApiTipset,
) -> Result<Vec<Cid>> {
    let net = RpcBlockstore::new(client);
    let mut out = Vec::<Cid>::new();
    let mut seen = HashSet::<Cid>::new();

    // Parent tipset CIDs are already in canonical order; use that order.
    for hdr in &parent.blocks {
        // Load TxMeta (CBOR 2-tuple)
        let txmeta_cid = Cid::try_from(hdr.messages.cid.as_str())?;
        let raw = net
            .get(&txmeta_cid)?
            .ok_or_else(|| anyhow!("missing TxMeta"))?;

        let (bls_root, secp_root): (Cid, Cid) = serde_ipld_dagcbor::from_slice(&raw)?;

        let bls_amt = Amtv0::<Cid, _>::load(&bls_root, &net)?;
        bls_amt.for_each(|_, c| {
            if seen.insert(*c) {
                out.push(*c);
            }
            Ok(())
        })?;

        let secp_amt = Amtv0::<Cid, _>::load(&secp_root, &net)?;
        secp_amt.for_each(|_, c| {
            if seen.insert(*c) {
                out.push(*c);
            }
            Ok(())
        })?;
    }
    Ok(out)
}

pub async fn generate_bundle(
    client: &LotusClient,
    parent: &ApiTipset, // H (finalized)
    child: &ApiTipset,  // H+1 (finalized)
    ev_signature: &str, // e.g., "NewTopDownMessage(bytes32,uint256)"
    topic_1: &str,
) -> Result<ProofBundle> {
    let t0: [u8; 32] = keccak_event_sig(ev_signature);
    let t1: [u8; 32] = bytes32_from_ascii(topic_1);
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
    let exec = canonical_exec_list_from_headers(client, parent).await?;
    let mut exec_index = HashMap::<Cid, usize>::new();
    for (i, c) in exec.iter().enumerate() {
        exec_index.insert(*c, i);
    }

    // --- 3) Find matching receipts/events, and RECORD minimal paths for each (i, j)
    // Receipts: load from child’s receipts_root with a recording store to capture path nodes
    let rec_receipts = RecordingBlockStore::new(&net);
    let r_amt = Amtv0::<MessageReceipt, _>::load(&receipts_root, &rec_receipts)?;

    let rpcs = client
        .request::<Vec<ApiReceipt>>(
            "Filecoin.ChainGetParentReceipts",
            serde_json::json!([CIDMap::from(child_cid.to_string().as_str())]),
        )
        .await?;

    let mut claims = Vec::<EventClaim>::new();

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
                if let Some(log) = evm_log_from_actor_event(&se.event) {
                    if log.topics.len() >= 2 && log.topics[0] == t0 && log.topics[1] == t1 {
                        claims.push(EventClaim {
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

    // Add the receipts-path nodes we touched (all i’s we read)
    for c in rec_receipts.take_seen() {
        needed.insert(c);
    }

    // --- 4) Materialize bundle blocks (raw IPLD bytes for every CID in `needed`)
    let mut blocks = Vec::<WitnessBlock>::new();
    let bs = MemoryBlockstore::new();
    for c in needed {
        let raw = net.get(&c)?.ok_or_else(|| anyhow!("missing block {}", c))?;
        bs.put_keyed(&c, &raw)?; // sanity rehash
        blocks.push(WitnessBlock { cid: c, data: raw });
    }

    Ok(ProofBundle { claims, blocks })
}
