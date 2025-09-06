use anyhow::{anyhow, Result};
use cid::Cid;
use fvm_ipld_amt::{Amt, Amtv0};
use fvm_ipld_blockstore::Blockstore;
use fvm_shared::event::StampedEvent;
use fvm_shared::receipt::Receipt as MessageReceipt;
use hex;
use serde_ipld_dagcbor;

use crate::client::types::{ApiReceipt, ApiTipset, CIDMap};
use crate::client::LotusClient;
use crate::proofs::common::{
    blockstore::RecordingBlockStore,
    evm::{ascii_to_bytes32, extract_evm_log, hash_event_signature},
    witness::{parse_cid, WitnessCollector},
};
use crate::proofs::events::{
    bundle::{EventData, EventProof, EventProofBundle},
    utils::build_execution_order,
};

/// Event matcher for filtering events by signature and topic
struct EventMatcher {
    topic0: [u8; 32],
    topic1: [u8; 32],
}

impl EventMatcher {
    /// Create a new event matcher from signature and topic
    fn new(event_signature: &str, topic_1: &str) -> Self {
        Self {
            topic0: hash_event_signature(event_signature),
            topic1: ascii_to_bytes32(topic_1),
        }
    }

    /// Check if an EVM log matches our criteria
    fn matches_log(&self, log: &crate::proofs::common::evm::EvmLog) -> bool {
        log.topics.len() >= 2 && log.topics[0] == self.topic0 && log.topics[1] == self.topic1
    }
}

/// Generate an event proof bundle for events matching the specified signature and topic
///
/// # Arguments
/// * `client` - Lotus RPC client
/// * `parent` - Parent tipset (H, finalized)
/// * `child` - Child tipset (H+1, finalized)
/// * `event_signature` - Event signature to match (e.g., "NewTopDownMessage(bytes32,uint256)")
/// * `topic_1` - First indexed topic to match
/// * `actor_id_filter` - Optional actor ID to filter events by their emitter
///
/// # Returns
/// Bundle containing event proofs and witness blocks
///
/// # Note
/// Events are filtered by:
/// 1. Event signature and topic (to find specific event types)
/// 2. Actor ID (optional, to scope by emitter)
pub async fn generate_event_proof<BS: Blockstore>(
    client: &LotusClient,
    net: &BS,
    parent: &ApiTipset,
    child: &ApiTipset,
    event_signature: &str,
    topic_1: &str,
    actor_id_filter: Option<u64>,
) -> Result<EventProofBundle> {
    // Step 1: Setup event matching and basic CIDs
    let matcher = EventMatcher::new(event_signature, topic_1);
    let (child_cid, receipts_root) = extract_child_info(child)?;

    // Step 2: Collect base witness blocks (headers and transaction metadata)
    let mut collector = WitnessCollector::new(net);
    collect_base_witness(&mut collector, parent, child_cid, receipts_root)?;

    // Step 3: Record transaction AMTs for execution order reconstruction
    let tx_recordings = record_transaction_amts(net, parent)?;
    collector.collect_from_recordings(tx_recordings.iter().collect());

    // Step 4: Build canonical execution order
    let exec = build_execution_order(client, parent).await?;

    // Step 5: Find matching events and record their paths (with optional actor filter)
    let (proofs, event_recordings) = find_matching_events(
        client,
        net,
        child,
        parent,
        child_cid,
        receipts_root,
        &exec,
        &matcher,
        actor_id_filter,
    )
    .await?;

    // Add event path recordings to witness
    for rec in &event_recordings {
        collector.collect_from_recording(rec);
    }

    // Step 6: Materialize all witness blocks
    let blocks = collector.materialize()?;

    Ok(EventProofBundle { proofs, blocks })
}

// --- Helper Functions ---

/// Extract child block and receipts root CIDs
fn extract_child_info(child: &ApiTipset) -> Result<(Cid, Cid)> {
    let child_cid = parse_cid(&child.cids[0].cid, "child block")?;
    let receipts_root = parse_cid(
        &child.blocks[0].parent_message_receipts.cid,
        "receipts root",
    )?;
    Ok((child_cid, receipts_root))
}

/// Collect base witness blocks (headers and transaction metadata)
fn collect_base_witness<BS: Blockstore>(
    collector: &mut WitnessCollector<'_, BS>,
    parent: &ApiTipset,
    child_cid: Cid,
    receipts_root: Cid,
) -> Result<()> {
    // Add parent headers
    for cm in &parent.cids {
        let parent_cid = parse_cid(&cm.cid, "parent header")?;
        collector.add_cid(parent_cid);
    }

    // Add child header and receipts root
    collector.add_cid(child_cid);
    collector.add_cid(receipts_root);

    // Add TxMeta CIDs (the 2-tuple of BLS and SECP roots)
    for h in &parent.blocks {
        let tx_meta_cid = parse_cid(&h.messages.cid, "TxMeta")?;
        collector.add_cid(tx_meta_cid);
    }

    Ok(())
}

/// Record all transaction AMTs to ensure we have full execution data
fn record_transaction_amts<'a, BS: Blockstore>(
    net: &'a BS,
    parent: &ApiTipset,
) -> Result<Vec<RecordingBlockStore<'a, BS>>> {
    let mut recordings = Vec::new();

    for hdr in &parent.blocks {
        let rec = RecordingBlockStore::new(net);

        // Load TxMeta with recording
        let tx_cid = parse_cid(&hdr.messages.cid, "TxMeta")?;
        let tx_raw = rec
            .get(&tx_cid)?
            .ok_or_else(|| anyhow!("missing TxMeta {}", tx_cid))?;

        // Parse as DAG-CBOR 2-tuple
        let (bls_root, secp_root): (Cid, Cid) = serde_ipld_dagcbor::from_slice(&tx_raw)?;

        // Walk both AMTs fully to record all nodes
        let bls_amt = Amtv0::<Cid, _>::load(&bls_root, &rec)?;
        bls_amt.for_each(|_, _| Ok(()))?;

        let secp_amt = Amtv0::<Cid, _>::load(&secp_root, &rec)?;
        secp_amt.for_each(|_, _| Ok(()))?;

        recordings.push(rec);
    }

    Ok(recordings)
}

/// Find all matching events and record their proof paths
async fn find_matching_events<'a, BS: Blockstore>(
    client: &LotusClient,
    net: &'a BS,
    child: &ApiTipset,
    parent: &ApiTipset,
    child_cid: Cid,
    receipts_root: Cid,
    exec: &[Cid],
    matcher: &EventMatcher,
    actor_id_filter: Option<u64>,
) -> Result<(Vec<EventProof>, Vec<RecordingBlockStore<'a, BS>>)> {
    let mut proofs = Vec::new();
    let mut event_recordings = Vec::new();

    // Load receipts AMT with recording to capture paths
    let rec_receipts = RecordingBlockStore::new(net);
    let r_amt = Amtv0::<MessageReceipt, _>::load(&receipts_root, &rec_receipts)?;

    // Get receipts from RPC
    let rpcs = client
        .request::<Vec<ApiReceipt>>(
            "Filecoin.ChainGetParentReceipts",
            serde_json::json!([CIDMap::from(child_cid.to_string().as_str())]),
        )
        .await?;

    // First pass: identify which messages have events matching our filters (without touching receipts)
    let mut matching_indices = Vec::new();

    for (i, api_r) in rpcs.iter().enumerate() {
        if let Some(er_map) = &api_r.events_root {
            let ev_root = parse_cid(&er_map.cid, "events root")?;

            // Quick check: load events WITHOUT recording paths
            let temp_store = RecordingBlockStore::new(net);
            let e_amt = Amt::<StampedEvent, _>::load(&ev_root, &temp_store)?;

            let mut has_matching = false;
            e_amt.for_each(|_, se| {
                // Apply actor filter if provided
                if let Some(filter_id) = actor_id_filter {
                    if se.emitter != filter_id {
                        return Ok(());
                    }
                }

                // Check event signature/topic
                if let Some(log) = extract_evm_log(&se.event) {
                    if matcher.matches_log(&log) {
                        has_matching = true;
                    }
                }
                Ok(())
            })?;

            if has_matching {
                matching_indices.push(i);
            }
        }
    }

    // Second pass: only touch receipts and record paths for matching messages
    for &i in &matching_indices {
        let api_r = &rpcs[i];
        let msg_cid = exec
            .get(i)
            .ok_or_else(|| anyhow!("Missing message at index {}", i))?;

        // NOW touch the receipt to record its path
        if r_amt.get(i as u64)?.is_none() {
            continue;
        }

        // Process the events we know match
        if let Some(er_map) = &api_r.events_root {
            let ev_root = parse_cid(&er_map.cid, "events root")?;

            // Use a recorder for this specific events tree
            let rec_events = RecordingBlockStore::new(net);
            let e_amt = Amt::<StampedEvent, _>::load(&ev_root, &rec_events)?;

            // Collect matching events
            e_amt.for_each(|j, se| {
                // Apply actor filter if provided
                if let Some(filter_id) = actor_id_filter {
                    if se.emitter != filter_id {
                        return Ok(());
                    }
                }

                // Check event signature and topic
                if let Some(log) = extract_evm_log(&se.event) {
                    if matcher.matches_log(&log) {
                        // Capture event data for on-chain execution
                        let event_data = EventData {
                            emitter: se.emitter,
                            topics: log
                                .topics
                                .iter()
                                .map(|t| format!("0x{}", hex::encode(t)))
                                .collect(),
                            data: format!("0x{}", hex::encode(&log.data)),
                        };

                        proofs.push(EventProof {
                            parent_epoch: parent.height,
                            child_epoch: child.height,
                            parent_tipset_cids: parent.cids.iter().map(|m| m.cid.clone()).collect(),
                            child_block_cid: child.cids[0].cid.clone(),
                            message_cid: msg_cid.to_string(),
                            exec_index: i as u64,
                            event_index: j,
                            event_data,
                        });
                    }
                }
                Ok(())
            })?;

            event_recordings.push(rec_events);
        }
    }

    // Add receipts recording last (it captures all receipt paths we touched)
    event_recordings.push(rec_receipts);

    Ok((proofs, event_recordings))
}
