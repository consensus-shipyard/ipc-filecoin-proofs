// SPDX-License-Identifier: MIT
// Glue to generate & verify event-in-receipt proofs for FEVM logs.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::string::String;

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cid::Cid;
// Amt for events Amtv0 for receipts/txmeta
use fvm_ipld_amt::{Amt, Amtv0};

use fvm_ipld_blockstore::{Blockstore, MemoryBlockstore};
use fvm_shared::event::{ActorEvent, Entry, StampedEvent};

use fvm_shared::receipt::Receipt as MessageReceipt;
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor;
use serde_tuple::Deserialize_tuple;

use tiny_keccak::{Hasher, Keccak};

use crate::client::LotusClient;
use crate::types::CIDMap;
use crate::ApiTipset;

// ---------- Proof bundle format ----------
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessBlock {
    pub cid: Cid,
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub data: Vec<u8>, // raw DAG-CBOR block bytes
}

fn serialize_base64<S>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let encoded = B64.encode(data);
    serializer.serialize_str(&encoded)
}

fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventClaim {
    pub parent_epoch: i64,
    pub child_epoch: i64,
    pub parent_tipset_cids: Vec<String>, // ordered tipset key of H
    pub child_block_cid: String,         // block header CID of H+1
    pub message_cid: String,             // the message that produced the event
    pub exec_index: u64,                 // i
    pub event_index: u64,                // j
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBundle {
    pub claims: Vec<EventClaim>,
    pub blocks: Vec<WitnessBlock>, // deduped raw IPLD blocks needed for verification
}

// ---------- RPC-backed read-only blockstore ----------
struct RpcBlockstore<'a> {
    client: &'a LotusClient,
}
impl<'a> Blockstore for RpcBlockstore<'a> {
    fn get(&self, k: &Cid) -> Result<Option<Vec<u8>>> {
        // Filecoin.ChainReadObj returns base64 raw block bytes
        let arg = serde_json::json!([{"/": k.to_string()}]);
        let b64: String =
            futures::executor::block_on(self.client.request("Filecoin.ChainReadObj", arg))?;
        let raw = B64.decode(b64)?;
        Ok(Some(raw))
    }
    fn put_keyed(&self, _: &Cid, _: &[u8]) -> Result<()> {
        unreachable!()
    }
    fn has(&self, k: &Cid) -> Result<bool> {
        Ok(self.get(k)?.is_some())
    }
}

// ---------- Recording wrapper (which CIDs did AMT traversal touch?) ----------
struct RecordingBs<'a, B: Blockstore> {
    inner: &'a B,
    seen: parking_lot::Mutex<BTreeSet<Cid>>,
}
impl<'a, B: Blockstore> RecordingBs<'a, B> {
    fn new(inner: &'a B) -> Self {
        Self {
            inner,
            seen: Default::default(),
        }
    }
    fn take_seen(&self) -> Vec<Cid> {
        self.seen.lock().iter().cloned().collect()
    }
}
impl<'a, B: Blockstore> Blockstore for RecordingBs<'a, B> {
    fn get(&self, k: &Cid) -> Result<Option<Vec<u8>>> {
        self.seen.lock().insert(*k);
        self.inner.get(k)
    }
    fn put_keyed(&self, k: &Cid, v: &[u8]) -> Result<()> {
        self.inner.put_keyed(k, v)
    }
    fn has(&self, k: &Cid) -> Result<bool> {
        self.inner.has(k)
    }
}

// Expand committed VM order from headers only (trustless)
pub async fn canonical_exec_list_from_headers(
    client: &LotusClient,
    parent: &ApiTipset,
) -> Result<Vec<Cid>> {
    let net = RpcBlockstore { client };
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

// ---------- FEVM log decoding & filter ----------
#[derive(Debug, Clone)]
pub struct EvmLog {
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

pub fn evm_log_from_actor_event(ev: &fvm_shared::event::ActorEvent) -> Option<EvmLog> {
    use std::collections::HashMap;
    let mut m = HashMap::<&str, &[u8]>::new();
    for e in &ev.entries {
        m.insert(e.key.as_str(), e.value.as_slice());
    }

    // Case A: explicit concatenated topics + data
    if let Some(topics_bytes) = m.get("topics").copied() {
        if topics_bytes.len() % 32 != 0 {
            return None;
        }
        let topics = topics_bytes
            .chunks(32)
            .map(|c| <[u8; 32]>::try_from(c).unwrap())
            .collect::<Vec<_>>();
        let data = m.get("data").cloned().unwrap_or_default().to_vec();
        return Some(EvmLog { topics, data });
    }

    // Case B: compact t1,t2,... plus d
    let mut topics = Vec::<[u8; 32]>::new();
    // t1 is the event signature hash
    let mut i = 1usize;
    loop {
        let key = match i {
            1 => "t1",
            2 => "t2",
            3 => "t3",
            4 => "t4",
            _ => break,
        };
        if let Some(val) = m.get(key).copied() {
            if val.len() != 32 {
                return None;
            }
            topics.push(<[u8; 32]>::try_from(val).ok()?);
            i += 1;
        } else {
            break;
        }
    }
    if topics.is_empty() {
        return None;
    }
    let data = m.get("d").cloned().unwrap_or_default().to_vec();
    Some(EvmLog { topics, data })
}

pub fn keccak_event_sig(s: &str) -> [u8; 32] {
    let mut h = Keccak::v256();
    let mut out = [0u8; 32];
    h.update(s.as_bytes());
    h.finalize(&mut out);
    out
}

pub fn bytes32_from_ascii(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b = s.as_bytes();
    let n = b.len().min(32);
    out[..n].copy_from_slice(&b[..n]);
    out
}

// ---------- Generator: build bundle of all events matching (topic0, topic1=subnet) ----------
pub async fn generate_bundle_for_subnet(
    client: &LotusClient,
    parent: &ApiTipset, // H (finalized)
    child: &ApiTipset,  // H+1 (finalized)
    ev_signature: &str, // e.g., "NewTopDownMessage(bytes32,uint256)"
    subnet_topic: &str,
) -> Result<ProofBundle> {
    let t0: [u8; 32] = keccak_event_sig(ev_signature);
    let t1: [u8; 32] = bytes32_from_ascii(subnet_topic);
    let child_cid = Cid::try_from(child.cids[0].cid.as_str())?;
    let receipts_root = Cid::try_from(child.blocks[0].parent_message_receipts.cid.as_str())?;

    // --- 0) base needed set: headers + receipts root + (optionally) txmeta CIDs
    let net = RpcBlockstore { client };
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
    let rec_exec = RecordingBs::new(&net);

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
    let rec_receipts = RecordingBs::new(&net);
    let r_amt = Amtv0::<MessageReceipt, _>::load(&receipts_root, &rec_receipts)?;

    let rpcs = client
        .request::<Vec<crate::ApiReceipt>>(
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
            let rec_events = RecordingBs::new(&net);
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
pub fn verify_bundle_offline(
    bundle: &ProofBundle,
    // Trust anchors: the caller must assert these headers are finalized.
    is_trusted_parent_ts: &dyn Fn(i64, &[Cid]) -> bool,
    is_trusted_child_header: &dyn Fn(i64, &Cid) -> bool,
    // Optional semantic check on the event contents
    check_event: Option<&dyn Fn(&ActorEvent) -> bool>,
) -> Result<Vec<bool>> {
    println!("Verifying bundle offline");
    // Load bundle blocks into an isolated store
    let bs = MemoryBlockstore::new();
    for wb in &bundle.blocks {
        bs.put_keyed(&wb.cid, &wb.data)?;
    }

    // Helper: rebuild exec from headers → TxMeta → AMTs
    fn exec_from_headers(bs: &MemoryBlockstore, parent_hdr_cids: &[Cid]) -> Result<Vec<Cid>> {
        let mut out = Vec::<Cid>::new();
        let mut seen = HashSet::<Cid>::new();
        for pcid in parent_hdr_cids {
            let raw = bs
                .get(pcid)?
                .ok_or_else(|| anyhow!("missing parent header {}", pcid))?;

            let hdr: HeaderLite = serde_ipld_dagcbor::from_slice(&raw)?;

            let tx_cid = hdr.messages;
            println!("tx_cid: {:?}", tx_cid);
            let tx_raw = bs
                .get(&tx_cid)?
                .ok_or_else(|| anyhow!("missing TxMeta {}", tx_cid))?;
            println!("tx_raw: {:?}", tx_raw);

            let (bls_root, secp_root): (Cid, Cid) = serde_ipld_dagcbor::from_slice(&tx_raw)?;

            println!("bls_root: {:?}", bls_root);
            println!("secp_root: {:?}", secp_root);

            let bls_amt = Amtv0::<Cid, _>::load(&bls_root, bs)?;
            println!("bls_amt: {:?}", bls_amt);
            bls_amt.for_each(|_, c| {
                if seen.insert(*c) {
                    out.push(*c);
                }
                Ok(())
            })?;
            let secp_amt = Amtv0::<Cid, _>::load(&secp_root, bs)?;
            println!("secp_amt: {:?}", secp_amt);
            secp_amt.for_each(|_, c| {
                if seen.insert(*c) {
                    out.push(*c);
                }
                Ok(())
            })?;
        }
        Ok(out)
    }

    let mut results = Vec::with_capacity(bundle.claims.len());

    'each: for cl in &bundle.claims {
        println!("trusting parent ts");
        // 1) trust anchors
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

        println!("trusting child header");

        // 2) compute VM exec order from committed data
        let exec = exec_from_headers(&bs, &p_cids)?;
        println!("exec: {:?}", exec);
        let msg_cid = Cid::try_from(cl.message_cid.as_str())?;
        let Some(i) = exec.iter().position(|c| c == &msg_cid) else {
            results.push(false);
            continue;
        };
        if i as u64 != cl.exec_index {
            results.push(false);
            continue;
        }

        // 3) prove receipt[i] under child's ParentMessageReceipts
        let child_raw = bs
            .get(&child_cid)?
            .ok_or_else(|| anyhow!("missing child header"))?;
        let child_hdr: HeaderLite = serde_ipld_dagcbor::from_slice(&child_raw)?;
        let r_root = child_hdr.parent_message_receipts;
        let r_amt = Amtv0::<MessageReceipt, _>::load(&r_root, &bs)?;
        let Some(rcpt) = r_amt.get(i as u64)? else {
            results.push(false);
            continue;
        };

        // 4) prove event[j] under events_root
        let Some(ev_root) = rcpt.events_root else {
            results.push(false);
            continue;
        };
        let e_amt = Amt::<StampedEvent, _>::load(&ev_root, &bs)?;
        let Some(se) = e_amt.get(cl.event_index)? else {
            results.push(false);
            continue;
        };

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
