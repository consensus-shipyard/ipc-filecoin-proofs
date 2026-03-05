use anyhow::{anyhow, Context, Result};
use std::collections::BTreeSet;

use cid::Cid;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::from_slice as dag_from_slice;
use fvm_ipld_hamt::{BytesKey, Hamt};
use fvm_ipld_kamt::{id::Identity, Kamt};
use fvm_shared::HAMT_BIT_WIDTH;
use ipld_core::ipld::Ipld;
use serde::de::IgnoredAny;
use serde::Deserialize;

// Inline small-map: { "v": [ [key_bytes, value_bytes], ... ] }
#[derive(Debug, Deserialize)]
struct SmallMap {
    v: Vec<(serde_bytes::ByteBuf, serde_bytes::ByteBuf)>,
}

// Inline tuple: [ <params: bytes>, SmallMap ]
#[derive(Debug, Deserialize)]
struct InlineTuple(serde_bytes::ByteBuf, SmallMap);

// Inline tuple *with list wrapper*: [ <params: bytes>, [ SmallMap ] ]
#[derive(Debug, Deserialize)]
struct InlineTupleList(serde_bytes::ByteBuf, Vec<SmallMap>);

// Optional ADT wrapper: [root_cid, bitwidth]  (rare here)
#[derive(Debug, Deserialize)]
struct MapTuple(pub Cid, pub u64);

// Optional ADT wrapper (map form): { root, bitwidth, ... }
#[derive(Debug, Deserialize)]
struct MapStruct {
    pub root: Cid,
    pub bitwidth: u64,
}

#[derive(Debug, Deserialize)]
struct LinkTupleWrapper {
    l: Vec<LinkListItem>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum LinkListItem {
    Link(Cid),
    Other(IgnoredAny),
}

/// Read a 32-byte FEVM storage slot from the contract state.
/// `slot_key` is the 32-byte slot *preimage* (e.g., mapping: keccak(pad(key)||pad(slotIndex))).
pub fn read_storage_slot<BS: Blockstore>(
    store: &BS,
    contract_state_root: &Cid,
    slot_key: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    let mut raw = store
        .get(contract_state_root)?
        .ok_or_else(|| anyhow!("missing contract_state root {}", contract_state_root))?;

    // Some FEVM states wrap the actual node in a CBOR byte string.
    if let Ok(blob) = dag_from_slice::<serde_bytes::ByteBuf>(&raw) {
        let inner = blob.into_vec();
        if let Ok(next_root) = Cid::try_from(inner.as_slice()) {
            if next_root != *contract_state_root {
                return read_storage_slot(store, &next_root, slot_key);
            }
        }
        raw = inner;
    }

    let kamt_like_root = dag_from_slice::<Ipld>(&raw)
        .ok()
        .map(|ipld| matches!(ipld, Ipld::List(_) | Ipld::Map(_)))
        .unwrap_or(false);

    // Generic IPLD map handling for KAMT pointers/values:
    // - {"v": [[key_bytes, value_bytes], ...]}
    // - {"l": [<next_cid>, <ext_len>, <ext_bits>]}
    if let Ok(Ipld::Map(map)) = dag_from_slice::<Ipld>(&raw) {
        if let Some(Ipld::List(entries)) = map.get("v") {
            for entry in entries {
                if let Ipld::List(kv) = entry {
                    if kv.len() == 2 {
                        if let (Ipld::Bytes(k), Ipld::Bytes(v)) = (&kv[0], &kv[1]) {
                            if k.as_slice() == slot_key {
                                return Ok(Some(v.clone()));
                            }
                        }
                    }
                }
            }
            return Ok(None);
        }
        if let Some(Ipld::List(items)) = map.get("l") {
            if let Some(Ipld::Link(next_root)) = items.first() {
                if next_root != contract_state_root {
                    return read_storage_slot(store, next_root, slot_key);
                }
            }
        }
    }

    // Custom generic walker for KAMT node/pointer encodings used by FEVM state.
    if let Some(value) = search_kamt_like(store, contract_state_root, slot_key)? {
        return Ok(Some(value));
    }
    if kamt_like_root {
        // KAMT-shaped root but key not present; treat as empty slot instead of forcing HAMT decode.
        return Ok(None);
    }

    // A1) Inline: [params, [SmallMap]]
    if let Ok(InlineTupleList(_params, vec_sm)) = dag_from_slice::<InlineTupleList>(&raw) {
        if let Some(sm) = vec_sm.into_iter().next() {
            for (k, v) in sm.v {
                if k.as_ref() == slot_key {
                    return Ok(Some(v.into_vec()));
                }
            }
            return Ok(None);
        }
    }

    // A2) Inline: [params, SmallMap]
    if let Ok(InlineTuple(_params, sm)) = dag_from_slice::<InlineTuple>(&raw) {
        for (k, v) in sm.v {
            if k.as_ref() == slot_key {
                return Ok(Some(v.into_vec()));
            }
        }
        return Ok(None);
    }

    // A3) Inline: SmallMap directly
    if let Ok(SmallMap { v: pairs }) = dag_from_slice::<SmallMap>(&raw) {
        for (k, v) in pairs {
            if k.as_ref() == slot_key {
                return Ok(Some(v.into_vec()));
            }
        }
        return Ok(None);
    }

    // B1) Wrapper → HAMT (tuple form)
    if let Ok(MapTuple(root, bw)) = dag_from_slice::<MapTuple>(&raw) {
        let hamt = Hamt::<_, Vec<u8>>::load_with_bit_width(&root, store, bw as u32)
            .context("open contract_state HAMT (wrapped tuple)")?;
        return Ok(hamt.get(&BytesKey::from(slot_key.to_vec()))?.cloned());
    }

    // B2) Wrapper → HAMT (map form)
    if let Ok(MapStruct { root, bitwidth }) = dag_from_slice::<MapStruct>(&raw) {
        let hamt = Hamt::<_, Vec<u8>>::load_with_bit_width(&root, store, bitwidth as u32)
            .context("open contract_state HAMT (wrapped map)")?;
        return Ok(hamt.get(&BytesKey::from(slot_key.to_vec()))?.cloned());
    }

    // B3) Generic wrapper map (observed shape: {"l": [<root_cid>, ...]})
    if let Ok(LinkTupleWrapper { l }) = dag_from_slice::<LinkTupleWrapper>(&raw) {
        if let Some(LinkListItem::Link(root)) = l.first() {
            if root != contract_state_root {
                return read_storage_slot(store, root, slot_key);
            }
        }
    }
    // B3b) Also handle legacy tuple form if it can be decoded directly.
    if let Ok((root, _meta, _rest)) = dag_from_slice::<(Cid, u64, Vec<u8>)>(&raw) {
        if root != *contract_state_root {
            eprintln!(
                "storage decode: unwrapping link-list wrapper {} -> {}",
                contract_state_root, root
            );
            // Recurse through wrapper links until we hit a concrete map structure.
            return read_storage_slot(store, &root, slot_key);
        }
    }

    // B4) Direct KAMT at this CID (modern FEVM contract storage shape)
    match Kamt::<_, [u8; 32], Vec<u8>, Identity>::load(contract_state_root, store) {
        Ok(kamt) => return Ok(kamt.get(slot_key)?.cloned()),
        Err(err) => {
            if let Some(next_root) = extract_wrapper_link_from_error(&err.to_string()) {
                if next_root != *contract_state_root {
                    return read_storage_slot(store, &next_root, slot_key);
                }
            }
        }
    }

    // C) Direct HAMT at this CID (default bitwidth = 5)
    let hamt =
        Hamt::<_, Vec<u8>>::load_with_bit_width(contract_state_root, store, HAMT_BIT_WIDTH as u32)
            .or_else(|err| {
                if let Some(next_root) = extract_wrapper_link_from_error(&err.to_string()) {
                    if next_root != *contract_state_root {
                        // Fall back to full recursive decode so we can unwrap nested pointer formats.
                        return Err(anyhow!(
                            "wrapped_root:{}|{}",
                            next_root,
                            err
                        ));
                    }
                }
                Err(anyhow!(err))
            });

    let hamt = match hamt {
        Ok(h) => h,
        Err(err) => {
            let msg = err.to_string();
            if let Some(rest) = msg.strip_prefix("wrapped_root:") {
                if let Some((cid_str, _)) = rest.split_once('|') {
                    if let Ok(next_root) = cid_str.parse::<Cid>() {
                        return read_storage_slot(store, &next_root, slot_key);
                    }
                }
            }
            return Err(err).context("open contract_state HAMT");
        }
    };

    Ok(hamt.get(&BytesKey::from(slot_key.to_vec()))?.cloned())
}

fn extract_wrapper_link_from_error(msg: &str) -> Option<Cid> {
    let marker = "Link(";
    let start = msg.find(marker)? + marker.len();
    let rest = &msg[start..];
    let end = rest.find(')')?;
    rest[..end].parse::<Cid>().ok()
}

fn search_kamt_like<BS: Blockstore>(
    store: &BS,
    root: &Cid,
    slot_key: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    let mut visited = BTreeSet::<Cid>::new();
    search_kamt_like_inner(store, root, slot_key, &mut visited)
}

fn search_kamt_like_inner<BS: Blockstore>(
    store: &BS,
    cid: &Cid,
    slot_key: &[u8; 32],
    visited: &mut BTreeSet<Cid>,
) -> Result<Option<Vec<u8>>> {
    if !visited.insert(*cid) {
        return Ok(None);
    }
    let raw = match store.get(cid)? {
        Some(v) => v,
        None => return Ok(None),
    };
    let ipld = match dag_from_slice::<Ipld>(&raw) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    search_in_ipld(store, &ipld, slot_key, visited)
}

fn search_in_ipld<BS: Blockstore>(
    store: &BS,
    ipld: &Ipld,
    slot_key: &[u8; 32],
    visited: &mut BTreeSet<Cid>,
) -> Result<Option<Vec<u8>>> {
    match ipld {
        // KAMT node encoding is commonly [bitfield, pointers]
        Ipld::List(items) => {
            for item in items {
                if let Some(v) = search_in_ipld(store, item, slot_key, visited)? {
                    return Ok(Some(v));
                }
            }
            Ok(None)
        }
        // Pointer encoding:
        // - {"v": [[key,value], ...]}
        // - {"l": [cid, ext_len, ext_bits]}
        Ipld::Map(map) => {
            if let Some(Ipld::List(values)) = map.get("v") {
                for kv in values {
                    if let Ipld::List(pair) = kv {
                        if pair.len() == 2 {
                            if let (Ipld::Bytes(k), Ipld::Bytes(v)) = (&pair[0], &pair[1]) {
                                if key_matches_slot(slot_key, k) {
                                    return Ok(Some(v.clone()));
                                }
                            }
                        }
                    }
                }
            }
            if let Some(Ipld::List(link_data)) = map.get("l") {
                if let Some(Ipld::Link(next)) = link_data.first() {
                    if let Some(v) = search_kamt_like_inner(store, next, slot_key, visited)? {
                        return Ok(Some(v));
                    }
                }
            }
            for v in map.values() {
                if let Some(found) = search_in_ipld(store, v, slot_key, visited)? {
                    return Ok(Some(found));
                }
            }
            Ok(None)
        }
        _ => Ok(None),
    }
}

fn key_matches_slot(slot_key: &[u8; 32], candidate: &[u8]) -> bool {
    if candidate == slot_key {
        return true;
    }
    let trimmed = trim_leading_zeros(slot_key);
    candidate == trimmed
}

fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let idx = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len() - 1);
    &bytes[idx..]
}
