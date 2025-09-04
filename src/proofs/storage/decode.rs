use anyhow::{anyhow, Context, Result};
use cid::Cid;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::from_slice as dag_from_slice;
use fvm_ipld_hamt::{BytesKey, Hamt};
use fvm_shared::HAMT_BIT_WIDTH;
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

/// Read a 32-byte FEVM storage slot from the contract state.
/// `slot_key` is the 32-byte slot *preimage* (e.g., mapping: keccak(pad(key)||pad(slotIndex))).
pub fn read_storage_slot<BS: Blockstore>(
    store: &BS,
    contract_state_root: &Cid,
    slot_key: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    let raw = store
        .get(contract_state_root)?
        .ok_or_else(|| anyhow!("missing contract_state root {}", contract_state_root))?;

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

    // C) Direct HAMT at this CID (default bitwidth = 5)
    let hamt =
        Hamt::<_, Vec<u8>>::load_with_bit_width(contract_state_root, store, HAMT_BIT_WIDTH as u32)
            .context("open contract_state HAMT")?;

    Ok(hamt.get(&BytesKey::from(slot_key.to_vec()))?.cloned())
}
