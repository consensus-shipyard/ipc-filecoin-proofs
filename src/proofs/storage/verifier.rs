use anyhow::{anyhow, Context};
use cid::Cid;
use fvm_ipld_blockstore::{Blockstore, MemoryBlockstore};
use fvm_shared::address::Address;
use hex;

use crate::proofs::common::{
    bundle::ProofBlock,
    decode::{extract_parent_state_root, get_actor_state, parse_evm_state},
    evm::left_pad_32,
};
use crate::proofs::storage::{bundle::StorageProof, decode::read_storage_slot};

/// Verify a storage proof offline using the provided witness blocks
pub fn verify_storage_proof(
    proof: &StorageProof,
    blocks: &[ProofBlock],
    // trust anchor: the caller tells us which child header is finalized
    is_trusted_child_header: &dyn Fn(i64, &Cid) -> bool,
) -> anyhow::Result<bool> {
    // 0) Load witness blocks into a fresh store
    let bs = MemoryBlockstore::new();
    for b in blocks {
        bs.put_keyed(&b.cid, &b.data)?;
    }

    // 1) Trust anchor: child header is finalized
    let child_cid = Cid::try_from(proof.child_block_cid.as_str())?;
    if !is_trusted_child_header(proof.child_epoch, &child_cid) {
        return Ok(false);
    }

    // 2) child header → ParentStateRoot (decode from RAW like the generator)
    let child_header_raw = bs
        .get(&child_cid)?
        .ok_or_else(|| anyhow!("missing child header {}", child_cid))?;
    let psr_from_header = extract_parent_state_root(&child_header_raw)
        .context("decode ParentStateRoot from child header")?;
    if psr_from_header.to_string() != proof.parent_state_root {
        return Ok(false);
    }

    // 3) Load actor object from the state-tree at ParentStateRoot (same helper)
    let id_addr = Address::new_id(proof.actor_id);
    let actor_obj = get_actor_state(&bs, &psr_from_header, id_addr)
        .context("get_actor_state")?;
    if actor_obj.state.to_string() != proof.actor_state_cid {
        return Ok(false);
    }

    // 4) EVM state → storage_root (same helper)
    let evm_state_raw = bs
        .get(&actor_obj.state)?
        .ok_or_else(|| anyhow!("missing EVM state {}", actor_obj.state))?;
    let evm_state = parse_evm_state(&evm_state_raw).context("parse_evm_state")?;
    if evm_state.contract_state.to_string() != proof.storage_root {
        return Ok(false);
    }

    // 5) Storage map: read slot (same helper)
    let mut slot_preimage = [0u8; 32];
    hex::decode_to_slice(proof.slot.trim_start_matches("0x"), &mut slot_preimage)
        .context("slot hex must be 32 bytes")?;

    let value_raw = read_storage_slot(&bs, &evm_state.contract_state, &slot_preimage)
        .context("read storage slot")?
        .unwrap_or_default(); // Missing key means zero

    // 6) Compare (left-pad to 32 like the generator)
    let value32 = left_pad_32(&value_raw);
    let got_hex = format!("0x{}", hex::encode(value32));

    Ok(got_hex.eq_ignore_ascii_case(&proof.value))
}
