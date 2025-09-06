use anyhow::{anyhow, Result};
use cid::Cid;
use ethereum_types::H256;
use fvm_ipld_blockstore::Blockstore;
use hex;

use crate::client::types::ApiTipset;
use crate::proofs::common::{
    blockstore::RecordingBlockStore,
    bundle::ProofBlock,
    decode::{extract_parent_state_root, get_actor_state, parse_evm_state},
    evm::left_pad_32,
};
use crate::proofs::storage::{bundle::StorageProof, decode::read_storage_slot};
use fvm_shared::address::Address;

/// Generate a storage proof for a specific actor's storage slot
pub async fn generate_storage_proof<BS: Blockstore>(
    net: &BS,
    _parent: &ApiTipset, // H (finalized) - not used directly
    child: &ApiTipset,   // H+1 (finalized)
    actor_id: u64,
    slot_h256: H256,
) -> Result<(StorageProof, Vec<ProofBlock>)> {
    // Choose first block in the tipset (assume agreement)
    let child_cid = Cid::try_from(child.cids[0].cid.as_str())?;

    // Verify ParentStateRoot from header CBOR, cross-check JSON
    let rec_header = RecordingBlockStore::new(net);

    let child_header_raw = rec_header
        .get(&child_cid)?
        .ok_or_else(|| anyhow!("missing child header {}", child_cid))?;

    let psr_from_header = extract_parent_state_root(&child_header_raw)?;
    let psr_from_json = Cid::try_from(child.blocks[0].parent_state_root.cid.as_str())?;
    if psr_from_header != psr_from_json {
        return Err(anyhow!(
            "ParentStateRoot mismatch: header {} vs JSON {}",
            psr_from_header,
            psr_from_json
        ));
    }
    let parent_state_root = psr_from_header;

    // 1) Load actor object from the state-tree at ParentStateRoot
    let rec_state = RecordingBlockStore::new(&net);

    let id_addr = Address::new_id(actor_id);
    let actor_obj = get_actor_state(&rec_state, &parent_state_root, id_addr)?;

    // 2) Load EVM state to get storage_root
    let head_cid = actor_obj.state;

    let evm_state_raw = rec_state
        .get(&head_cid)?
        .ok_or_else(|| anyhow::anyhow!("missing EVM state {}", head_cid))?;

    let evm_state = parse_evm_state(&evm_state_raw)?;

    // This is the storage_root
    let storage_root: Cid = evm_state.contract_state;

    // 3) Load the storage HAMT and read the slot
    let rec_storage = RecordingBlockStore::new(&net);

    let value_raw =
        read_storage_slot(&rec_state, &storage_root, &slot_h256.into())?.unwrap_or_default(); // Missing key means zero

    // 4) Collect all blocks needed for offline verification
    let mut needed = std::collections::BTreeSet::<Cid>::new();
    // trust anchors
    needed.insert(child_cid);
    needed.insert(parent_state_root);
    // actor head and storage root
    needed.insert(head_cid);
    needed.insert(storage_root);

    // include traversals
    for c in rec_header.take_seen() {
        needed.insert(c);
    }
    for c in rec_state.take_seen() {
        needed.insert(c);
    }
    for c in rec_storage.take_seen() {
        needed.insert(c);
    }

    // Materialize witness blocks
    let mut blocks = Vec::<ProofBlock>::new();
    for c in needed {
        let raw = net.get(&c)?.ok_or_else(|| anyhow!("missing {}", c))?;
        blocks.push(ProofBlock { cid: c, data: raw });
    }

    let value32 = left_pad_32(&value_raw);

    // Create proof claim
    let proof = StorageProof {
        child_epoch: child.height,
        child_block_cid: child_cid.to_string(),
        parent_state_root: parent_state_root.to_string(),
        actor_id,
        actor_state_cid: head_cid.to_string(),
        storage_root: storage_root.to_string(),
        slot: format!("0x{}", hex::encode(slot_h256.0)),
        value: format!("0x{}", hex::encode(value32)),
    };

    Ok((proof, blocks))
}
