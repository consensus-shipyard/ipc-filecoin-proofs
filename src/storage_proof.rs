// Copyright 2022-2024 Protocol Labs
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use cid::Cid;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::from_slice;
use fvm_ipld_hamt::Hamt;
use multihash_codetable::MultihashDigest;
use serde::Deserialize;
use url::Url;

use crate::blockstore::{MemoryBlockstore, RecordingBlockstore};
use crate::client::LotusClient;
use crate::types::{
    BlockHeaderBundle, F3CertificateBytes, HamtActorProof, KamtStorageProof, StateLookupIDResponse,
    StorageSubmission,
};

/// KAMT type for EVM storage (32-byte keys to values)
type Kamt<BS> = fvm_ipld_hamt::Hamt<BS, fvm_ipld_hamt::BytesKey, fvm_ipld_hamt::BytesKey>;

/// Build a storage proof
pub async fn build_storage_submission(
    rpc: &str,
    height_h_plus_1: i64,
    contract_addr: &str,
    key32: [u8; 32],
) -> Result<StorageSubmission> {
    let client = LotusClient::new(Url::parse(rpc)?, None);

    // Step 1: Get tipset at height H+1
    let tipset = client
        .get_tipset_by_height(height_h_plus_1, None)
        .await
        .context("Failed to get tipset")?;

    // Pick first block
    let block_cid = Cid::try_from(&tipset.cids[0]).context("Failed to parse block CID")?;

    // Step 2: Get block header raw bytes
    let header_raw_b64 = client
        .chain_read_obj(block_cid)
        .await
        .context("Failed to read block header")?;
    let header_raw = BASE64
        .decode(&header_raw_b64)
        .context("Failed to decode header bytes")?;

    // Verify CID matches
    let computed_cid = Cid::new_v1(
        fvm_ipld_encoding::DAG_CBOR,
        multihash_codetable::Code::Blake2b256.digest(&header_raw),
    );
    if computed_cid != block_cid {
        anyhow::bail!("Header CID mismatch");
    }

    // Step 3: Decode header to get ParentStateRoot
    let header = &tipset.blocks[0];
    let state_root =
        Cid::try_from(&header.parent_state_root).context("Failed to parse state root")?;

    // Step 4: Resolve actor ID at H+1
    let tipset_key = serde_json::json!(tipset.cids);
    let id_response: StateLookupIDResponse = client
        .request(
            "Filecoin.StateLookupID",
            serde_json::json!([contract_addr, tipset_key]),
        )
        .await
        .context("Failed to lookup actor ID")?;

    // Parse actor ID (format: "f0<id>" or "t0<id>")
    let id_str = id_response.0;
    let id_address: u64 = id_str
        .strip_prefix("f0")
        .or_else(|| id_str.strip_prefix("t0"))
        .and_then(|s| s.parse().ok())
        .context("Failed to parse actor ID")?;

    // Step 5: Build HAMT proof for actor
    let recording_store = RecordingBlockstore::new(client.clone());
    let hamt: Hamt<_, fvm_ipld_hamt::BytesKey, fvm_ipld_hamt::BytesKey> =
        Hamt::load_with_bit_width(&state_root, &recording_store, 5)
            .context("Failed to load state HAMT")?;

    // Convert ID to address bytes for HAMT lookup
    let id_bytes = fvm_shared::address::Address::new_id(id_address).to_bytes();
    let id_key = fvm_ipld_hamt::BytesKey(id_bytes);

    let actor_value_bytes = hamt
        .get(&id_key)
        .context("Failed to get actor from HAMT")?
        .context("Actor not found in state tree")?
        .clone();

    let actor_value_raw: Vec<u8> = actor_value_bytes.0;

    let hamt_nodes = recording_store.trace();

    // Step 6: Decode actor to get Head
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct ActorPartial {
        head: Cid,
    }
    let actor: ActorPartial = from_slice(&actor_value_raw).context("Failed to decode actor")?;

    // Step 7: Get EVM state object
    let evm_state_raw_b64 = client
        .chain_read_obj(actor.head)
        .await
        .context("Failed to read EVM state")?;
    let evm_state_raw = BASE64
        .decode(&evm_state_raw_b64)
        .context("Failed to decode EVM state bytes")?;

    // Verify CID
    let computed = Cid::new_v1(
        fvm_ipld_encoding::DAG_CBOR,
        multihash_codetable::Code::Blake2b256.digest(&evm_state_raw),
    );
    if computed != actor.head {
        anyhow::bail!("EVM state CID mismatch");
    }

    // Step 8: Decode EVM state to get ContractState KAMT root
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct EvmStatePartial {
        contract_state: Cid,
    }
    let evm_state: EvmStatePartial =
        from_slice(&evm_state_raw).context("Failed to decode EVM state")?;

    // Step 9: Build KAMT proof for storage value
    let recording_store2 = RecordingBlockstore::new(client.clone());
    let kamt: Kamt<_> = Hamt::load_with_bit_width(&evm_state.contract_state, &recording_store2, 5)
        .context("Failed to load KAMT")?;

    let key_bytes = fvm_ipld_hamt::BytesKey(key32.to_vec());
    let value_bytes = kamt
        .get(&key_bytes)
        .context("Failed to get value from KAMT")?
        .cloned()
        .unwrap_or_else(|| fvm_ipld_hamt::BytesKey(vec![0u8; 32]));
    let value_vec: Vec<u8> = value_bytes.0;

    // Convert to [u8; 32]
    let mut value = [0u8; 32];
    if value_vec.len() >= 32 {
        value.copy_from_slice(&value_vec[..32]);
    } else {
        value[..value_vec.len()].copy_from_slice(&value_vec);
    }

    let kamt_nodes = recording_store2.trace();

    Ok(StorageSubmission {
        f3_cert: F3CertificateBytes(vec![]), // Mock for now
        header: BlockHeaderBundle {
            cid: block_cid,
            raw: header_raw,
        },
        hamt: HamtActorProof {
            state_root,
            id_address,
            nodes: hamt_nodes,
            actor_value_raw,
            actor_head: actor.head,
            actor_code: None,
        },
        kamt: KamtStorageProof {
            root: evm_state.contract_state,
            key: key32,
            nodes: kamt_nodes,
            value,
            evm_state_raw,
        },
    })
}

/// Verify a storage submission (mock version)
pub fn verify_storage_submission_mock(sub: &StorageSubmission) -> Result<()> {
    // Step 1: Accept any F3 cert (mock)
    tracing::info!("F3 cert accepted (mock)");

    // Step 2: Verify header
    let computed_cid = Cid::new_v1(
        fvm_ipld_encoding::DAG_CBOR,
        multihash_codetable::Code::Blake2b256.digest(&sub.header.raw),
    );
    if computed_cid != sub.header.cid {
        anyhow::bail!("Header CID mismatch in verification");
    }

    // Decode header to get ParentStateRoot
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct HeaderPartial {
        parent_state_root: Cid,
    }
    let header: HeaderPartial = from_slice(&sub.header.raw).context("Failed to decode header")?;

    if header.parent_state_root != sub.hamt.state_root {
        anyhow::bail!("State root mismatch with header");
    }

    // Step 3: Verify HAMT proof
    let memory_store = MemoryBlockstore::new();

    // Put all HAMT nodes into the store (put_keyed verifies CID)
    for node in &sub.hamt.nodes {
        memory_store
            .put_keyed(&node.cid, &node.raw)
            .context("Failed to store HAMT node")?;
    }

    // Load HAMT and verify actor
    let hamt: Hamt<_, fvm_ipld_hamt::BytesKey, fvm_ipld_hamt::BytesKey> =
        Hamt::load_with_bit_width(&sub.hamt.state_root, &memory_store, 5)
            .context("Failed to load HAMT in verification")?;

    let id_bytes = fvm_shared::address::Address::new_id(sub.hamt.id_address).to_bytes();
    let id_key = fvm_ipld_hamt::BytesKey(id_bytes);
    let actor_value = hamt
        .get(&id_key)
        .context("Failed to get actor in verification")?
        .context("Actor not found in HAMT during verification")?;

    let actor_value_vec: Vec<u8> = actor_value.clone().0;
    if actor_value_vec != sub.hamt.actor_value_raw {
        anyhow::bail!("Actor value mismatch in verification");
    }

    // Decode actor to verify Head
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct ActorPartial {
        head: Cid,
    }
    let actor: ActorPartial =
        from_slice(&sub.hamt.actor_value_raw).context("Failed to decode actor in verification")?;

    if actor.head != sub.hamt.actor_head {
        anyhow::bail!("Actor head mismatch");
    }

    // Step 4: Verify EVM state object
    let computed = Cid::new_v1(
        fvm_ipld_encoding::DAG_CBOR,
        multihash_codetable::Code::Blake2b256.digest(&sub.kamt.evm_state_raw),
    );
    if computed != sub.hamt.actor_head {
        anyhow::bail!("EVM state CID mismatch in verification");
    }

    // Decode EVM state to verify ContractState root
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct EvmStatePartial {
        contract_state: Cid,
    }
    let evm_state: EvmStatePartial = from_slice(&sub.kamt.evm_state_raw)
        .context("Failed to decode EVM state in verification")?;

    if evm_state.contract_state != sub.kamt.root {
        anyhow::bail!("KAMT root mismatch with EVM state");
    }

    // Step 5: Verify KAMT proof
    let memory_store2 = MemoryBlockstore::new();

    // Put all KAMT nodes into the store (put_keyed verifies CID)
    for node in &sub.kamt.nodes {
        memory_store2
            .put_keyed(&node.cid, &node.raw)
            .context("Failed to store KAMT node")?;
    }

    // Load KAMT and verify value
    let kamt: Kamt<_> = Hamt::load_with_bit_width(&sub.kamt.root, &memory_store2, 5)
        .context("Failed to load KAMT in verification")?;

    let key_bytes = fvm_ipld_hamt::BytesKey(sub.kamt.key.to_vec());
    let value_bytes = kamt
        .get(&key_bytes)
        .context("Failed to get value in verification")?
        .cloned()
        .unwrap_or_else(|| fvm_ipld_hamt::BytesKey(vec![0u8; 32]));
    let value_vec: Vec<u8> = value_bytes.0;

    // Convert to [u8; 32]
    let mut value = [0u8; 32];
    if value_vec.len() >= 32 {
        value.copy_from_slice(&value_vec[..32]);
    } else {
        value[..value_vec.len()].copy_from_slice(&value_vec);
    }

    if value != sub.kamt.value {
        anyhow::bail!("Storage value mismatch in verification");
    }

    tracing::info!("✅ Storage proof verified successfully");
    Ok(())
}
