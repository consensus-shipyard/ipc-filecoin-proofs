use anyhow::Result;
use ethereum_types::H256;
use std::collections::BTreeSet;

use crate::client::types::ApiTipset;
use crate::client::{CachedBlockstore, LotusClient, RpcBlockstore};
use crate::proofs::common::bundle::{ProofBlock, UnifiedProofBundle};
use crate::proofs::events::generator::generate_event_proof;
use crate::proofs::storage::generator::generate_storage_proof;

/// Configuration for generating storage proofs
pub struct StorageProofSpec {
    pub actor_id: u64, // Filecoin Actor ID (resolved from Ethereum address if needed)
    pub slot: H256,
}

/// Configuration for generating event proofs
pub struct EventProofSpec {
    pub event_signature: String, // Event signature to match (e.g., "NewTopDownMessage(bytes32,uint256)")
    pub topic_1: String,         // First indexed topic to match
    pub actor_id_filter: Option<u64>, // Optional actor ID to filter events by emitter
}

/// Generate a unified proof bundle containing both storage and event proofs
pub async fn generate_proof_bundle(
    client: &LotusClient,
    parent: &ApiTipset,
    child: &ApiTipset,
    storage_specs: Vec<StorageProofSpec>,
    event_specs: Vec<EventProofSpec>,
) -> Result<UnifiedProofBundle> {
    let mut storage_proofs = Vec::new();
    let mut event_proofs = Vec::new();
    let mut all_blocks = BTreeSet::new(); // Use BTreeSet to deduplicate

    // Create a shared cache for all proof generation
    // This dramatically reduces RPC calls by reusing fetched blocks
    let rpc_store = RpcBlockstore::new(client);
    let cached_store = CachedBlockstore::new(rpc_store);
    let shared_cache = cached_store.shared_cache();

    // Generate storage proofs with shared cache
    for spec in storage_specs {
        // Create a new cached store sharing the same cache
        let rpc = RpcBlockstore::new(client);
        let store = CachedBlockstore::with_shared_cache(rpc, shared_cache.clone());

        let (proof, blocks) =
            generate_storage_proof(&store, parent, child, spec.actor_id, spec.slot).await?;

        storage_proofs.push(proof);
        for block in blocks {
            all_blocks.insert((block.cid, block.data));
        }
    }

    // Generate event proofs with shared cache
    for spec in event_specs {
        // Create a new cached store sharing the same cache
        let rpc = RpcBlockstore::new(client);
        let store = CachedBlockstore::with_shared_cache(rpc, shared_cache.clone());

        let bundle = generate_event_proof(
            client,
            &store,
            parent,
            child,
            &spec.event_signature,
            &spec.topic_1,
            spec.actor_id_filter,
        )
        .await?;

        event_proofs.extend(bundle.proofs);
        for block in bundle.blocks {
            all_blocks.insert((block.cid, block.data));
        }
    }

    // Log cache statistics for debugging
    let (entries, bytes) = cached_store.cache_stats();
    eprintln!("Cache stats: {} entries, {} bytes", entries, bytes);

    // Convert deduplicated blocks back to Vec<ProofBlock>
    let blocks: Vec<ProofBlock> = all_blocks
        .into_iter()
        .map(|(cid, data)| ProofBlock { cid, data })
        .collect();

    Ok(UnifiedProofBundle {
        storage_proofs,
        event_proofs,
        blocks,
    })
}
