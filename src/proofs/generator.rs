use anyhow::Result;
use cid::Cid;
use ethereum_types::H256;
use std::collections::BTreeSet;

use crate::client::LotusClient;
use crate::proofs::common::bundle::{ProofBlock, UnifiedProofBundle};
use crate::proofs::events::{bundle::EventProof, generator::generate_event_proof};
use crate::proofs::storage::{bundle::StorageProof, generator::generate_storage_proof};
use crate::types::ApiTipset;

/// Configuration for generating storage proofs
pub struct StorageProofSpec {
    pub actor_id: u64,
    pub slot: H256,
}

/// Configuration for generating event proofs
pub struct EventProofSpec {
    pub event_signature: String,
    pub topic_1: String,
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

    // Generate storage proofs
    for spec in storage_specs {
        let (proof, blocks) =
            generate_storage_proof(client, parent, child, spec.actor_id, spec.slot).await?;

        storage_proofs.push(proof);
        for block in blocks {
            all_blocks.insert((block.cid, block.data));
        }
    }

    // Generate event proofs
    for spec in event_specs {
        let bundle =
            generate_event_proof(client, parent, child, &spec.event_signature, &spec.topic_1)
                .await?;

        event_proofs.extend(bundle.proofs);
        for block in bundle.blocks {
            all_blocks.insert((block.cid, block.data));
        }
    }

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
