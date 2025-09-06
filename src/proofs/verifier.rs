use anyhow::Result;
use cid::Cid;
use fvm_shared::event::ActorEvent;

use crate::proofs::common::bundle::{UnifiedProofBundle, UnifiedVerificationResult};
use crate::proofs::events::bundle::EventProofBundle;
use crate::proofs::events::verifier::verify_event_proof;
use crate::proofs::storage::verifier::verify_storage_proof;
use crate::proofs::trust::TrustPolicy;

/// Verify a unified proof bundle containing both storage and event proofs
pub fn verify_proof_bundle(
    bundle: &UnifiedProofBundle,
    trust_policy: &TrustPolicy,
    event_filter: Option<&dyn Fn(&ActorEvent) -> bool>,
) -> Result<UnifiedVerificationResult> {
    // Verify storage proofs
    let mut storage_results = Vec::new();
    for proof in &bundle.storage_proofs {
        // Create a closure that uses the trust policy
        let verifier = |epoch: i64, cid: &Cid| -> bool {
            trust_policy
                .verify_child_header(epoch, cid)
                .unwrap_or(false)
        };

        let result = verify_storage_proof(proof, &bundle.blocks, &verifier)?;
        storage_results.push(result);
    }

    // Verify event proofs - need to create an EventProofBundle for the verifier
    let event_bundle = EventProofBundle {
        proofs: bundle.event_proofs.clone(),
        blocks: bundle.blocks.clone(),
    };

    // Create closures for event verification
    let parent_verifier = |epoch: i64, cids: &[Cid]| -> bool {
        trust_policy
            .verify_parent_tipset(epoch, cids)
            .unwrap_or(false)
    };
    let child_verifier = |epoch: i64, cid: &Cid| -> bool {
        trust_policy
            .verify_child_header(epoch, cid)
            .unwrap_or(false)
    };

    let event_results = verify_event_proof(
        &event_bundle,
        &parent_verifier,
        &child_verifier,
        event_filter,
    )?;

    Ok(UnifiedVerificationResult {
        storage_results,
        event_results,
    })
}
