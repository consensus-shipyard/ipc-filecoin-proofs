use anyhow::Result;
use cid::Cid;
use fvm_shared::event::ActorEvent;

use crate::proofs::common::bundle::{UnifiedProofBundle, UnifiedVerificationResult};
use crate::proofs::events::verifier::verify_event_proof;
use crate::proofs::events::bundle::EventProofBundle;
use crate::proofs::storage::verifier::verify_storage_proof;

/// Trust anchors for verification
pub struct TrustAnchors {
    /// Function to verify if a parent tipset is finalized
    pub is_trusted_parent_ts: Box<dyn Fn(i64, &[Cid]) -> bool>,
    /// Function to verify if a child header is finalized
    pub is_trusted_child_header: Box<dyn Fn(i64, &Cid) -> bool>,
}

impl TrustAnchors {
    /// Create trust anchors that accept everything (for testing)
    pub fn accept_all() -> Self {
        Self {
            is_trusted_parent_ts: Box::new(|_, _| true),
            is_trusted_child_header: Box::new(|_, _| true),
        }
    }
}

/// Verify a unified proof bundle containing both storage and event proofs
pub fn verify_proof_bundle(
    bundle: &UnifiedProofBundle,
    trust_anchors: &TrustAnchors,
    event_filter: Option<&dyn Fn(&ActorEvent) -> bool>,
) -> Result<UnifiedVerificationResult> {
    // Verify storage proofs
    let mut storage_results = Vec::new();
    for proof in &bundle.storage_proofs {
        let result = verify_storage_proof(
            proof,
            &bundle.blocks,
            &*trust_anchors.is_trusted_child_header,
        )?;
        storage_results.push(result);
    }

    // Verify event proofs - need to create an EventProofBundle for the verifier
    let event_bundle = EventProofBundle {
        proofs: bundle.event_proofs.clone(),
        blocks: bundle.blocks.clone(),
    };
    
    let event_results = verify_event_proof(
        &event_bundle,
        &*trust_anchors.is_trusted_parent_ts,
        &*trust_anchors.is_trusted_child_header,
        event_filter,
    )?;

    Ok(UnifiedVerificationResult {
        storage_results,
        event_results,
    })
}
