pub mod common;
pub mod events;
pub mod generator;
pub mod storage;
pub mod trust;
pub mod verifier;

// Re-export unified API
pub use common::address::resolve_eth_address_to_actor_id;
pub use common::bundle::{ProofBlock, UnifiedProofBundle, UnifiedVerificationResult};
pub use common::error::{ProofError, ProofResult};
pub use generator::{generate_proof_bundle, EventProofSpec, StorageProofSpec};
pub use trust::TrustPolicy;
pub use verifier::verify_proof_bundle;

// Re-export individual proof APIs for convenience
pub use events::{
    create_event_filter, generate_event_proof, verify_event_proof, EventProof, EventProofBundle,
};
pub use storage::{
    calculate_storage_slot, compute_mapping_slot, generate_storage_proof, verify_storage_proof,
    StorageProof,
};
