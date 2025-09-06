pub mod common;
pub mod events;
pub mod generator;
pub mod storage;
pub mod trust;
pub mod verifier;

// Re-export unified API (only what's actually used)
pub use common::address::resolve_eth_address_to_actor_id;
pub use generator::{generate_proof_bundle, EventProofSpec, StorageProofSpec};
pub use trust::TrustPolicy;
pub use verifier::verify_proof_bundle;

// Re-export utilities that are used
pub use events::create_event_filter;
pub use storage::calculate_storage_slot;
