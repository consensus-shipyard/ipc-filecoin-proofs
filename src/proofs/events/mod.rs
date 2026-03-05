pub mod bundle;
pub mod generator;
pub mod utils;
pub mod verifier;

// Internal exports - only expose what's needed by other modules
pub use bundle::{EventData, EventProof, EventProofBundle};
pub use generator::generate_event_proof;
pub use verifier::{create_event_filter, verify_event_proof};
