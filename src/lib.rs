// Copyright 2022-2024 Protocol Labs
// SPDX-License-Identifier: MIT

//! # Proofs Library
//!
//! A library for generating and verifying storage and event proofs for the IPC (InterPlanetary Consensus) project.
//!
//! ## Features
//!
//! - **Storage Proofs**: Generate and verify proofs of storage state
//! - **Event Proofs**: Generate and verify proofs of emitted events
//! - **Unified Bundles**: Combine storage and event proofs with witness data
//! - **Trust Policies**: Support for different trust models (Accept All, F3 Certificates)
//! - **Lotus RPC Integration**: Built-in support for Lotus RPC clients
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use proofs::{
//!     client::LotusClient,
//!     proofs::{
//!         generate_proof_bundle, verify_proof_bundle,
//!         EventProofSpec, StorageProofSpec, TrustPolicy,
//!         calculate_storage_slot, create_event_filter,
//!         resolve_eth_address_to_actor_id,
//!     }
//! };
//! use url::Url;
//! use serde_json::json;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Create a client
//!     let client = LotusClient::new(
//!         Url::parse("https://api.calibration.node.glif.io/rpc/v1")?,
//!         None,
//!     );
//!
//!     // Get tipsets for proof generation
//!     let height = 2992953;
//!     let parent = client.request("Filecoin.ChainGetTipSetByHeight", json!([height, null])).await?;
//!     let child = client.request("Filecoin.ChainGetTipSetByHeight", json!([height + 1, null])).await?;
//!
//!     // Configure storage proof
//!     let actor_id = resolve_eth_address_to_actor_id(&client, "0x52f864e96e8c85836c2df262ae34d2dc4df5953a").await?;
//!     let slot = calculate_storage_slot("calib-subnet-1", 0);
//!     let storage_specs = vec![StorageProofSpec { actor_id, slot }];
//!
//!     // Configure event proof
//!     let event_specs = vec![EventProofSpec {
//!         event_signature: "NewTopDownMessage(bytes32,uint256)".to_string(),
//!         topic_1: "calib-subnet-1".to_string(),
//!         actor_id_filter: Some(actor_id),
//!     }];
//!
//!     // Generate proof bundle
//!     let bundle = generate_proof_bundle(&client, &parent, &child, storage_specs, event_specs).await?;
//!
//!     // Verify the bundle
//!     let trust_policy = TrustPolicy::accept_all();
//!     let event_filter = create_event_filter("NewTopDownMessage(bytes32,uint256)", "calib-subnet-1");
//!     let results = verify_proof_bundle(&bundle, &trust_policy, Some(&event_filter))?;
//!
//!     assert!(results.all_valid());
//!     Ok(())
//! }
//! ```

// Internal modules
mod cert;

// Public modules
pub mod client;
pub mod proofs;

// Re-export commonly used types at the crate root for convenience
pub use client::LotusClient;
pub use proofs::{
    // Utility functions
    calculate_storage_slot,
    create_event_filter,
    // Core proof generation and verification
    generate_proof_bundle,
    resolve_eth_address_to_actor_id,
    verify_proof_bundle,

    // Proof specifications
    EventProofSpec,
    StorageProofSpec,

    // Trust and security
    TrustPolicy,
};
