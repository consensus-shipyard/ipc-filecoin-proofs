// Copyright 2022-2024 Protocol Labs
// SPDX-License-Identifier: MIT
mod cert;
mod client;
mod proofs;

use crate::client::LotusClient;

use client::types::ApiTipset;
use serde_json::json;
use url::Url;

use crate::proofs::{
    calculate_storage_slot, create_event_filter, generate_proof_bundle,
    resolve_eth_address_to_actor_id, verify_proof_bundle, EventProofSpec, StorageProofSpec,
    TrustPolicy,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = LotusClient::new(
        Url::parse("https://api.calibration.node.glif.io/rpc/v1").unwrap(),
        None,
    );

    let height = 2988247;
    let _last_top_down_nonce = 15;

    let parent: ApiTipset = client
        .request("Filecoin.ChainGetTipSetByHeight", json!([height, null]))
        .await?;
    let child: ApiTipset = client
        .request("Filecoin.ChainGetTipSetByHeight", json!([height + 1, null]))
        .await?;

    // Unified proof generation example
    let slot = calculate_storage_slot("calib-subnet-1", 0);

    // Contract configuration - you can use either:
    // 1. An Ethereum address that will be resolved to an actor ID
    // 2. A known actor ID directly

    // Option 1: Using Ethereum address (will be resolved via RPC)
    let contract_address = "0x52f864e96e8c85836c2df262ae34d2dc4df5953a";

    println!("\n Contract Configuration:");
    println!("  Ethereum address: {}", contract_address);

    // Resolve Ethereum address to Actor ID
    let actor_id = resolve_eth_address_to_actor_id(&client, contract_address).await?;

    // Define what proofs we want to generate
    let storage_spec = StorageProofSpec { actor_id, slot };

    let storage_specs = vec![storage_spec];

    // Event specs
    let event_specs = vec![EventProofSpec {
        event_signature: "NewTopDownMessage(bytes32,uint256)".to_string(),
        topic_1: "calib-subnet-1".to_string(),
    }];

    // Generate unified bundle with both storage and event proofs
    let unified_bundle =
        generate_proof_bundle(&client, &parent, &child, storage_specs, event_specs).await?;

    println!("\nUnified Proof Bundle generated:");
    println!("  Storage proofs: {}", unified_bundle.storage_proofs.len());
    println!("  Event proofs: {}", unified_bundle.event_proofs.len());
    println!("  Total witness blocks: {}", unified_bundle.blocks.len());

    // Option 1: Accept all - FOR TESTING ONLY
    let trust_policy = TrustPolicy::accept_all();

    // Option 2: F3 Certificate - FOR PRODUCTION
    // To use F3 certificates, you would get them from the F3 consensus protocol:
    // let f3_cert = get_f3_certificate_for_epoch(height)?;
    // let trust_policy = TrustPolicy::with_f3_certificate(f3_cert);

    let event_filter = create_event_filter("NewTopDownMessage(bytes32,uint256)", "calib-subnet-1");

    let verification_results =
        verify_proof_bundle(&unified_bundle, &trust_policy, Some(&event_filter))?;

    println!("\nVerification Results:");
    println!(
        "  Storage proofs valid: {:?}",
        verification_results.storage_results
    );
    println!(
        "  Event proofs valid: {:?}",
        verification_results.event_results
    );
    println!("  All valid: {}", verification_results.all_valid());

    Ok(())
}
