// Copyright 2022-2024 Protocol Labs
// SPDX-License-Identifier: MIT
mod cert;
mod client;
mod proofs;
mod types;

use crate::client::LotusClient;
use anyhow::Ok;

use serde_json::json;
use types::ApiTipset;
use url::Url;

use crate::proofs::{
    calculate_storage_slot, create_event_filter, generate_proof_bundle, verify_proof_bundle,
    EventProofSpec, StorageProofSpec, TrustAnchors,
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

    // Define what proofs we want to generate
    let storage_specs = vec![StorageProofSpec {
        actor_id: 169451,
        slot,
    }];

    let event_specs = vec![EventProofSpec {
        event_signature: "NewTopDownMessage(bytes32,uint256)".to_string(),
        topic_1: "calib-subnet-1".to_string(),
    }];

    // Generate unified bundle with both storage and event proofs
    let unified_bundle =
        generate_proof_bundle(&client, &parent, &child, storage_specs, event_specs).await?;

    println!("Unified Proof Bundle generated:");
    println!("  Storage proofs: {}", unified_bundle.storage_proofs.len());
    println!("  Event proofs: {}", unified_bundle.event_proofs.len());
    println!("  Total witness blocks: {}", unified_bundle.blocks.len());

    // Verify the unified bundle
    // TODO: add real trusted parent ts and child header - this should use the verified F3 certificate
    let trust_anchors = TrustAnchors::accept_all();
    let event_filter = create_event_filter("NewTopDownMessage(bytes32,uint256)", "calib-subnet-1");

    let verification_results =
        verify_proof_bundle(&unified_bundle, &trust_anchors, Some(&event_filter))?;

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
