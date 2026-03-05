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
    create_event_filter, generate_proof_bundle, resolve_eth_address_to_actor_id,
    verify_proof_bundle, EventProofSpec, StorageProofSpec, TrustPolicy,
};
use crate::proofs::common::evm::keccak256;
use crate::proofs::storage::utils::compute_mapping_slot;

#[derive(serde::Deserialize)]
struct ChainHead {
    #[serde(rename = "Height")]
    height: i64,
}

const SUBNETS_MAPPING_SLOT: u64 = 22;
const SUBNET_TOPDOWN_NONCE_OFFSET: u64 = 3;
const NEXT_CONFIG_NUMBER_ABSOLUTE_SLOT: u64 = 20;

fn parse_eth_address(addr: &str) -> anyhow::Result<[u8; 20]> {
    let hex = addr
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("expected 0x-prefixed ETH address: {}", addr))?;
    if hex.len() != 40 {
        return Err(anyhow::anyhow!("expected 20-byte ETH address: {}", addr));
    }
    let mut out = [0u8; 20];
    hex::decode_to_slice(hex, &mut out)?;
    Ok(out)
}

fn parse_subnet_path(subnet_id: &str) -> anyhow::Result<(u64, Vec<String>)> {
    let parts: Vec<&str> = subnet_id.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() || !parts[0].starts_with('r') {
        return Err(anyhow::anyhow!("invalid subnet id: {}", subnet_id));
    }
    let root = parts[0][1..].parse::<u64>()?;
    let route = parts.iter().skip(1).map(|s| s.to_string()).collect::<Vec<_>>();
    Ok((root, route))
}

fn abi_encode_subnet_id(root: u64, route: &[[u8; 20]]) -> Vec<u8> {
    // abi.encode((uint64,address[])) as top-level args: head(root, offset=0x40) + tail(route)
    let mut out = Vec::with_capacity(64 + 32 + route.len() * 32);
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&root.to_be_bytes());
    out.extend_from_slice(&word);

    let mut offset = [0u8; 32];
    offset[31] = 0x40;
    out.extend_from_slice(&offset);

    let mut len_word = [0u8; 32];
    len_word[24..].copy_from_slice(&(route.len() as u64).to_be_bytes());
    out.extend_from_slice(&len_word);

    for addr in route {
        let mut addr_word = [0u8; 32];
        addr_word[12..].copy_from_slice(addr);
        out.extend_from_slice(&addr_word);
    }
    out
}

fn add_u64_to_word(mut word: [u8; 32], add: u64) -> [u8; 32] {
    let mut carry = add;
    let mut i = 31usize;
    while carry > 0 {
        let sum = word[i] as u64 + (carry & 0xff);
        word[i] = (sum & 0xff) as u8;
        carry = (carry >> 8) + (sum >> 8);
        if i == 0 {
            break;
        }
        i -= 1;
    }
    word
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    const CALIBRATION_RPC_URL: &str = "https://api.calibration.node.glif.io/rpc/v1";
    const SUBNET_ID: &str = "/r314159/t410fqznpcmrs4vzpafzs3q5zhwsl4rm6rqdzps62lqq";
    const GATEWAY_ADDRESS: &str = "0xC6CccA04981FA1380fED9014b9A79c3f2a5B7C46";
    const GATEWAY_ACTOR_ID: u64 = 181949;

    let client = LotusClient::new(Url::parse(CALIBRATION_RPC_URL).unwrap(), None);

    // Use a recent block height (head - 100) so required blocks are retrievable.
    let head: ChainHead = client.request("Filecoin.ChainHead", json!([])).await?;
    let height = head.height - 100;
    let parent: ApiTipset = client
        .request("Filecoin.ChainGetTipSetByHeight", json!([height, null]))
        .await?;
    let child: ApiTipset = client
        .request("Filecoin.ChainGetTipSetByHeight", json!([height + 1, null]))
        .await?;

    // Contract configuration - you can use either:
    // 1. An Ethereum address that will be resolved to an actor ID
    // 2. A known actor ID directly

    // Option 1: Using Ethereum address (will be resolved via RPC)
    let contract_address = GATEWAY_ADDRESS;

    println!("\n Contract Configuration:");
    println!("  Ethereum address: {}", contract_address);

    // Resolve Ethereum address to Actor ID
    let actor_id = GATEWAY_ACTOR_ID;
    let resolved_actor_id = resolve_eth_address_to_actor_id(&client, contract_address).await?;
    println!("  Resolved to Actor ID: {}", resolved_actor_id);
    println!("  Configured Actor ID: {}", actor_id);

    let (root_id, route_addrs) = parse_subnet_path(SUBNET_ID)?;
    let mut route_eth = Vec::<[u8; 20]>::new();
    let mut route_eth_str = Vec::<String>::new();
    for addr in route_addrs {
        let eth_addr: String = client
            .request("Filecoin.FilecoinAddressToEthAddress", json!([addr]))
            .await?;
        route_eth.push(parse_eth_address(&eth_addr)?);
        route_eth_str.push(eth_addr);
    }
    let subnet_topic_1 = route_eth_str
        .last()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("subnet route is empty"))?;
    let subnet_hash = keccak256(abi_encode_subnet_id(root_id, &route_eth));
    let subnet_base_slot = compute_mapping_slot(subnet_hash, SUBNETS_MAPPING_SLOT);
    let topdown_nonce_slot = add_u64_to_word(subnet_base_slot, SUBNET_TOPDOWN_NONCE_OFFSET);

    // IPC-style storage specs: topDownNonce + nextConfigurationNumber.
    let storage_specs: Vec<StorageProofSpec> = vec![
        StorageProofSpec {
            actor_id,
            slot: ethereum_types::H256(topdown_nonce_slot),
        },
        StorageProofSpec {
            actor_id,
            slot: ethereum_types::H256::from_low_u64_be(NEXT_CONFIG_NUMBER_ABSOLUTE_SLOT),
        },
    ];

    // IPC-style event specs: topdown + power change.
    let event_specs = vec![
        EventProofSpec {
            event_signature:
                "NewTopDownMessage(address,(uint8,uint64,uint64,uint256,((uint64,address[]),(uint8,bytes)),((uint64,address[]),(uint8,bytes)),bytes),bytes32)".to_string(),
            topic_1: subnet_topic_1,
            actor_id_filter: Some(actor_id),
        },
        EventProofSpec {
            event_signature: "NewPowerChangeRequest(uint8,address,bytes,uint64)".to_string(),
            topic_1: String::new(),
            actor_id_filter: Some(actor_id),
        },
    ];
    let topdown_topic_1 = event_specs[0].topic_1.clone();

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

    // For verification, we can still create a filter for specific event types if needed
    let topdown_event_filter = create_event_filter(
        "NewTopDownMessage(address,(uint8,uint64,uint64,uint256,((uint64,address[]),(uint8,bytes)),((uint64,address[]),(uint8,bytes)),bytes),bytes32)",
        topdown_topic_1.as_str(),
    );

    let verification_results =
        verify_proof_bundle(&unified_bundle, &trust_policy, Some(&topdown_event_filter))?;

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
