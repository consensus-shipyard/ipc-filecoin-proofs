use anyhow::{anyhow, Result};
use fvm_shared::address::Address;
use serde_json::json;

use crate::client::LotusClient;

/// Resolve an Ethereum address (0x...) to a Filecoin Actor ID
pub async fn resolve_eth_address_to_actor_id(client: &LotusClient, eth_addr: &str) -> Result<u64> {
    // Normalize the address (remove 0x prefix if present)
    let eth_addr = eth_addr.trim_start_matches("0x");

    // Validate it's a valid hex string of correct length
    let bytes =
        hex::decode(eth_addr).map_err(|e| anyhow!("Invalid hex in Ethereum address: {}", e))?;
    if bytes.len() != 20 {
        return Err(anyhow!(
            "Invalid Ethereum address length: expected 20 bytes, got {}",
            bytes.len()
        ));
    }

    // Format as 0x-prefixed hex string for RPC call
    let eth_addr_str = format!("0x{}", eth_addr);

    // Call Filecoin.EthAddressToFilecoinAddress to get the f4 address
    let fil_addr: String = client
        .request(
            "Filecoin.EthAddressToFilecoinAddress",
            json!([eth_addr_str]),
        )
        .await
        .map_err(|e| {
            anyhow!(
                "Failed to convert Ethereum address to Filecoin address: {}",
                e
            )
        })?;

    // Parse the Filecoin address
    let address = parse_address(&fil_addr)?;

    // For EVM addresses (f410...), we need to look up the ID address
    // Check if this is a delegated address
    if address.protocol() == fvm_shared::address::Protocol::Delegated {
        // Look up the ID address using StateLookupID
        let id_address: String = client
            .request("Filecoin.StateLookupID", json!([fil_addr, null]))
            .await
            .map_err(|e| anyhow!("Failed to lookup ID address: {}", e))?;

        // Parse and extract the ID
        let id_addr = parse_address(&id_address)?;
        id_addr
            .id()
            .map_err(|e| anyhow!("Failed to extract actor ID from ID address: {}", e))
    } else {
        // Try to extract ID directly
        address
            .id()
            .map_err(|e| anyhow!("Failed to extract actor ID directly: {}", e))
    }
}

// Helper function to parse Filecoin addresses (handles both mainnet and testnet)
fn parse_address(s: &str) -> Result<Address> {
    use std::str::FromStr;

    // Handle both testnet (t) and mainnet (f) prefixes
    let normalized = if s.starts_with('t') {
        // Convert testnet prefix to mainnet for parsing
        format!("f{}", &s[1..])
    } else {
        s.to_string()
    };

    Address::from_str(&normalized).map_err(|e| anyhow!("Failed to parse address '{}': {}", s, e))
}
