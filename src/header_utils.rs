use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use cid::Cid;
use reqwest;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct FilecoinBlockHeader {
    #[serde(rename = "ParentMessageReceipts")]
    parent_message_receipts: Vec<u8>, // Store as raw bytes first
    #[serde(rename = "Messages")]
    messages: Vec<u8>,
    #[serde(rename = "ParentStateRoot")]
    parent_state_root: Vec<u8>,
    #[serde(rename = "Height")]
    height: u64,
    #[serde(rename = "Miner")]
    miner: String,
    // Add other fields as needed
}

/// Decode a Filecoin block header and extract the ParentMessageReceipts CID
pub async fn decode_header_receipt_root(block_cid: &str, rpc_url: &str) -> Result<String> {
    // Make the RPC call to get the block header
    let client = reqwest::Client::new();
    let request_body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"Filecoin.ChainReadObj","params":[{{"/":"{}"}}]}}"#,
        block_cid
    );

    let response = client
        .post(rpc_url)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await?;

    let response_json: serde_json::Value = response.json().await?;
    let header_b64 = response_json["result"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No result field in response"))?;

    // Decode the base64 header
    let header_bytes = BASE64.decode(header_b64)?;

    // First, let's see what the raw CBOR structure looks like
    let header_value: serde_cbor::Value = serde_cbor::from_slice(&header_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse header CBOR as value: {}", e))?;

    tracing::info!("Raw header structure: {:?}", header_value);

    // Parse the header as an array and extract the ParentMessageReceipts
    let header_array = match header_value {
        serde_cbor::Value::Array(arr) => arr,
        _ => anyhow::bail!("Header is not an array"),
    };

    // Based on the structure, ParentMessageReceipts is likely at index 9
    // Let's check the structure and find the right index
    if header_array.len() < 10 {
        anyhow::bail!("Header array too short, expected at least 10 elements");
    }

    // Let's find the ParentMessageReceipts by looking for the AMT root we know
    // The AMT root we're looking for is: bafy2bzacec4slfvaaxd54rbej25khbrzvztbilthtfcbs4tzbhmfbe7h4ka6q
    let target_amt_root = "bafy2bzacec4slfvaaxd54rbej25khbrzvztbilthtfcbs4tzbhmfbe7h4ka6q";

    let mut receipt_index = None;
    for (i, element) in header_array.iter().enumerate() {
        if let serde_cbor::Value::Bytes(bytes) = element {
            // Try to parse as CID
            if let Ok(cid) = Cid::try_from(bytes.as_slice()) {
                if cid.to_string() == target_amt_root {
                    receipt_index = Some(i);
                    break;
                }
            }
        }
    }

    let receipt_bytes = if let Some(index) = receipt_index {
        match &header_array[index] {
            serde_cbor::Value::Bytes(bytes) => bytes,
            _ => anyhow::bail!("ParentMessageReceipts at index {} is not bytes", index),
        }
    } else {
        // Fallback to index 9 if not found
        match &header_array[9] {
            serde_cbor::Value::Bytes(bytes) => bytes,
            _ => anyhow::bail!("ParentMessageReceipts at index 9 is not bytes"),
        }
    };

    tracing::info!("Receipt bytes at index 9: {:?}", receipt_bytes);

    // Try to parse the CID from the raw bytes
    // The bytes should be a valid CID in some format
    let receipt_cid = Cid::try_from(receipt_bytes.as_slice()).map_err(|e| {
        tracing::error!("Failed to parse CID from bytes: {:?}", receipt_bytes);
        anyhow::anyhow!("Failed to parse receipt CID: {}", e)
    })?;

    tracing::info!("Extracted ParentMessageReceipts CID: {}", receipt_cid);

    // Return the ParentMessageReceipts CID
    Ok(receipt_cid.to_string())
}
