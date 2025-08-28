// Copyright 2022-2024 Protocol Labs
// SPDX-License-Identifier: MIT

use anyhow::Result;
use proofs::{
    header_utils,
    receipt_proof::{self},
    storage_proof,
    types::ReceiptSubmission,
};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let command = &args[1];
    let args = args.clone();

    match command.as_str() {
        "receipt" => handle_receipt(args).await,
        "storage" => handle_storage(args).await,
        "verify-receipt" => {
            handle_verify_receipt(args).await?;
            Ok(())
        }
        "test-receipt" => {
            handle_test_receipt(args).await?;
            Ok(())
        }
        "test-header-decode" => {
            test_header_decode(args).await?;
            Ok(())
        }
        _ => {
            print_usage();
            Ok(())
        }
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  cargo run -- receipt <rpc_url> <height> <message_cid>");
    println!("  cargo run -- verify-receipt <rpc_url> <proof_file>");
    println!("  cargo run -- test-receipt <rpc_url> <height> <message_cid>");
    println!("  cargo run -- test-header-decode <rpc_url> <block_cid>");
}

async fn handle_receipt(args: Vec<String>) -> Result<()> {
    if args.len() < 4 {
        eprintln!(
            "Usage: {} receipt <rpc_url> <height> <message_cid>",
            args[0]
        );
        return Ok(());
    }

    let rpc_url = &args[2];
    let height: i64 = args[3].parse()?;
    let message_cid = &args[4];

    let submission =
        receipt_proof::build_receipt_submission(rpc_url, height, message_cid.parse()?).await?;
    println!("{}", serde_json::to_string_pretty(&submission)?);
    Ok(())
}

async fn handle_storage(args: Vec<String>) -> Result<()> {
    if args.len() < 5 {
        eprintln!(
            "Usage: {} storage <rpc_url> <height> <contract_address> <storage_key>",
            args[0]
        );
        return Ok(());
    }

    let rpc_url = &args[2];
    let height: i64 = args[3].parse()?;
    let contract_address = &args[4];
    let storage_key = &args[5];

    // Convert storage_key to bytes
    let key_bytes = hex::decode(storage_key.strip_prefix("0x").unwrap_or(storage_key))?;
    if key_bytes.len() != 32 {
        anyhow::bail!("Storage key must be exactly 32 bytes");
    }
    let mut key32 = [0u8; 32];
    key32.copy_from_slice(&key_bytes);

    let submission =
        storage_proof::build_storage_submission(rpc_url, height, contract_address, key32).await?;
    println!("{}", serde_json::to_string_pretty(&submission)?);
    Ok(())
}

async fn handle_verify_receipt(args: Vec<String>) -> Result<()> {
    if args.len() < 4 {
        eprintln!(
            "Usage: {} verify-receipt <rpc_url> <submission_json_file>",
            args[0]
        );
        return Ok(());
    }

    let rpc_url = &args[2];
    let json_file = &args[3];
    let json_data = std::fs::read_to_string(json_file)?;
    let submission = serde_json::from_str(&json_data)?;

    tracing::info!("Verifying receipt proof from file...");
    receipt_proof::verify_receipt_submission_mock(&submission, rpc_url).await?;

    tracing::info!("✅ Receipt proof verified successfully!");
    Ok(())
}

async fn handle_test_receipt(args: Vec<String>) -> Result<()> {
    if args.len() < 4 {
        eprintln!(
            "Usage: {} test-receipt <rpc_url> <height> <message_cid>",
            args[0]
        );
        return Ok(());
    }

    let rpc_url = &args[2];
    let height: i64 = args[3].parse()?;
    let message_cid = &args[4];

    tracing::info!("Testing receipt proof for height: {}", height);
    receipt_proof::test_receipt_submission(rpc_url, height, message_cid.parse()?).await?;
    tracing::info!("✅ Receipt proof test completed!");
    Ok(())
}

async fn test_header_decode(args: Vec<String>) -> Result<()> {
    if args.len() < 4 {
        eprintln!(
            "Usage: {} test-header-decode <rpc_url> <block_cid>",
            args[0]
        );
        return Ok(());
    }

    let rpc_url = &args[2];
    let block_cid = &args[3];

    tracing::info!("Testing header decode for block: {}", block_cid);
    let receipt_root = header_utils::decode_header_receipt_root(block_cid, rpc_url).await?;
    tracing::info!("✅ Header receipt root: {}", receipt_root);
    Ok(())
}
