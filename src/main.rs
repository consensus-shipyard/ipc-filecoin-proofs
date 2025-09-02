// Copyright 2022-2024 Protocol Labs
// SPDX-License-Identifier: MIT
mod cert;
mod client;
mod proofs;
mod types;

use crate::client::LotusClient;
use anyhow::Ok;
use cid::Cid;

use serde_json::json;
use types::ApiTipset;
use url::Url;

use crate::proofs::generator::generate_bundle;
use crate::proofs::verifier::{make_check_event_evm, verify_bundle};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = LotusClient::new(
        Url::parse("https://api.calibration.node.glif.io/rpc/v1").unwrap(),
        None,
    );

    let height = 2982844;
    let _last_top_down_nonce = 6;

    let parent: ApiTipset = client
        .request("Filecoin.ChainGetTipSetByHeight", json!([height, null]))
        .await?;
    let child: ApiTipset = client
        .request("Filecoin.ChainGetTipSetByHeight", json!([height + 1, null]))
        .await?;

    let proof_bundle = generate_bundle(
        &client,
        &parent,
        &child,
        "NewTopDownMessage(bytes32,uint256)",
        "calib-subnet-1",
    )
    .await?;

    // TODO: add real trusted parent ts and child header - this should use the verified F3 certificate
    let is_trusted_parent_ts = |_: i64, _: &[Cid]| true;
    let is_trusted_child_header = |_: i64, _: &Cid| true;

    let check_event = make_check_event_evm("NewTopDownMessage(bytes32,uint256)", "calib-subnet-1");

    let res = verify_bundle(
        &proof_bundle,
        &is_trusted_parent_ts,
        &is_trusted_child_header,
        Some(&check_event),
    )?;

    println!("Verification Result: {:?}", res);

    Ok(())
}
