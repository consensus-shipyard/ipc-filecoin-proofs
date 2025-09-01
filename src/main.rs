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

use proofs::{generate_bundle_for_subnet, make_check_event_evm, verify_bundle_offline};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = LotusClient::new(
        Url::parse("https://api.calibration.node.glif.io/rpc/v1").unwrap(),
        None,
    );

    let H = 2980106;

    let parent: ApiTipset = client
        .request("Filecoin.ChainGetTipSetByHeight", json!([H, null]))
        .await?;
    let child: ApiTipset = client
        .request("Filecoin.ChainGetTipSetByHeight", json!([H + 1, null]))
        .await?;

    let proof_bundle = generate_bundle_for_subnet(
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

    let res = verify_bundle_offline(
        &proof_bundle,
        &is_trusted_parent_ts,
        &is_trusted_child_header,
        Some(&check_event),
    )?;

    println!("Verification Result: {:?}", res);

    Ok(())
}
