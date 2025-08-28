use crate::client::LotusClient;
use serde_json::json;
use url::Url;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = LotusClient::new(
        Url::parse("https://api.calibration.node.glif.io/rpc/v1").unwrap(),
        None,
    );

    // Get current chain head
    println!("Getting current chain head...");
    let chain_head = client.chain_head().await?;
    println!("Chain head CIDs:");
    for (i, cid) in chain_head.cids.iter().enumerate() {
        println!("  {}: {}", i, cid.cid);
    }

    // Get a few tipsets from different heights
    for height in [2968600, 2968500, 2968400] {
        println!("\nGetting tipset at height {}...", height);
        match client.get_tipset_by_height(height, None).await {
            Ok(tipset) => {
                println!("  Height {} CIDs:", height);
                for (i, cid) in tipset.cids.iter().enumerate() {
                    println!("    {}: {}", i, cid.cid);
                }
            }
            Err(e) => {
                println!("  Error getting height {}: {}", height, e);
            }
        }
    }

    Ok(())
}
