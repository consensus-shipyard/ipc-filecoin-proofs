use anyhow::{anyhow, Result};
use cid::Cid;
use fvm_ipld_amt::Amtv0;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::CborStore;
use multihash_codetable::Code;
use serde_ipld_dagcbor;

use std::collections::HashSet;

use crate::client::{LotusClient, RpcBlockstore};
use crate::proofs::common::decode::HeaderLite;
use crate::types::ApiTipset;

/// Reconstruct the execution order from blockstore headers (for offline verification)
pub fn reconstruct_execution_order<S>(bs: &S, parent_hdr_cids: &[Cid]) -> Result<Vec<Cid>>
where
    S: Blockstore,
{
    let mut txmeta_cids = Vec::with_capacity(parent_hdr_cids.len());
    for pcid in parent_hdr_cids {
        let raw = bs
            .get(pcid)?
            .ok_or_else(|| anyhow!("missing parent header {}", pcid))?;
        let hdr: HeaderLite = serde_ipld_dagcbor::from_slice(&raw)?;
        txmeta_cids.push(hdr.messages);
    }

    collect_exec_list(bs, txmeta_cids, true)
}

/// Build the execution order from a tipset (for online generation)
pub async fn build_execution_order(client: &LotusClient, parent: &ApiTipset) -> Result<Vec<Cid>> {
    // Use your existing RpcBlockstore wrapper
    let net = RpcBlockstore::new(client);

    // Parent blocks are already in canonical order.
    let txmeta_cids = parent
        .blocks
        .iter()
        .map(|hdr| Cid::try_from(hdr.messages.cid.as_str()))
        .collect::<Result<Vec<_>, _>>()?;

    collect_exec_list(&net, txmeta_cids, false)
}

/// Internal: Collect the execution list from the blockstore.
fn collect_exec_list<S, I>(bs: &S, txmeta_cids: I, verify_txmeta: bool) -> Result<Vec<Cid>>
where
    S: Blockstore,
    I: IntoIterator<Item = Cid>,
{
    let mut out = Vec::<Cid>::new();
    let mut seen = HashSet::<Cid>::new();

    for tx_cid in txmeta_cids {
        // Load TxMeta (CBOR 2-tuple of (bls_root, secp_root))
        let tx_raw = bs
            .get(&tx_cid)?
            .ok_or_else(|| anyhow!("missing TxMeta {}", tx_cid))?;
        let (bls_root, secp_root): (Cid, Cid) = serde_ipld_dagcbor::from_slice(&tx_raw)?;

        // Optional trustless verification
        if verify_txmeta {
            let recomputed = bs.put_cbor(&(bls_root, secp_root), Code::Blake2b256)?;
            if recomputed != tx_cid {
                return Err(anyhow!(
                    "TxMeta mismatch: header {} vs recomputed {}",
                    tx_cid,
                    recomputed
                ));
            }
        }

        // Walk AMTs; dedupe while preserving first-seen order
        let bls_amt = Amtv0::<Cid, _>::load(&bls_root, bs)?;
        bls_amt.for_each(|_, c| {
            if seen.insert(*c) {
                out.push(*c);
            }
            Ok(())
        })?;

        let secp_amt = Amtv0::<Cid, _>::load(&secp_root, bs)?;
        secp_amt.for_each(|_, c| {
            if seen.insert(*c) {
                out.push(*c);
            }
            Ok(())
        })?;
    }

    Ok(out)
}
