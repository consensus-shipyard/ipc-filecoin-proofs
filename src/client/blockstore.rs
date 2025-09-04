use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cid::Cid;
use fvm_ipld_blockstore::Blockstore;
use std::string::String;

use super::LotusClient;

/// RPC-backed read-only blockstore for fetching IPLD blocks from a Lotus node
pub struct RpcBlockstore<'a> {
    client: &'a LotusClient,
}

impl<'a> RpcBlockstore<'a> {
    pub fn new(client: &'a LotusClient) -> Self {
        Self { client }
    }
}

impl<'a> Blockstore for RpcBlockstore<'a> {
    fn get(&self, k: &Cid) -> Result<Option<Vec<u8>>> {
        // Filecoin.ChainReadObj returns base64 raw block bytes
        let arg = serde_json::json!([{"/": k.to_string()}]);
        let b64: String =
            futures::executor::block_on(self.client.request("Filecoin.ChainReadObj", arg))?;
        let raw = B64.decode(b64)?;
        Ok(Some(raw))
    }

    fn put_keyed(&self, _: &Cid, _: &[u8]) -> Result<()> {
        unreachable!("RpcBlockstore is read-only")
    }

    fn has(&self, k: &Cid) -> Result<bool> {
        Ok(self.get(k)?.is_some())
    }
}
