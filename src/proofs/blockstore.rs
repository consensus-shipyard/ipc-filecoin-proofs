use std::collections::BTreeSet;
use std::string::String;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cid::Cid;

use fvm_ipld_blockstore::Blockstore;

use crate::client::LotusClient;

/// RPC-backed read-only blockstore
pub(crate) struct RpcBlockstore<'a> {
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
        unreachable!()
    }

    fn has(&self, k: &Cid) -> Result<bool> {
        Ok(self.get(k)?.is_some())
    }
}

/// Recording wrapper (which CIDs did AMT traversal touched)
pub(crate) struct RecordingBlockStore<'a, B: Blockstore> {
    inner: &'a B,
    seen: parking_lot::Mutex<BTreeSet<Cid>>,
}

impl<'a, B: Blockstore> RecordingBlockStore<'a, B> {
    pub fn new(inner: &'a B) -> Self {
        Self {
            inner,
            seen: Default::default(),
        }
    }

    pub fn take_seen(&self) -> Vec<Cid> {
        self.seen.lock().iter().cloned().collect()
    }
}

impl<'a, B: Blockstore> Blockstore for RecordingBlockStore<'a, B> {
    fn get(&self, k: &Cid) -> Result<Option<Vec<u8>>> {
        self.seen.lock().insert(*k);
        self.inner.get(k)
    }

    fn put_keyed(&self, k: &Cid, v: &[u8]) -> Result<()> {
        self.inner.put_keyed(k, v)
    }

    fn has(&self, k: &Cid) -> Result<bool> {
        self.inner.has(k)
    }
}
