use std::collections::BTreeSet;

use anyhow::Result;
use cid::Cid;
use fvm_ipld_blockstore::Blockstore;

/// Recording wrapper that tracks which CIDs were accessed during traversal
pub struct RecordingBlockStore<'a, B: Blockstore> {
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
