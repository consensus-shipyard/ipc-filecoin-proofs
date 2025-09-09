use anyhow::Result;
use cid::Cid;
use fvm_ipld_blockstore::Blockstore;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use super::blockstore::RpcBlockstore;

/// Cached wrapper around RpcBlockstore that eliminates duplicate RPC calls
/// This cache is shared across all proof generation to maximize efficiency
pub struct CachedBlockstore<'a> {
    inner: RpcBlockstore<'a>,
    cache: Rc<RefCell<HashMap<Cid, Vec<u8>>>>,
}

impl<'a> CachedBlockstore<'a> {
    /// Create a new cached blockstore with its own cache
    pub fn new(inner: RpcBlockstore<'a>) -> Self {
        Self {
            inner,
            cache: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    /// Create a cached blockstore that shares a cache with other instances
    pub fn with_shared_cache(
        inner: RpcBlockstore<'a>,
        cache: Rc<RefCell<HashMap<Cid, Vec<u8>>>>,
    ) -> Self {
        Self { inner, cache }
    }

    /// Get the shared cache for reuse in other blockstores
    pub fn shared_cache(&self) -> Rc<RefCell<HashMap<Cid, Vec<u8>>>> {
        self.cache.clone()
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.borrow();
        let entries = cache.len();
        let bytes: usize = cache.values().map(|v| v.len()).sum();
        (entries, bytes)
    }

    /// Clear the cache to free memory
    pub fn clear_cache(&self) {
        self.cache.borrow_mut().clear();
    }
}

impl<'a> Blockstore for CachedBlockstore<'a> {
    fn get(&self, k: &Cid) -> Result<Option<Vec<u8>>> {
        // Check cache first
        if let Some(data) = self.cache.borrow().get(k) {
            // Cache hit - no RPC needed!
            return Ok(Some(data.clone()));
        }

        // Cache miss - fetch from RPC
        let data = self.inner.get(k)?;

        // Store in cache for future use
        if let Some(ref d) = data {
            self.cache.borrow_mut().insert(*k, d.clone());
        }

        Ok(data)
    }

    fn put_keyed(&self, k: &Cid, block: &[u8]) -> Result<()> {
        // Also cache puts for consistency
        self.cache.borrow_mut().insert(*k, block.to_vec());
        self.inner.put_keyed(k, block)
    }

    fn has(&self, k: &Cid) -> Result<bool> {
        // Check cache first
        if self.cache.borrow().contains_key(k) {
            return Ok(true);
        }
        self.inner.has(k)
    }
}
