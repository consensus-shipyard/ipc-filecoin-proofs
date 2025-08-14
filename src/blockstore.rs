// Copyright 2022-2024 Protocol Labs
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use cid::Cid;
use fvm_ipld_blockstore::Blockstore;
use multihash_codetable::MultihashDigest;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::client::LotusClient;
use crate::types::ProofNode;

/// Recording blockstore that traces all accessed nodes
pub struct RecordingBlockstore {
    client: LotusClient,
    cache: Mutex<HashMap<Cid, Vec<u8>>>,
    trace: Mutex<Vec<ProofNode>>,
}

impl RecordingBlockstore {
    pub fn new(client: LotusClient) -> Self {
        Self {
            client,
            cache: Mutex::new(HashMap::new()),
            trace: Mutex::new(Vec::new()),
        }
    }

    /// Get a clone of the trace of accessed nodes
    pub fn trace(&self) -> Vec<ProofNode> {
        self.trace.lock().unwrap().clone()
    }

    /// Verify that raw bytes hash to the expected CID
    fn verify_cid(raw: &[u8], expected: &Cid) -> Result<()> {
        let computed = Cid::new_v1(
            fvm_ipld_encoding::DAG_CBOR,
            multihash_codetable::Code::Blake2b256.digest(raw),
        );
        if computed != *expected {
            anyhow::bail!(
                "CID mismatch: computed {} != expected {}",
                computed,
                expected
            );
        }
        Ok(())
    }
}

impl Blockstore for RecordingBlockstore {
    fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>> {
        // Check cache first
        if let Some(data) = self.cache.lock().unwrap().get(cid).cloned() {
            return Ok(Some(data));
        }

        // Fetch from Lotus
        let raw = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { self.client.chain_read_obj(*cid).await })
        })
        .context(format!("Failed to fetch CID {}", cid))?;

        let raw_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &raw)
            .context("Failed to decode base64")?;

        // Verify the CID matches
        Self::verify_cid(&raw_bytes, cid)?;

        // Cache it
        self.cache.lock().unwrap().insert(*cid, raw_bytes.clone());

        // Add to trace
        self.trace.lock().unwrap().push(ProofNode {
            cid: *cid,
            raw: raw_bytes.clone(),
        });

        Ok(Some(raw_bytes))
    }

    fn put_keyed(&self, cid: &Cid, data: &[u8]) -> Result<()> {
        // Verify the CID matches
        Self::verify_cid(data, cid)?;

        // Cache it
        self.cache.lock().unwrap().insert(*cid, data.to_vec());
        Ok(())
    }

    fn has(&self, cid: &Cid) -> Result<bool> {
        Ok(self.cache.lock().unwrap().contains_key(cid))
    }
}

/// Memory blockstore for verification
pub struct MemoryBlockstore {
    data: HashMap<Cid, Vec<u8>>,
}

impl MemoryBlockstore {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

impl Blockstore for MemoryBlockstore {
    fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>> {
        Ok(self.data.get(cid).cloned())
    }

    fn put_keyed(&self, cid: &Cid, data: &[u8]) -> Result<()> {
        // Verify the CID matches
        let computed = Cid::new_v1(
            fvm_ipld_encoding::DAG_CBOR,
            multihash_codetable::Code::Blake2b256.digest(data),
        );
        if computed != *cid {
            anyhow::bail!(
                "CID mismatch in put_keyed: computed {} != expected {}",
                computed,
                cid
            );
        }

        // Cache it
        // NOTE: MemoryBlockstore is not Sync/Send; if used concurrently, wrap in Mutex outside.
        let ptr = self as *const Self as *mut Self;
        unsafe { (*ptr).data.insert(*cid, data.to_vec()) };
        Ok(())
    }

    fn has(&self, cid: &Cid) -> Result<bool> {
        Ok(self.data.contains_key(cid))
    }
}
