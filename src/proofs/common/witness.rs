use anyhow::{anyhow, Result};
use cid::Cid;
use fvm_ipld_blockstore::Blockstore;
use std::collections::BTreeSet;

use crate::proofs::common::{blockstore::RecordingBlockStore, bundle::ProofBlock};

/// Utility for collecting and materializing witness blocks needed for proof verification
pub struct WitnessCollector<'a, BS: Blockstore> {
    needed: BTreeSet<Cid>,
    blockstore: &'a BS,
}

impl<'a, BS: Blockstore> WitnessCollector<'a, BS> {
    /// Create a new witness collector with the given blockstore
    pub fn new(blockstore: &'a BS) -> Self {
        Self {
            needed: BTreeSet::new(),
            blockstore,
        }
    }

    /// Add a single CID to the witness set
    pub fn add_cid(&mut self, cid: Cid) {
        self.needed.insert(cid);
    }

    /// Collect all CIDs from a recording blockstore and add them to the witness set
    pub fn collect_from_recording(&mut self, recorder: &RecordingBlockStore<BS>) {
        for cid in recorder.take_seen() {
            self.needed.insert(cid);
        }
    }

    /// Collect CIDs from multiple recording blockstores
    pub fn collect_from_recordings(&mut self, recorders: Vec<&RecordingBlockStore<BS>>) {
        for recorder in recorders {
            self.collect_from_recording(recorder);
        }
    }

    /// Materialize all collected CIDs into ProofBlocks by fetching their data
    pub fn materialize(self) -> Result<Vec<ProofBlock>> {
        let mut blocks = Vec::with_capacity(self.needed.len());

        for cid in self.needed {
            let raw = self
                .blockstore
                .get(&cid)?
                .ok_or_else(|| anyhow!("missing block {}", cid))?;

            blocks.push(ProofBlock { cid, data: raw });
        }

        Ok(blocks)
    }
}

/// Helper to parse a CID from string with context
pub fn parse_cid(cid_str: &str, context: &str) -> Result<Cid> {
    Cid::try_from(cid_str)
        .map_err(|e| anyhow!("Failed to parse {} CID '{}': {}", context, cid_str, e))
}

/// Helper to parse multiple CIDs from strings
pub fn parse_cids(cid_strs: &[String], context: &str) -> Result<Vec<Cid>> {
    cid_strs
        .iter()
        .enumerate()
        .map(|(i, s)| parse_cid(s, &format!("{} [{}]", context, i)))
        .collect()
}
