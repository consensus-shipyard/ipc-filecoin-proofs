use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cid::Cid;
use serde::{Deserialize, Serialize};
use std::string::String;

use crate::proofs::{events::bundle::EventProof, storage::bundle::StorageProof};

/// A single IPLD block with its CID and raw data, used as proof witness
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBlock {
    pub cid: Cid,
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub data: Vec<u8>, // raw DAG-CBOR block bytes
}

fn serialize_base64<S>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let encoded = B64.encode(data);
    serializer.serialize_str(&encoded)
}

fn deserialize_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)
}

/// Unified proof bundle containing both storage and event proofs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnifiedProofBundle {
    /// Storage proofs for specific storage slots
    pub storage_proofs: Vec<StorageProof>,
    /// Event proofs for specific events
    pub event_proofs: Vec<EventProof>,
    /// Witness blocks needed to verify all proofs (deduplicated)
    pub blocks: Vec<ProofBlock>,
}

/// Result of verifying a unified proof bundle
#[derive(Debug)]
pub struct UnifiedVerificationResult {
    /// Results for each storage proof (in order)
    pub storage_results: Vec<bool>,
    /// Results for each event proof (in order)
    pub event_results: Vec<bool>,
}

impl UnifiedVerificationResult {
    /// Check if all proofs are valid
    pub fn all_valid(&self) -> bool {
        self.storage_results.iter().all(|&v| v) && self.event_results.iter().all(|&v| v)
    }
}
