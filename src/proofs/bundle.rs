use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cid::Cid;
use serde::{Deserialize, Serialize};
use std::string::String;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessBlock {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventClaim {
    pub parent_epoch: i64,
    pub child_epoch: i64,
    pub parent_tipset_cids: Vec<String>, // ordered tipset key of H
    pub child_block_cid: String,         // block header CID of H+1
    pub message_cid: String,             // the message that produced the event
    pub exec_index: u64,                 // index of the execution in the parent tipset
    pub event_index: u64,                // index of the event in the receipt
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofBundle {
    pub claims: Vec<EventClaim>,
    pub blocks: Vec<WitnessBlock>, // deduped raw IPLD blocks needed for verification
}
