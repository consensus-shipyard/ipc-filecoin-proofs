use fvm_shared::event::ActorEvent;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

/// Represents an EVM log event with topics and data
#[derive(Debug, Clone)]
pub struct EvmLog {
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

/// Extract an EVM log from a Filecoin actor event
pub fn extract_evm_log(ev: &ActorEvent) -> Option<EvmLog> {
    let mut m = HashMap::<&str, &[u8]>::new();
    for e in &ev.entries {
        m.insert(e.key.as_str(), e.value.as_slice());
    }

    // Case A: explicit concatenated topics + data
    if let Some(topics_bytes) = m.get("topics").copied() {
        if topics_bytes.len() % 32 != 0 {
            return None;
        }
        let topics = topics_bytes
            .chunks(32)
            .map(|c| <[u8; 32]>::try_from(c).unwrap())
            .collect::<Vec<_>>();
        let data = m.get("data").cloned().unwrap_or_default().to_vec();
        return Some(EvmLog { topics, data });
    }

    // Case B: compact t1,t2,... plus d
    let mut topics = Vec::<[u8; 32]>::new();
    // t1 is the event signature hash
    let mut i = 1usize;
    loop {
        let key = match i {
            1 => "t1",
            2 => "t2",
            3 => "t3",
            4 => "t4",
            _ => break,
        };
        if let Some(val) = m.get(key).copied() {
            if val.len() != 32 {
                return None;
            }
            topics.push(<[u8; 32]>::try_from(val).ok()?);
            i += 1;
        } else {
            break;
        }
    }
    if topics.is_empty() {
        return None;
    }
    let data = m.get("d").cloned().unwrap_or_default().to_vec();
    Some(EvmLog { topics, data })
}

/// Hash an event signature string using Keccak256 (Solidity standard)
pub fn hash_event_signature(s: &str) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(s.as_bytes());
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Convert ASCII string to bytes32 (right-padded with zeros)
pub fn ascii_to_bytes32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b = s.as_bytes();
    let n = b.len().min(32);
    out[..n].copy_from_slice(&b[..n]);
    out
}

/// General Keccak256 hash function
pub fn keccak256(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(bytes.as_ref());
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Left-pad bytes to 32 bytes (for EVM storage values)
pub fn left_pad_32(v: &[u8]) -> [u8; 32] {
    if v.len() >= 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&v[v.len() - 32..]);
        return out;
    }
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(v);
    out
}
