use fvm_shared::event::ActorEvent;
use std::collections::HashMap;
use tiny_keccak::{Hasher, Keccak};

#[derive(Debug, Clone)]
pub struct EvmLog {
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

pub fn evm_log_from_actor_event(ev: &ActorEvent) -> Option<EvmLog> {
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

pub fn keccak_event_sig(s: &str) -> [u8; 32] {
    let mut h = Keccak::v256();
    let mut out = [0u8; 32];
    h.update(s.as_bytes());
    h.finalize(&mut out);
    out
}

pub fn bytes32_from_ascii(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b = s.as_bytes();
    let n = b.len().min(32);
    out[..n].copy_from_slice(&b[..n]);
    out
}
