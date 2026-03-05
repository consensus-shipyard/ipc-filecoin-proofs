use crate::proofs::common::evm::{ascii_to_bytes32, keccak256};
use ethereum_types::H256;

/// Compute a Solidity mapping slot using keccak( key(32) || slotIndex(32) )
pub fn compute_mapping_slot(key: [u8; 32], slot_index: u64) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&key);
    let mut slot_be = [0u8; 32];
    slot_be[24..].copy_from_slice(&slot_index.to_be_bytes());
    buf[32..].copy_from_slice(&slot_be);
    keccak256(buf)
}

/// Calculate the storage slot for subnets[bytes32 subnetId].topDownNonce
/// This is a convenience function for the specific use case of subnet mapping
pub fn calculate_storage_slot(subnet_ascii: &str, subnets_slot_index: u64) -> H256 {
    let key = ascii_to_bytes32(subnet_ascii);
    H256(compute_mapping_slot(key, subnets_slot_index))
}
