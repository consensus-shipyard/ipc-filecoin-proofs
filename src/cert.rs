use crate::client::types::CIDMap;
use serde::{Deserialize, Serialize};

// F3 Finality Certificate types (aligned with Forest implementation)
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FinalityCertificate {
    #[serde(rename = "GPBFTInstance")]
    pub instance: u64,
    #[serde(rename = "ECChain")]
    pub ec_chain: Vec<ECTipSet>,
    pub supplemental_data: SupplementalData,
    pub signers: Vec<u8>,   // BitField as Vec<u8>
    pub signature: Vec<u8>, // Vec<u8>
    pub power_table_delta: Vec<PowerTableDelta>,
}

// TipsetKey as a newtype wrapper (matching Forest's implementation)
// Forest uses SmallCidNonEmptyVec(NonEmpty<SmallCid>) for space optimization
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TipsetKey(pub Vec<CIDMap>); // Simplified version for RPC compatibility

// TipsetKey methods removed - were unused

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ECTipSet {
    pub key: TipsetKey,       // TipsetKey as newtype wrapper
    pub epoch: i64,           // ChainEpoch
    pub power_table: CIDMap,  // Cid (simplified)
    pub commitments: Vec<u8>, // Vec<u8>
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct SupplementalData {
    pub commitments: Vec<u8>, // Vec<u8>
    pub power_table: CIDMap,  // Cid (simplified)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct PowerTableDelta {
    #[serde(rename = "ParticipantID")]
    pub participant_id: u64, // ActorID
    pub power_delta: String, // BigInt as string
    pub signing_key: String, // Vec<u8> as base64 string
}

impl FinalityCertificate {
    /// Check if certificate is valid for an epoch (placeholder implementation)
    pub fn is_valid_for_epoch(&self, epoch: i64) -> bool {
        // TODO: Implement proper validation against the EC chain
        // For now, check if epoch is within the EC chain range
        if self.ec_chain.is_empty() {
            return false;
        }

        // Check if epoch is within the range of the EC chain
        let min_epoch = self.ec_chain.first().map(|t| t.epoch).unwrap_or(0);
        let max_epoch = self.ec_chain.last().map(|t| t.epoch).unwrap_or(0);

        epoch >= min_epoch && epoch <= max_epoch
    }

    // Removed unused is_valid_for_tipset method
}
