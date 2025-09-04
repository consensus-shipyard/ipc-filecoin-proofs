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

impl TipsetKey {
    /// Returns an iterator of CIDs in the tipset key
    pub fn iter(&self) -> impl Iterator<Item = &CIDMap> {
        self.0.iter()
    }

    /// Returns the number of CIDs in the tipset key
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the tipset key is empty (should never be true in practice)
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the first CID in the tipset key
    pub fn first(&self) -> Option<&CIDMap> {
        self.0.first()
    }

    /// Returns all CIDs as a slice
    pub fn as_slice(&self) -> &[CIDMap] {
        &self.0
    }

    /// Returns all CIDs as a reference to the vector
    pub fn cids(&self) -> &Vec<CIDMap> {
        &self.0
    }
}

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
use url::Url;

fn create_mock_finality_certificate() -> FinalityCertificate {
    FinalityCertificate {
        instance: 1,
        ec_chain: vec![ECTipSet {
            key: TipsetKey(vec![
                CIDMap::from("bafy2bzaceaesqcrmw5payqsgxqptjfmglb25hv5ldawqgf74oryfh4bbnhs2e"),
                CIDMap::from("bafy2bzaceczzcfgsqtdaz6awlvsdupcanl6chqync2olijapwxmagvao5eanc"),
            ]),
            epoch: 2930879,
            power_table: CIDMap::from(
                "bafy2bzacea7vkttjrv3pvia2yhahwi3qgss4ujozels5oxkgkupyvcej7zbdw",
            ),
            commitments: b"commitments epoch 2930879".to_vec(),
        }],
        supplemental_data: SupplementalData {
            commitments: b"supplemental commitments".to_vec(),
            power_table: CIDMap::from(
                "bafy2bzacea7vkttjrv3pvia2yhahwi3qgss4ujozels5oxkgkupyvcej7zbdw",
            ),
        },
        signers: vec![1, 2, 3, 4], // BitField as Vec<u8>
        signature: b"signature data".to_vec(),
        power_table_delta: vec![PowerTableDelta {
            participant_id: 1001,
            power_delta: "1000000000000000000".to_string(),
            signing_key: "c2lnbmluZyBrZXk=".to_string(), // "signing key" in base64
        }],
    }
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

    /// Verify certificate is valid for a tipset and instance
    pub fn is_valid_for_tipset(&self, tipset: &TipsetKey, instance: u64) -> bool {
        // This would check:
        // 1. The certificate instance matches the expected instance
        // 2. The tipset is within the EC chain range
        // 3. The signature is valid for the signers
        // 4. The power table delta is correctly applied
        // For now this is a simplified check
        self.instance == instance && tipset.cids().len() > 0
    }
}
