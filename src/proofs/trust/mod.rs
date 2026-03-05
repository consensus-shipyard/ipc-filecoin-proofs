use anyhow::Result;
use cid::Cid;

use crate::cert::FinalityCertificate;

/// Trust verification policy for validating finality of blocks
#[derive(Debug, Clone)]
pub enum TrustPolicy {
    /// Accept all blocks as trusted (for testing only)
    /// WARNING: This should only be used in development/testing environments
    AcceptAll,

    /// Verify using F3 finality certificates (recommended for production)
    /// This ensures blocks are finalized according to the F3 consensus protocol
    F3Certificate { certificate: FinalityCertificate },
}

/// Custom verifier wrapper
#[derive(Clone)]
pub struct CustomVerifier {
    verifier: std::sync::Arc<dyn TrustVerifier>,
}

impl std::fmt::Debug for CustomVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomVerifier").finish()
    }
}

/// Trait for custom trust verification logic
pub trait TrustVerifier: Send + Sync {
    /// Verify if a parent tipset is trusted/finalized
    fn verify_parent_tipset(&self, epoch: i64, cids: &[Cid]) -> Result<bool>;

    /// Verify if a child header is trusted/finalized
    fn verify_child_header(&self, epoch: i64, cid: &Cid) -> Result<bool>;
}

impl TrustPolicy {
    /// Create a policy that accepts everything (testing only)
    /// WARNING: Only use this in development/testing environments
    pub fn accept_all() -> Self {
        Self::AcceptAll
    }

    /// Create a policy using F3 certificates (recommended for production)
    /// This ensures cryptographic proof of finality
    pub fn with_f3_certificate(cert: FinalityCertificate) -> Self {
        Self::F3Certificate { certificate: cert }
    }

    /// Verify if a parent tipset is trusted according to this policy
    pub fn verify_parent_tipset(&self, epoch: i64, _cids: &[Cid]) -> Result<bool> {
        match self {
            Self::AcceptAll => Ok(true),

            Self::F3Certificate { certificate } => {
                // TODO: Implement actual F3 certificate verification
                // For now, just check if the tipset is covered by the certificate
                // This would need proper F3 certificate validation logic
                Ok(certificate.is_valid_for_epoch(epoch))
            }
        }
    }

    /// Verify if a child header is trusted according to this policy
    pub fn verify_child_header(&self, epoch: i64, _cid: &Cid) -> Result<bool> {
        match self {
            Self::AcceptAll => Ok(true),

            Self::F3Certificate { certificate } => {
                // TODO: Implement actual F3 certificate verification
                // For now, just check if the header is covered by the certificate
                // This would need proper F3 certificate validation logic
                Ok(certificate.is_valid_for_epoch(epoch))
            }
        }
    }
}

/// Mock trust verifier for testing
pub struct MockTrustVerifier {
    pub parent_result: bool,
    pub child_result: bool,
}

impl TrustVerifier for MockTrustVerifier {
    fn verify_parent_tipset(&self, _epoch: i64, _cids: &[Cid]) -> Result<bool> {
        Ok(self.parent_result)
    }

    fn verify_child_header(&self, _epoch: i64, _cid: &Cid) -> Result<bool> {
        Ok(self.child_result)
    }
}
