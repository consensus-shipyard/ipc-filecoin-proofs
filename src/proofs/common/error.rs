use std::fmt;
use thiserror::Error;

/// Main error type for proof generation and verification
#[derive(Error, Debug)]
pub enum ProofError {
    /// RPC communication errors
    #[error("RPC error: {message}")]
    Rpc {
        message: String,
        #[source]
        source: Option<anyhow::Error>,
    },

    /// Address resolution errors
    #[error("Failed to resolve address: {message}")]
    AddressResolution { message: String },

    /// Storage proof specific errors
    #[error("Storage error: {message}")]
    Storage { message: String },

    /// Event proof specific errors  
    #[error("Event error: {message}")]
    Event { message: String },

    /// Trust verification failures
    #[error("Trust verification failed: {reason}")]
    TrustVerificationFailed { reason: String },

    /// Invalid proof structure or data
    #[error("Invalid proof: {reason}")]
    InvalidProof { reason: String },

    /// Missing required data
    #[error("Missing data: {what}")]
    MissingData { what: String },

    /// Verification failed with details
    #[error("Verification failed: {details}")]
    VerificationFailed { details: String },

    /// Generic errors from other sources
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl ProofError {
    /// Create an RPC error
    pub fn rpc(message: impl Into<String>) -> Self {
        Self::Rpc {
            message: message.into(),
            source: None,
        }
    }

    /// Create an RPC error with source
    pub fn rpc_with_source(message: impl Into<String>, source: anyhow::Error) -> Self {
        Self::Rpc {
            message: message.into(),
            source: Some(source),
        }
    }

    /// Create an address resolution error
    pub fn address_resolution(message: impl Into<String>) -> Self {
        Self::AddressResolution {
            message: message.into(),
        }
    }

    /// Create a storage error
    pub fn storage(message: impl Into<String>) -> Self {
        Self::Storage {
            message: message.into(),
        }
    }

    /// Create an event error
    pub fn event(message: impl Into<String>) -> Self {
        Self::Event {
            message: message.into(),
        }
    }

    /// Create a trust verification error
    pub fn trust_failed(reason: impl Into<String>) -> Self {
        Self::TrustVerificationFailed {
            reason: reason.into(),
        }
    }

    /// Create an invalid proof error
    pub fn invalid_proof(reason: impl Into<String>) -> Self {
        Self::InvalidProof {
            reason: reason.into(),
        }
    }

    /// Create a missing data error
    pub fn missing_data(what: impl Into<String>) -> Self {
        Self::MissingData { what: what.into() }
    }

    /// Create a verification failed error
    pub fn verification_failed(details: impl Into<String>) -> Self {
        Self::VerificationFailed {
            details: details.into(),
        }
    }
}

/// Result type alias using ProofError
pub type ProofResult<T> = Result<T, ProofError>;
