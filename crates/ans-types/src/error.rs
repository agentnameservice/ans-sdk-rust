//! Error types for ANS shared types.

use thiserror::Error;

/// Certificate and cryptographic errors.
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum CryptoError {
    /// Invalid DER encoding
    #[error("Invalid DER encoding: {0}")]
    InvalidDer(String),

    /// Certificate parsing failed
    #[error("Certificate parsing failed: {0}")]
    ParseFailed(String),

    /// Invalid fingerprint format
    #[error("Invalid fingerprint format: {fingerprint}")]
    InvalidFingerprint {
        /// The invalid fingerprint string.
        fingerprint: String,
    },

    /// Missing required certificate extension
    #[error("Missing required certificate extension: {name}")]
    MissingExtension {
        /// The name of the missing extension.
        name: String,
    },

    /// No common name found in certificate
    #[error("No common name found in certificate")]
    NoCommonName,

    /// No URI SAN found in certificate
    #[error("No URI SAN found in certificate")]
    NoUriSan,
}

/// Parse errors for various types.
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum ParseError {
    /// Invalid FQDN format
    #[error("Invalid FQDN: {0}")]
    InvalidFqdn(String),

    /// Invalid version format
    #[error("Invalid version format: {0}")]
    InvalidVersion(String),

    /// Invalid ANS name format
    #[error("Invalid ANS name format: {0}")]
    InvalidAnsName(String),

    /// Invalid URL
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Record is structurally invalid for its expected form
    #[error("Invalid record: {0}")]
    InvalidRecord(String),
}
