//! Error types for ANS verification.

use ans_types::{BadgeStatus, CryptoError, ParseError};
use thiserror::Error;

/// Top-level error type for ANS operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AnsError {
    /// DNS lookup or parsing error
    #[error("DNS error: {0}")]
    Dns(#[from] DnsError),

    /// Transparency log API error
    #[error("Transparency log error: {0}")]
    TransparencyLog(#[from] TlogError),

    /// Certificate parsing or cryptographic error
    #[error("Certificate error: {0}")]
    Certificate(#[from] CryptoError),

    /// Verification logic error
    #[error("Verification error: {0}")]
    Verification(#[from] VerificationError),

    /// Parse error for types
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),

    /// SCITT verification error
    #[cfg(feature = "scitt")]
    #[error("SCITT error: {0}")]
    Scitt(#[from] crate::scitt::ScittError),
}

/// Result type alias using `AnsError`.
pub type AnsResult<T> = Result<T, AnsError>;

/// DNS-specific errors.
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum DnsError {
    /// Record does not exist (NXDOMAIN)
    #[error("DNS record not found (NXDOMAIN) for {fqdn}")]
    NotFound {
        /// The FQDN that was queried.
        fqdn: String,
    },

    /// DNS lookup failed (SERVFAIL, timeout, etc.)
    #[error("DNS lookup failed for {fqdn}: {reason}")]
    LookupFailed {
        /// The FQDN that was queried.
        fqdn: String,
        /// The reason the lookup failed.
        reason: String,
    },

    /// DNS query timed out
    #[error("DNS query timed out for {fqdn}")]
    Timeout {
        /// The FQDN that timed out.
        fqdn: String,
    },

    /// DNSSEC validation failed
    #[error("DNSSEC validation failed for {fqdn}")]
    DnssecFailed {
        /// The FQDN that failed DNSSEC validation.
        fqdn: String,
    },

    /// Invalid TXT record format
    #[error("Invalid badge TXT record format: {record}")]
    InvalidFormat {
        /// The malformed DNS record content.
        record: String,
    },

    /// Resolver configuration error
    #[error("DNS resolver error: {0}")]
    ResolverError(String),
}

impl DnsError {
    /// Only lookup outages can justify reuse of previously verified evidence.
    pub(crate) fn is_unavailable(&self) -> bool {
        matches!(self, Self::LookupFailed { .. } | Self::Timeout { .. })
    }
}

/// HTTP transport error wrapper.
///
/// Wraps the underlying HTTP client error to avoid exposing third-party
/// types in the public API.
#[derive(Debug)]
pub struct HttpError {
    inner: reqwest::Error,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

impl From<reqwest::Error> for HttpError {
    fn from(err: reqwest::Error) -> Self {
        Self { inner: err }
    }
}

/// Transparency log API errors.
///
/// These errors map to HTTP responses from the TL API:
/// - 404 → `NotFound`
/// - 429 or 5xx → `ServiceUnavailable`
/// - Parse failures → `InvalidResponse`
/// - Network/HTTP errors → `HttpError`
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TlogError {
    /// HTTP request failed (network error, timeout, etc.)
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] HttpError),

    /// Badge not found (HTTP 404)
    #[error("Badge not found at {url}")]
    NotFound {
        /// The URL that returned 404.
        url: String,
    },

    /// Invalid or unparseable badge response
    #[error("Invalid badge response: {0}")]
    InvalidResponse(String),

    /// Service unavailable or rate limited (HTTP 5xx or 429)
    #[error("Transparency log service unavailable")]
    ServiceUnavailable,

    /// The TL returned the badge-only UNKNOWN status (ANS-6 §4.1).
    #[error("Transparency log cannot determine the agent's current status")]
    StatusUnknown,

    /// Invalid URL construction
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// Invalid HTTP header name or value
    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    /// Badge URL domain is not in the trusted RA domains list
    #[error("Untrusted badge domain: {domain}")]
    UntrustedDomain {
        /// The domain that was not trusted.
        domain: String,
        /// The list of trusted domains.
        trusted: Vec<String>,
    },
}

impl TlogError {
    /// Malformed, missing, or untrusted evidence is not a transport outage.
    pub(crate) fn is_unavailable(&self) -> bool {
        matches!(
            self,
            Self::HttpError(_) | Self::ServiceUnavailable | Self::StatusUnknown
        )
    }
}

/// Verification logic errors.
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum VerificationError {
    /// Badge status is not valid for connections
    #[error("Badge status {status:?} is not valid for connections")]
    InvalidStatus {
        /// The badge status that was rejected.
        status: BadgeStatus,
    },

    /// Certificate fingerprint does not match badge
    #[error("Fingerprint mismatch: expected {expected}, got {actual}")]
    FingerprintMismatch {
        /// The expected fingerprint from the badge.
        expected: String,
        /// The actual fingerprint from the certificate.
        actual: String,
    },

    /// Hostname does not match badge
    #[error("Hostname mismatch: expected {expected}, got {actual}")]
    HostnameMismatch {
        /// The expected hostname from the badge.
        expected: String,
        /// The actual hostname from the certificate.
        actual: String,
    },

    /// ANS name does not match badge
    #[error("ANS name mismatch: expected {expected}, got {actual}")]
    AnsNameMismatch {
        /// The expected ANS name from the badge.
        expected: String,
        /// The actual ANS name from the certificate.
        actual: String,
    },

    /// No matching badge found for the presented certificate version
    #[error("No matching badge found for version {version}")]
    NoMatchingBadge {
        /// The version that had no matching badge.
        version: String,
    },

    /// Certificate does not chain to trusted CA
    #[error("Certificate does not chain to trusted CA")]
    UntrustedCertificate,

    /// DANE/TLSA verification failed
    #[error("DANE verification failed: {0}")]
    DaneVerificationFailed(DaneError),

    /// Multiple errors occurred
    #[error("Multiple verification errors: {errors:?}")]
    Multiple {
        /// The collected verification errors.
        errors: Vec<Self>,
    },

    /// Builder or verifier configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),
}

/// DANE/TLSA verification errors.
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum DaneError {
    /// No TLSA records found when required
    #[error("No TLSA records found for {fqdn}:{port}")]
    NoTlsaRecords {
        /// The FQDN that was queried.
        fqdn: String,
        /// The port that was queried.
        port: u16,
    },

    /// TLSA record fingerprint does not match certificate
    #[error("TLSA fingerprint mismatch: certificate not bound to DNS")]
    FingerprintMismatch,

    /// DNSSEC validation failed
    #[error("DNSSEC validation failed for {fqdn}")]
    DnssecValidationFailed {
        /// The FQDN that failed DNSSEC validation.
        fqdn: String,
    },

    /// DNSSEC required but not present
    #[error("DNSSEC required but not present for {fqdn}")]
    DnssecNotPresent {
        /// The FQDN missing DNSSEC.
        fqdn: String,
    },

    /// Invalid TLSA record format
    #[error("Invalid TLSA record: {reason}")]
    InvalidRecord {
        /// The reason the record is invalid.
        reason: String,
    },

    /// DNS lookup error during TLSA query
    #[error("DNS error during TLSA lookup: {0}")]
    DnsError(#[from] DnsError),
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_error_display() {
        let error = DnsError::NotFound {
            fqdn: "example.com".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "DNS record not found (NXDOMAIN) for example.com"
        );
    }

    #[test]
    fn test_tlog_error_display() {
        let error = TlogError::NotFound {
            url: "https://example.com/badge".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Badge not found at https://example.com/badge"
        );
    }

    #[test]
    fn test_verification_error_display() {
        let error = VerificationError::InvalidStatus {
            status: BadgeStatus::Revoked.clone(),
        };
        assert_eq!(
            error.to_string(),
            "Badge status Revoked is not valid for connections"
        );
    }

    #[test]
    fn test_dane_error_display() {
        let error = DaneError::NoTlsaRecords {
            fqdn: "example.com".to_string(),
            port: 443,
        };
        assert_eq!(
            error.to_string(),
            "No TLSA records found for example.com:443"
        );
    }

    #[test]
    fn test_multiple_verification_error_display() {
        let error = VerificationError::Multiple {
            errors: vec![
                VerificationError::FingerprintMismatch {
                    expected: "expected".to_string(),
                    actual: "actual".to_string(),
                },
                VerificationError::InvalidStatus {
                    status: BadgeStatus::Revoked.clone(),
                },
            ],
        };
        assert_eq!(
            error.to_string(),
            "Multiple verification errors: [FingerprintMismatch { expected: \"expected\", actual: \"actual\" }, InvalidStatus { status: Revoked }]"
        );
    }

    #[test]
    fn test_configuration_error_display() {
        let error = VerificationError::Configuration("missing key".to_string());
        assert_eq!(error.to_string(), "Configuration error: missing key");
    }
}
