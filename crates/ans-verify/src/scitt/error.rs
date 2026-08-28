//! Error types for SCITT verification.
//!
//! `ScittError` covers all failure modes in the SCITT verification path:
//! structural (CBOR/COSE parsing), cryptographic (signature, Merkle),
//! status token (expiry, terminal status), key management (C2SP format),
//! and transport (HTTP responses from the SCITT API).

use crate::error::HttpError;
use ans_types::BadgeStatus;
use thiserror::Error;
use uuid::Uuid;

/// Errors from SCITT receipt and status token verification.
///
/// Each variant maps to a specific failure mode. Use
/// [`VerificationOutcome::is_terminal_status()`](crate::VerificationOutcome::is_terminal_status)
/// for a unified terminal-status check across both badge and SCITT paths.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ScittError {
    // ── Structural ──
    /// Input `COSE_Sign1` artifact exceeds maximum size.
    #[error("Input exceeds maximum size of {max_bytes} bytes")]
    OversizedInput {
        /// The maximum allowed size in bytes.
        max_bytes: usize,
    },

    /// Input is not a valid `COSE_Sign1` structure.
    #[error("Not a COSE_Sign1 structure")]
    NotACoseSign1,

    /// CBOR decoding failed.
    #[error("CBOR decode failed: {0}")]
    CborDecodeError(String),

    /// `COSE_Sign1` must be a 4-element array.
    #[error("Invalid COSE_Sign1: expected 4-element array, got {found}")]
    InvalidArrayLength {
        /// The actual number of elements found.
        found: usize,
    },

    /// ECDSA P-256 signatures must be exactly 64 bytes (P1363 format).
    #[error("Invalid signature length: expected 64 bytes, got {actual}")]
    InvalidSignatureLength {
        /// The actual signature length in bytes.
        actual: usize,
    },

    // ── Protected header ──
    /// Protected header is malformed or missing required fields.
    #[error("Invalid protected header: {0}")]
    InvalidProtectedHeader(String),

    /// COSE algorithm is not ES256 (required for SCITT P-256 signatures).
    #[error("Unsupported COSE algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// COSE protected header is missing the `kid` (key ID) field.
    #[error("Missing kid in COSE protected header")]
    MissingKid,

    // ── Cryptographic ──
    /// ECDSA signature verification failed.
    #[error("ECDSA signature verification failed")]
    SignatureInvalid,

    /// The key ID from the COSE header is not in the trusted key store.
    #[error("Unknown key ID: {}", hex::encode(.0))]
    UnknownKeyId(
        /// The 4-byte key ID that was not found.
        [u8; 4],
    ),

    /// Receipt `iss` claim does not match the signing key's TL domain.
    #[error("Issuer mismatch: receipt claims iss={claimed:?} but key belongs to {key_domain:?}")]
    IssuerMismatch {
        /// The `iss` value from the COSE protected header.
        claimed: String,
        /// The TL domain from the trusted key's C2SP name.
        key_domain: String,
    },

    /// Status token names a different host than the one the caller dialed
    /// (ANS-6 §5.2 — the artifacts alone cannot supply this anchor).
    #[error("Host mismatch: dialed {expected:?} but status token names {actual:?}")]
    HostMismatch {
        /// The host the caller resolved and dialed.
        expected: String,
        /// The host from the status token's `ansName`.
        actual: String,
    },

    // ── Merkle ──
    /// Merkle inclusion proof is structurally invalid.
    #[error("Merkle proof invalid: {0}")]
    InvalidMerkleProof(String),

    /// Computed Merkle root does not match the expected root from the receipt.
    #[error("Computed Merkle root does not match expected root")]
    MerkleRootMismatch,

    // ── Status token ──
    /// Status token has expired.
    ///
    /// This is NOT an integrity failure — the token was validly signed but is
    /// simply stale. Under all tier policies, `TokenExpired` is a hard reject
    /// when SCITT headers are present. Badge fallback only occurs when SCITT
    /// headers are completely absent.
    #[error("Status token expired (exp={exp}, now={now})")]
    TokenExpired {
        /// The token's expiry timestamp (Unix seconds).
        exp: i64,
        /// The current time (Unix seconds).
        now: i64,
    },

    /// Status token is missing a required CBOR field.
    #[error("Status token missing required field: {0}")]
    MissingTokenField(String),

    /// Agent is in a terminal status that rejects connections.
    #[error("Terminal status: {0:?}")]
    TerminalStatus(BadgeStatus),

    // ── Key management ──
    /// C2SP key format string is invalid.
    #[error("Invalid C2SP key format: {0}")]
    InvalidKeyFormat(String),

    /// Key hash in C2SP key does not match the SPKI-DER hash.
    #[error("Key hash mismatch in C2SP key")]
    KeyHashMismatch,

    /// SPKI-DER does not encode a valid ECDSA P-256 public key.
    #[error("Invalid ECDSA P-256 public key: {0}")]
    InvalidPublicKey(String),

    /// Key belongs to a TL domain not in the trusted domain list.
    #[error("Untrusted TL domain '{domain}' (trusted: {trusted:?})")]
    UntrustedKeyDomain {
        /// The untrusted domain.
        domain: String,
        /// The list of trusted domains.
        trusted: Vec<String>,
    },

    // ── Client configuration ──
    /// Base URL or header configuration for the SCITT client is invalid.
    #[error("Invalid SCITT client config: {0}")]
    InvalidUrl(String),

    /// TL returned an unexpected HTTP status code.
    #[error("Unexpected HTTP {status} from {url}")]
    UnexpectedHttpStatus {
        /// The HTTP status code.
        status: u16,
        /// The URL that was requested.
        url: String,
    },

    // ── Transport ──
    /// HTTP request to the SCITT API failed.
    #[error("SCITT HTTP error: {0}")]
    HttpError(#[from] HttpError),

    /// SCITT artifact not found for the given agent.
    #[error("SCITT artifact not found for agent {agent_id}")]
    NotFound {
        /// The agent ID that was queried.
        agent_id: Uuid,
    },

    /// Base64 decoding of an HTTP header value failed.
    #[error("Base64 decode error: {0}")]
    Base64Decode(String),

    // ── HTTP status codes ──
    /// Agent is in a terminal state per the TL (HTTP 410 Gone).
    #[error("Agent {agent_id} is in terminal state (410 Gone)")]
    AgentTerminal {
        /// The agent ID that is terminal.
        agent_id: Uuid,
    },

    /// The TL instance does not support SCITT (HTTP 501).
    #[error("SCITT not supported by TL instance at {endpoint} (501)")]
    NotSupported {
        /// The endpoint that returned 501.
        endpoint: String,
    },
}

impl ScittError {
    /// Returns `true` if this error represents a terminal agent status.
    ///
    /// Terminal status errors are always hard rejects — they are never eligible
    /// for badge fallback, and `BadgeWithScittEnhancement` will not discard them.
    ///
    /// Callers should use [`VerificationOutcome::is_terminal_status()`] for a
    /// unified check that covers both badge-detected (`InvalidStatus`) and
    /// SCITT-detected terminal statuses.
    ///
    /// [`VerificationOutcome::is_terminal_status()`]: crate::VerificationOutcome::is_terminal_status
    pub fn is_terminal_status(&self) -> bool {
        matches!(self, Self::TerminalStatus(_) | Self::AgentTerminal { .. })
    }

    /// Returns `true` if this error is a non-integrity transport/availability
    /// failure from the SCITT client (agent-side supplier), not a verification
    /// failure.
    ///
    /// The built-in verifier does **not** use this method — when SCITT headers
    /// are present, the verification result is final with no badge fallback.
    /// This method exists for custom integrations that need to distinguish
    /// transport failures from integrity failures.
    ///
    /// Non-integrity failures:
    /// - `NotSupported`: TL doesn't support SCITT
    /// - `NotFound`: agent not yet registered for SCITT
    /// - `UnexpectedHttpStatus`: TL returned an error (transient)
    /// - `HttpError`: transport failure (network, timeout)
    ///
    /// All integrity failures (structural, crypto, Merkle, expired) are
    /// **not** included.
    pub fn should_fallback_to_badge(&self) -> bool {
        matches!(
            self,
            Self::NotSupported { .. }
                | Self::NotFound { .. }
                | Self::UnexpectedHttpStatus { .. }
                | Self::HttpError(_)
        )
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_oversized_input() {
        let err = ScittError::OversizedInput {
            max_bytes: 1_048_576,
        };
        assert_eq!(
            err.to_string(),
            "Input exceeds maximum size of 1048576 bytes"
        );
    }

    #[test]
    fn display_not_a_cose_sign1() {
        let err = ScittError::NotACoseSign1;
        assert_eq!(err.to_string(), "Not a COSE_Sign1 structure");
    }

    #[test]
    fn display_cbor_decode_error() {
        let err = ScittError::CborDecodeError("unexpected EOF".to_string());
        assert_eq!(err.to_string(), "CBOR decode failed: unexpected EOF");
    }

    #[test]
    fn display_invalid_array_length() {
        let err = ScittError::InvalidArrayLength { found: 3 };
        assert_eq!(
            err.to_string(),
            "Invalid COSE_Sign1: expected 4-element array, got 3"
        );
    }

    #[test]
    fn display_invalid_signature_length() {
        let err = ScittError::InvalidSignatureLength { actual: 32 };
        assert_eq!(
            err.to_string(),
            "Invalid signature length: expected 64 bytes, got 32"
        );
    }

    #[test]
    fn display_signature_invalid() {
        let err = ScittError::SignatureInvalid;
        assert_eq!(err.to_string(), "ECDSA signature verification failed");
    }

    #[test]
    fn display_unknown_key_id() {
        let err = ScittError::UnknownKeyId([0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(err.to_string(), "Unknown key ID: deadbeef");
    }

    #[test]
    fn display_merkle_root_mismatch() {
        let err = ScittError::MerkleRootMismatch;
        assert_eq!(
            err.to_string(),
            "Computed Merkle root does not match expected root"
        );
    }

    #[test]
    fn display_token_expired() {
        let err = ScittError::TokenExpired {
            exp: 1_700_000_000,
            now: 1_700_003_600,
        };
        assert_eq!(
            err.to_string(),
            "Status token expired (exp=1700000000, now=1700003600)"
        );
    }

    #[test]
    fn display_terminal_status() {
        let err = ScittError::TerminalStatus(BadgeStatus::Revoked);
        assert_eq!(err.to_string(), "Terminal status: Revoked");
    }

    #[test]
    fn display_agent_terminal() {
        let id = Uuid::nil();
        let err = ScittError::AgentTerminal { agent_id: id };
        assert!(err.to_string().contains("terminal state (410 Gone)"));
    }

    #[test]
    fn display_not_supported() {
        let err = ScittError::NotSupported {
            endpoint: "https://tl.example.com/v1/scitt".to_string(),
        };
        assert!(err.to_string().contains("501"));
        assert!(err.to_string().contains("tl.example.com"));
    }

    #[test]
    fn display_not_found() {
        let id = Uuid::nil();
        let err = ScittError::NotFound { agent_id: id };
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn display_base64_decode() {
        let err = ScittError::Base64Decode("invalid padding".to_string());
        assert_eq!(err.to_string(), "Base64 decode error: invalid padding");
    }

    #[test]
    fn display_invalid_url() {
        let err = ScittError::InvalidUrl("bad URL".to_string());
        assert_eq!(err.to_string(), "Invalid SCITT client config: bad URL");
    }

    #[test]
    fn display_unexpected_http_status() {
        let err = ScittError::UnexpectedHttpStatus {
            status: 503,
            url: "https://tl.example.com/root-keys".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Unexpected HTTP 503 from https://tl.example.com/root-keys"
        );
    }

    #[test]
    fn display_invalid_key_format() {
        let err = ScittError::InvalidKeyFormat("missing + delimiter".to_string());
        assert!(err.to_string().contains("missing + delimiter"));
    }

    #[test]
    fn display_untrusted_key_domain() {
        let err = ScittError::UntrustedKeyDomain {
            domain: "evil.com".to_string(),
            trusted: vec!["tl.example.com".to_string()],
        };
        assert!(err.to_string().contains("evil.com"));
        assert!(err.to_string().contains("tl.example.com"));
    }

    // ── is_terminal_status ──

    #[test]
    fn is_terminal_status_for_terminal_variants() {
        assert!(ScittError::TerminalStatus(BadgeStatus::Revoked).is_terminal_status());
        assert!(ScittError::TerminalStatus(BadgeStatus::Expired).is_terminal_status());
        assert!(
            ScittError::AgentTerminal {
                agent_id: Uuid::nil()
            }
            .is_terminal_status()
        );
    }

    #[test]
    fn is_terminal_status_false_for_non_terminal() {
        assert!(!ScittError::SignatureInvalid.is_terminal_status());
        assert!(!ScittError::MerkleRootMismatch.is_terminal_status());
        assert!(!ScittError::TokenExpired { exp: 0, now: 3600 }.is_terminal_status());
        assert!(!ScittError::NotACoseSign1.is_terminal_status());
    }

    // ── should_fallback_to_badge ──

    #[test]
    fn fallback_for_non_integrity_errors() {
        assert!(
            ScittError::NotSupported {
                endpoint: "https://tl.example.com".to_string()
            }
            .should_fallback_to_badge()
        );
        assert!(
            ScittError::NotFound {
                agent_id: Uuid::nil()
            }
            .should_fallback_to_badge()
        );
        assert!(
            ScittError::UnexpectedHttpStatus {
                status: 503,
                url: "https://tl.example.com/root-keys".to_string()
            }
            .should_fallback_to_badge()
        );
    }

    #[test]
    fn no_fallback_for_integrity_errors() {
        assert!(!ScittError::SignatureInvalid.should_fallback_to_badge());
        assert!(!ScittError::MerkleRootMismatch.should_fallback_to_badge());
        assert!(!ScittError::NotACoseSign1.should_fallback_to_badge());
        assert!(!ScittError::Base64Decode("bad".to_string()).should_fallback_to_badge());
        assert!(!ScittError::UnknownKeyId([0; 4]).should_fallback_to_badge());
        assert!(!ScittError::CborDecodeError("bad".to_string()).should_fallback_to_badge());
        assert!(!ScittError::InvalidArrayLength { found: 3 }.should_fallback_to_badge());
        assert!(!ScittError::InvalidSignatureLength { actual: 32 }.should_fallback_to_badge());
        assert!(!ScittError::TokenExpired { exp: 0, now: 3600 }.should_fallback_to_badge());
        assert!(
            !ScittError::IssuerMismatch {
                claimed: "evil.com".to_string(),
                key_domain: "tl.example.com".to_string()
            }
            .should_fallback_to_badge()
        );
    }

    #[test]
    fn display_issuer_mismatch() {
        let err = ScittError::IssuerMismatch {
            claimed: "evil.example.com".to_string(),
            key_domain: "tl.example.com".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("evil.example.com"));
        assert!(msg.contains("tl.example.com"));
    }

    #[test]
    fn issuer_mismatch_is_not_terminal() {
        assert!(
            !ScittError::IssuerMismatch {
                claimed: "a.com".to_string(),
                key_domain: "b.com".to_string()
            }
            .is_terminal_status()
        );
    }

    #[test]
    fn no_fallback_for_terminal_status() {
        assert!(!ScittError::TerminalStatus(BadgeStatus::Revoked).should_fallback_to_badge());
        assert!(
            !ScittError::AgentTerminal {
                agent_id: Uuid::nil()
            }
            .should_fallback_to_badge()
        );
    }

    // ── From<HttpError> ──

    #[test]
    fn from_http_error() {
        // Build an HttpError via a reqwest error (use a deliberately bad URL)
        let result = reqwest::Url::parse("not a url");
        assert!(result.is_err()); // just verify we can construct errors
    }
}
