//! Typed errors for `DPoP` proof-of-possession verification.

use thiserror::Error;

/// Stable category for a [`PopError`], suitable for metrics and structured logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PopErrorKind {
    /// Structurally invalid compact JWS, header, or payload.
    MalformedProof,
    /// `typ`/`alg`/`jwk` curve is not the pinned ES256 / `dpop+jwt` profile.
    UnsupportedAlg,
    /// `htm` or `htu` does not match the request.
    HttpBindingMismatch,
    /// `iat` is outside the freshness window.
    ProofStale,
    /// `jti` already seen within the freshness window.
    Replay,
    /// Replay cache is at capacity of still-live entries (fail closed).
    ReplayCacheFull,
    /// JWS signature does not verify under the `x5c[0]` key.
    SignatureInvalid,
    /// Missing, unparseable, or non-P-256 `x5c` leaf.
    CertInvalid,
    /// Header `jwk` does not match the `x5c[0]` public key.
    KeyMismatch,
    /// `ath` ↔ access-token binding failed.
    TokenBindingMismatch,
    /// Proof, status token, and receipt do not name the same agent.
    BindingFailed,
    /// Status token failed SCITT verification.
    StatusInvalid,
    /// Receipt failed SCITT verification or its leaf could not be bound.
    ReceiptInvalid,
    /// Missing `DPoP` proof, status token, or required receipt.
    MissingHeaders,
    /// Required dependency was not supplied (programmer error).
    Misconfigured,
    /// Proven caller is not in the callee's accepted-peer set.
    ExpectedPeerMismatch,
    /// Request authority is not in the callee's trusted set (ANS-6 §7.7).
    UntrustedAuthority,
}

impl PopErrorKind {
    /// Stable string label, matching the Go `pop` package categories.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedProof => "MALFORMED_PROOF",
            Self::UnsupportedAlg => "UNSUPPORTED_ALG",
            Self::HttpBindingMismatch => "HTTP_BINDING_MISMATCH",
            Self::ProofStale => "PROOF_STALE",
            Self::Replay => "REPLAY",
            Self::ReplayCacheFull => "REPLAY_CACHE_FULL",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::CertInvalid => "CERT_INVALID",
            Self::KeyMismatch => "KEY_MISMATCH",
            Self::TokenBindingMismatch => "TOKEN_BINDING_MISMATCH",
            Self::BindingFailed => "BINDING_FAILED",
            Self::StatusInvalid => "STATUS_INVALID",
            Self::ReceiptInvalid => "RECEIPT_INVALID",
            Self::MissingHeaders => "MISSING_HEADERS",
            Self::Misconfigured => "MISCONFIGURED",
            Self::ExpectedPeerMismatch => "EXPECTED_PEER_MISMATCH",
            Self::UntrustedAuthority => "UNTRUSTED_AUTHORITY",
        }
    }
}

impl std::fmt::Display for PopErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned by all `DPoP` verification and signing paths.
#[derive(Debug, Error)]
#[error("pop: {kind}: {message}")]
pub struct PopError {
    /// Stable failure category.
    pub kind: PopErrorKind,
    message: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl PopError {
    pub(crate) fn new(kind: PopErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
        }
    }

    pub(crate) fn with_source(
        kind: PopErrorKind,
        message: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            source: Some(source.into()),
        }
    }

    /// True when verification failed because an artifact's signing key id
    /// (`kid`) is absent from the key store — the ANS-6 §9.5 retry trigger.
    ///
    /// An unknown `kid` is not immediately a forgery: the TL may have added
    /// a key. Refresh the root keys once, cooldown-gated
    /// ([`crate::RefreshableKeyStore::refresh_if_cooldown_elapsed`]), and
    /// retry against the new snapshot before rejecting. Do not fall back to
    /// a weaker tier on an unknown `kid` alone.
    pub fn is_unknown_key_id(&self) -> bool {
        self.source
            .as_deref()
            .and_then(|s| s.downcast_ref::<crate::scitt::ScittError>())
            .is_some_and(|e| matches!(e, crate::scitt::ScittError::UnknownKeyId(_)))
    }

    /// Truncate untrusted input before interpolating it into an error message.
    pub(crate) fn echo(s: &str) -> String {
        const MAX: usize = 64;
        if s.len() <= MAX {
            s.to_string()
        } else {
            let mut end = MAX;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}…", &s[..end])
        }
    }
}
