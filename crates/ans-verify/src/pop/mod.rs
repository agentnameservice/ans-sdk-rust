//! Application-layer proof of possession for ANS agent-to-agent traffic.
//!
//! Flavor B of ANS-6: the caller proves identity through L7 proxies that
//! terminate TLS, using an RFC 9449 `DPoP` proof bound to the Identity
//! Certificate via `x5c` and to the transparency log via the status token.
//!
//! Authentication is three independent proofs, all bound to one certificate:
//!
//! | Proof | Provided by |
//! |---|---|
//! | Identity | SCITT receipt (`X-SCITT-Receipt`) |
//! | Liveness | Status token (`X-ANS-Status-Token`) |
//! | Possession | `DPoP` proof (`DPoP` header) |
//!
//! This module composes with [`crate::scitt`]; it does not replace it.
//! Missing status token is a hard reject — Flavor B does not fall back to
//! the badge tier.
//!
//! Enable with `features = ["scitt"]`.

mod cache;
mod caller;
mod error;
mod http;
mod jws;
mod proof;
mod replay;
mod sign;
mod verify;

pub use cache::{DEFAULT_ARTIFACT_CACHE_ENTRIES, VerifiedArtifactCache};
pub use caller::{CallerIdentity, VerifyCallerOptions, verify_caller};
pub use error::{PopError, PopErrorKind};
pub use http::{
    DPOP_HEADER, access_token_from_authorization, attach_identity, reject_duplicate_header,
};
pub use proof::{normalize_authority, normalize_htu, request_authority};
pub use replay::{DEFAULT_REPLAY_MAX_ENTRIES, MemoryReplayCache, ReplayCache};
pub use sign::Signer;
pub use verify::{
    DEFAULT_POP_SKEW, MAX_JTI_SIZE, MAX_PROOF_SIZE, ProofResult, VerifyProofOptions, verify_proof,
};

#[cfg(test)]
mod tests;
