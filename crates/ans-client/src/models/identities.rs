//! Management contracts for the optional Verified Identity capability.

use super::{IdentityKind, IdentityStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Register or rotate an identifier; its kind is inferred by the RA.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct IdentityRegistrationRequest {
    /// Identifier to prove control of.
    pub value: String,
}
impl IdentityRegistrationRequest {
    /// Select an identifier without asserting its kind.
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

/// One key eligible to sign the RA's exact payload segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IdentityProofChallenge {
    /// Eligible verification method, omitted when keys could not be enumerated.
    pub kid: Option<String>,
    /// Base64url JCS input supplied by the RA; sign this verbatim.
    pub signing_input: String,
}

/// A pending registration or rotation challenge round.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IdentityChallengeResponse {
    /// Identity stream identifier.
    pub identity_id: String,
    /// Inferred identifier kind.
    pub kind: IdentityKind,
    /// Canonical identifier for this round.
    pub value: String,
    /// `PENDING_CONTROL`, or VERIFIED while rotating.
    pub status: IdentityStatus,
    /// Shared single-use nonce.
    pub nonce: String,
    /// Challenge expiry.
    pub expires_at: DateTime<Utc>,
    /// Eligible keys, all sharing one signing input.
    pub challenges: Vec<IdentityProofChallenge>,
}

/// Compact JWS proofs submitted atomically for a challenge round.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct VerifyIdentityControlRequest {
    /// One proof per distinct key, between one and sixteen entries.
    pub signed_proofs: Vec<String>,
}
impl VerifyIdentityControlRequest {
    /// Supply compact proofs; the client validates the batch bound before sending.
    pub fn new(signed_proofs: Vec<String>) -> Self {
        Self { signed_proofs }
    }
}

/// One live management link from an identity to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IdentityAgentLink {
    /// Linked registration identifier.
    pub agent_id: String,
    /// Link time, if supplied.
    pub linked_at: Option<DateTime<Utc>>,
}

/// Current owner-scoped identity detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IdentityDetails {
    /// Identity stream identifier.
    pub identity_id: String,
    /// Identifier kind.
    pub kind: IdentityKind,
    /// Canonical identifier.
    pub value: String,
    /// Current lifecycle state.
    pub status: IdentityStatus,
    /// Control-proof method used.
    pub proof_method: Option<String>,
    /// Staged replacement during rotation.
    pub pending_value: Option<String>,
    /// Successful verification time.
    pub verified_at: Option<DateTime<Utc>>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Present on detail responses; omitted on collection items.
    #[serde(default, deserialize_with = "super::null_as_default")]
    pub linked_agents: Vec<IdentityAgentLink>,
}

/// Cursor-paginated owner identity collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IdentityListResponse {
    /// Identities on this page.
    pub items: Vec<IdentityDetails>,
    /// Number returned.
    pub returned_count: u32,
    /// Applied page size.
    pub limit: u32,
    /// Opaque next-page cursor.
    pub next_cursor: Option<String>,
    /// Whether another page exists.
    pub has_more: bool,
}

/// A single atomic link batch.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IdentityLinkRequest {
    /// Owned agent identifiers, between one and 256 entries.
    pub agent_ids: Vec<String>,
}
impl IdentityLinkRequest {
    /// Select the agents to link.
    pub fn new(agent_ids: Vec<String>) -> Self {
        Self { agent_ids }
    }
}

/// Result of an idempotent link batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct IdentityLinkResponse {
    /// Newly created links; existing links are skipped.
    pub linked: u32,
}
