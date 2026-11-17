//! Verified Identity management and transparency data (ANS-0/V2).

use crate::MerkleProof;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Domain separator for all Verified Identity control proofs.
pub const IDENTITY_PROOF_PURPOSE: &str = "ans:identity-proof:v1";

/// Identifier kinds recognized by the merged ANS specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum IdentityKind {
    /// Web-hosted DID, with challenge-bound key possession.
    #[serde(rename = "did:web")]
    DidWeb,
    /// Self-contained key DID.
    #[serde(rename = "did:key")]
    DidKey,
    /// LEI/vLEI; its control-proof profile is postponed.
    #[serde(rename = "lei")]
    Lei,
    /// ENS; its control-proof profile is postponed.
    #[serde(rename = "ens")]
    Ens,
}
impl IdentityKind {
    /// The exact wire identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DidWeb => "did:web",
            Self::DidKey => "did:key",
            Self::Lei => "lei",
            Self::Ens => "ens",
        }
    }
}

/// Current lifecycle state of a Verified Identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum IdentityStatus {
    /// Awaiting a control proof.
    PendingControl,
    /// Control has been proven.
    Verified,
    /// Terminal revocation; subsequent events cannot restore this identity.
    Revoked,
}

/// The exact six-member, domain-separated proof payload served by the RA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct IdentityProofInput {
    /// Canonical identifier being proved.
    pub identifier: String,
    /// Assigned identity stream identifier.
    pub identity_id: String,
    /// Single-use base64url nonce.
    pub nonce: String,
    /// Fixed ANS proof domain separator.
    pub purpose: String,
    /// RA identifier from trusted configuration/sealed evidence.
    pub ra_id: String,
    /// Identifier kind.
    pub scheme: IdentityKind,
}
impl IdentityProofInput {
    /// Build the expected payload, with the fixed ANS domain separator.
    pub fn new(
        identifier: impl Into<String>,
        identity_id: impl Into<String>,
        nonce: impl Into<String>,
        ra_id: impl Into<String>,
        scheme: IdentityKind,
    ) -> Self {
        Self {
            identifier: identifier.into(),
            identity_id: identity_id.into(),
            nonce: nonce.into(),
            purpose: IDENTITY_PROOF_PURPOSE.into(),
            ra_id: ra_id.into(),
            scheme,
        }
    }
}

/// One sealed key and its compact JWS possession proof.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ProvenIdentityKey {
    /// Complete source verification method, including unrecognized members.
    /// This is preserved verbatim; derived keys/thumbprints are not substituted.
    pub verification_method: Value,
    /// Compact JWS whose payload is the served signing input.
    pub signed_proof: String,
}

/// The immutable identity-event family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum IdentityEventType {
    /// Initial successful control proof.
    IdentityVerified,
    /// Proven rotation/replacement.
    IdentityUpdated,
    /// Terminal revocation.
    IdentityRevoked,
    /// Batch of links to agents.
    IdentityLinked,
    /// Batch of removed links.
    IdentityUnlinked,
}

/// Producer-authored identity event, matching the sealed V2 schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IdentityEvent {
    /// Event family member.
    pub event_type: IdentityEventType,
    /// Identity stream identifier.
    pub identity_id: String,
    /// Identifier profile.
    pub kind: IdentityKind,
    /// Canonical identifier.
    pub value: String,
    /// Producer event timestamp.
    pub timestamp: DateTime<Utc>,
    /// Control-proof method when present.
    pub proof_method: Option<String>,
    /// Owning provider, required on proof events.
    pub provider_id: Option<String>,
    /// Proof events carry the complete proven set; link/revocation events omit it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<ProvenIdentityKey>,
    /// Identifier before a rotation.
    pub previous_value: Option<String>,
    /// Link/unlink batch. Non-link events have no agent identifiers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ans_ids: Vec<String>,
    /// Successful proof time.
    pub verified_at: Option<DateTime<Utc>>,
    /// Revocation time.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Sealed RA identifier, needed for offline proof reconstruction.
    pub ra_id: Option<String>,
}

/// Producer signature and its sealed identity event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IdentityProducer {
    /// Identity event.
    pub event: IdentityEvent,
    /// Producer key identifier.
    pub key_id: String,
    /// Detached producer signature.
    pub signature: String,
}

/// Identity leaf payload in the common TL envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IdentityLogPayload {
    /// TL-assigned entry identifier.
    pub log_id: String,
    /// Signed producer event.
    pub producer: IdentityProducer,
}

/// An identity badge or historical identity log entry.
///
/// Current badge `keys` contain verification methods only. The JWS proofs live
/// in the proof event identified by `keys_log_id`, not in that computed list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IdentityBadge {
    /// Sealed event payload (the latest event may be only a link/unlink).
    pub payload: IdentityLogPayload,
    /// Identity envelopes use V2.
    pub schema_version: String,
    /// TL detached attestation.
    pub signature: String,
    /// Current badge status, or historical envelope status on audit entries.
    /// Historical envelope status alone must not be used as a liveness claim.
    pub status: String,
    /// Optional JSON inclusion-proof representation.
    pub merkle_proof: Option<MerkleProof>,
    /// Current verification methods, omitted on revoked badges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<Value>,
    /// Proof event containing the current methods' signed proofs.
    pub keys_log_id: Option<String>,
}

/// Identity audit/history pages use the same `records` envelope as agent audits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct IdentityAuditResponse {
    /// Sealed records, newest first.
    pub records: Vec<IdentityBadge>,
}

/// Current identity association, shared by management and TL views.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LinkedIdentity {
    /// Identity stream identifier.
    pub identity_id: String,
    /// Identifier profile.
    pub kind: IdentityKind,
    /// Canonical identifier.
    pub value: String,
    /// Current state; older management views may omit it.
    pub identity_status: Option<IdentityStatus>,
    /// Current verification methods, not possession proofs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<Value>,
    /// Sealed proof event to fetch for offline evidence.
    pub keys_log_id: Option<String>,
    /// Link time.
    pub linked_at: Option<DateTime<Utc>>,
    /// Sealed link event identifier.
    pub link_log_id: Option<String>,
}

/// Paginated current identities linked to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LinkedIdentitiesResponse {
    /// Visible current associations, including revoked identities without keys.
    pub identities: Vec<LinkedIdentity>,
    /// Count across all pages.
    pub total: u64,
}

/// An agent currently linked to an identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct LinkedAgent {
    /// Agent registration identifier.
    pub ans_id: String,
    /// Link time.
    pub linked_at: Option<DateTime<Utc>>,
    /// Current agent status.
    pub agent_status: Option<crate::BadgeStatus>,
}

/// Paginated reverse identity-to-agent association.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct LinkedAgentsResponse {
    /// Visible, live agents.
    pub agents: Vec<LinkedAgent>,
    /// Count across all pages.
    pub total: u64,
}
