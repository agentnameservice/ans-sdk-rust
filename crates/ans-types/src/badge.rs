//! Badge data models from the Transparency Log API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Badge status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum BadgeStatus {
    /// Agent is registered and in good standing.
    Active,
    /// Certificate expires within 30 days.
    Warning,
    /// AHP has marked this version for retirement; consumers should migrate.
    Deprecated,
    /// Certificate has expired.
    Expired,
    /// Registration has been explicitly revoked.
    Revoked,
    /// The TL cannot determine current status. Badge-only; apply the verifier's
    /// failure policy instead of treating this as a successful status.
    Unknown,
}

impl BadgeStatus {
    /// Check if this status is valid for establishing connections.
    pub fn is_valid_for_connection(&self) -> bool {
        matches!(self, Self::Active | Self::Warning | Self::Deprecated)
    }

    /// Check if this status is fully active (not deprecated).
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active | Self::Warning)
    }

    /// Check if this is a determinate terminal status.
    ///
    /// `Unknown` is not terminal, but is also never valid for a connection.
    pub fn should_reject(&self) -> bool {
        matches!(self, Self::Expired | Self::Revoked)
    }
}

/// Event types for badge events.
///
/// Known values match the TL API schema. Unfamiliar informational event labels
/// are preserved; live authentication depends on the badge status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
#[non_exhaustive]
pub enum EventType {
    /// Agent was initially registered.
    AgentRegistered,
    /// Agent certificates were renewed.
    AgentRenewed,
    /// Agent registration was updated.
    AgentUpdated,
    /// AHP has marked this version for retirement.
    AgentDeprecated,
    /// Agent registration was revoked.
    AgentRevoked,
    /// An event label introduced after this SDK version.
    Other(String),
}

impl From<String> for EventType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "AGENT_REGISTERED" => Self::AgentRegistered,
            "AGENT_RENEWED" => Self::AgentRenewed,
            "AGENT_UPDATED" => Self::AgentUpdated,
            "AGENT_DEPRECATED" => Self::AgentDeprecated,
            "AGENT_REVOKED" => Self::AgentRevoked,
            _ => Self::Other(value),
        }
    }
}

impl From<EventType> for String {
    fn from(value: EventType) -> Self {
        match value {
            EventType::AgentRegistered => "AGENT_REGISTERED".into(),
            EventType::AgentRenewed => "AGENT_RENEWED".into(),
            EventType::AgentUpdated => "AGENT_UPDATED".into(),
            EventType::AgentDeprecated => "AGENT_DEPRECATED".into(),
            EventType::AgentRevoked => "AGENT_REVOKED".into(),
            EventType::Other(value) => value,
        }
    }
}

/// Full badge response from the Transparency Log API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Badge {
    /// Current status of the badge.
    pub status: BadgeStatus,
    /// Badge payload containing the signed event.
    pub payload: BadgePayload,
    /// Schema version (`V1` or `V2`).
    pub schema_version: String,
    /// Signature over the badge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Merkle proof for transparency log inclusion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_proof: Option<MerkleProof>,
}

impl Badge {
    /// Get the agent's ANS name.
    pub fn agent_name(&self) -> &str {
        &self.payload.producer.event.ans_name
    }

    /// Get the agent's host FQDN.
    pub fn agent_host(&self) -> &str {
        &self.payload.producer.event.agent.host
    }

    /// Get the agent's version string.
    pub fn agent_version(&self) -> &str {
        &self.payload.producer.event.agent.version
    }

    /// Get the first server certificate fingerprint, or `""` if absent.
    ///
    /// Use [`Self::server_cert_fingerprints`] for verification: rotations
    /// can publish more than one certificate.
    pub fn server_cert_fingerprint(&self) -> &str {
        self.server_cert_fingerprints().next().unwrap_or("")
    }

    /// Get the first identity certificate fingerprint, or `""` if absent.
    ///
    /// Use [`Self::identity_cert_fingerprints`] for verification.
    pub fn identity_cert_fingerprint(&self) -> &str {
        self.identity_cert_fingerprints().next().unwrap_or("")
    }

    /// All server certificate fingerprints for this badge's schema.
    pub fn server_cert_fingerprints(&self) -> impl Iterator<Item = &str> {
        let attestations = &self.payload.producer.event.attestations;
        self.cert_fingerprints(
            &attestations.server_certs,
            attestations.server_cert.as_ref(),
        )
    }

    /// All identity certificate fingerprints for this badge's schema.
    ///
    /// Registrations without an Identity Certificate yield no entries.
    pub fn identity_cert_fingerprints(&self) -> impl Iterator<Item = &str> {
        let attestations = &self.payload.producer.event.attestations;
        self.cert_fingerprints(
            &attestations.identity_certs,
            attestations.identity_cert.as_ref(),
        )
    }

    fn cert_fingerprints<'a>(
        &'a self,
        certificates: &'a [CertAttestation],
        legacy: Option<&'a CertAttestation>,
    ) -> impl Iterator<Item = &'a str> {
        // V2 uses only arrays: a stale singular field must not restore a
        // certificate missing from the current array. Unknown schemas fail
        // closed instead of inheriting V1 semantics.
        let (certificates, legacy) = match self.schema_version.as_str() {
            "V1" if certificates.is_empty() => (certificates, legacy),
            "V1" | "V2" => (certificates, None),
            _ => (&[][..], None),
        };
        certificates
            .iter()
            .chain(legacy)
            .map(|cert| cert.fingerprint.as_str())
    }

    /// Get the agent ID (UUID).
    pub fn agent_id(&self) -> Uuid {
        self.payload.producer.event.ans_id
    }

    /// Get the event type.
    pub fn event_type(&self) -> EventType {
        self.payload.producer.event.event_type.clone()
    }

    /// Check if this badge is valid for connections.
    pub fn is_valid(&self) -> bool {
        self.status.is_valid_for_connection()
    }
}

/// Badge payload containing the producer and signed event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BadgePayload {
    /// Log ID for this entry.
    pub log_id: Uuid,
    /// Producer information with signed event.
    pub producer: Producer,
}

/// Producer information with the agent event and signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Producer {
    /// The agent event details.
    pub event: AgentEvent,
    /// Key ID used for signing.
    pub key_id: String,
    /// Signature over the event.
    pub signature: String,
}

/// Agent event containing all registration/verification details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AgentEvent {
    /// Agent's unique ID.
    pub ans_id: Uuid,
    /// Full ANS name (e.g., "<ans://v1.0.0.agent.example.com>").
    pub ans_name: String,
    /// Type of event.
    pub event_type: EventType,
    /// Agent information.
    pub agent: AgentInfo,
    /// Certificate attestations.
    pub attestations: Attestations,
    /// When this registration expires, if present in the sealed event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// When this registration was issued.
    pub issued_at: DateTime<Utc>,
    /// Registration Authority ID.
    pub ra_id: String,
    /// Event timestamp.
    pub timestamp: DateTime<Utc>,
}

/// Basic agent information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AgentInfo {
    /// Agent's host FQDN.
    pub host: String,
    /// Human-readable agent name.
    #[serde(default)]
    pub name: String,
    /// Agent version string.
    pub version: String,
}

/// Certificate attestations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Attestations {
    /// Domain validation method, when this event includes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_validation: Option<String>,
    /// Legacy V1 identity certificate, absent for server-only registrations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_cert: Option<CertAttestation>,
    /// Legacy V1 server certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_cert: Option<CertAttestation>,
    /// V2 identity certificates, including the rotation overlap.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_certs: Vec<CertAttestation>,
    /// V2 server certificates, including the rotation overlap.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server_certs: Vec<CertAttestation>,
}

/// Certificate attestation with fingerprint and type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CertAttestation {
    /// Certificate fingerprint in `SHA256:<hex>` format.
    pub fingerprint: String,
    /// Certificate type (e.g., "X509-DV-SERVER", "X509-OV-CLIENT").
    #[serde(rename = "type")]
    pub cert_type: String,
}

/// Merkle proof for transparency log inclusion verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct MerkleProof {
    /// Hash of the leaf node.
    pub leaf_hash: String,
    /// Index of the leaf in the tree.
    pub leaf_index: u64,
    /// Proof path (sibling hashes).
    pub path: Vec<String>,
    /// Root hash of the tree.
    pub root_hash: String,
    /// Signature over the root.
    pub root_signature: String,
    /// Total size of the tree.
    pub tree_size: u64,
    /// Version of the tree.
    pub tree_version: u64,
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_badge_status_valid_for_connection() {
        assert!(BadgeStatus::Active.is_valid_for_connection());
        assert!(BadgeStatus::Warning.is_valid_for_connection());
        assert!(BadgeStatus::Deprecated.is_valid_for_connection());
        assert!(!BadgeStatus::Expired.is_valid_for_connection());
        assert!(!BadgeStatus::Revoked.is_valid_for_connection());
        assert!(!BadgeStatus::Unknown.is_valid_for_connection());
    }

    #[test]
    fn test_badge_status_should_reject() {
        assert!(!BadgeStatus::Active.should_reject());
        assert!(!BadgeStatus::Warning.should_reject());
        assert!(!BadgeStatus::Deprecated.should_reject());
        assert!(BadgeStatus::Expired.should_reject());
        assert!(BadgeStatus::Revoked.should_reject());
        assert!(!BadgeStatus::Unknown.should_reject());
    }

    #[test]
    fn unknown_status_is_distinct_from_unrecognized_status() {
        assert_eq!(
            serde_json::from_str::<BadgeStatus>("\"UNKNOWN\"").unwrap(),
            BadgeStatus::Unknown
        );
        assert!(serde_json::from_str::<BadgeStatus>("\"FUTURE_TERMINAL_STATUS\"").is_err());
    }

    #[test]
    fn unfamiliar_event_type_round_trips() {
        let json = "\"AGENT_FUTURE_EVENT\"";
        let event: EventType = serde_json::from_str(json).unwrap();
        assert_eq!(event, EventType::Other("AGENT_FUTURE_EVENT".into()));
        assert_eq!(serde_json::to_string(&event).unwrap(), json);
    }

    #[test]
    fn test_deserialize_badge() {
        let json = r#"{
            "status": "ACTIVE",
            "payload": {
                "logId": "019be7f3-5720-77c9-9672-adae3394502f",
                "producer": {
                    "event": {
                        "ansId": "7b93c61c-e261-488c-89a3-f948119be0a0",
                        "ansName": "ans://v1.0.0.agent.example.com",
                        "eventType": "AGENT_REGISTERED",
                        "agent": {
                            "host": "agent.example.com",
                            "name": "Test Agent",
                            "version": "v1.0.0"
                        },
                        "attestations": {
                            "domainValidation": "ACME-DNS-01",
                            "identityCert": {
                                "fingerprint": "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496",
                                "type": "X509-OV-CLIENT"
                            },
                            "serverCert": {
                                "fingerprint": "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
                                "type": "X509-DV-SERVER"
                            }
                        },
                        "expiresAt": "2027-01-22T22:58:52.000000Z",
                        "issuedAt": "2026-01-22T22:58:51.839533Z",
                        "raId": "gd-ra-us-west-2-ote-db21525-9ffa069a429b4a938e09d1e3e701958c",
                        "timestamp": "2026-01-22T23:04:02.890851Z"
                    },
                    "keyId": "ra-gd-ra-us-west-2-ote",
                    "signature": "eyJhbGci..."
                }
            },
            "schemaVersion": "V1"
        }"#;

        let badge: Badge = serde_json::from_str(json).unwrap();
        assert_eq!(badge.status, BadgeStatus::Active);
        assert_eq!(badge.agent_host(), "agent.example.com");
        assert_eq!(badge.agent_version(), "v1.0.0");
        assert!(badge.server_cert_fingerprint().starts_with("SHA256:"));
    }
}
