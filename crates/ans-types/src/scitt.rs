//! SCITT (Supply Chain Integrity, Transparency, and Trust) shared types.
//!
//! These are pure data types with no crypto library dependencies. They live in
//! `ans-types` (not feature-gated) so all consumers can inspect SCITT metadata
//! without pulling in `ciborium` or `p256`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::badge::BadgeStatus;
use crate::fingerprint::CertFingerprint;
use crate::types::AnsName;

/// Which verification tier produced the verification result.
///
/// Ordered by assurance level: `BadgeOnly` < `StatusTokenVerified` < `FullScitt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum VerificationTier {
    /// Traditional: DNS + transparency log badge only.
    BadgeOnly,
    /// Status token verified (signed current-status claim).
    /// Sufficient for live connection verification.
    StatusTokenVerified,
    /// Both receipt and status token verified offline.
    /// Highest assurance: proves both historical inclusion and current status.
    FullScitt,
}

impl VerificationTier {
    /// Returns `true` if this tier includes SCITT verification
    /// (status token and/or receipt).
    pub fn is_scitt(&self) -> bool {
        matches!(self, Self::StatusTokenVerified | Self::FullScitt)
    }

    /// Returns `true` if this tier includes a verified receipt
    /// proving append-only log inclusion.
    pub fn has_receipt(&self) -> bool {
        matches!(self, Self::FullScitt)
    }
}

impl std::fmt::Display for VerificationTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadgeOnly => write!(f, "BadgeOnly"),
            Self::StatusTokenVerified => write!(f, "StatusTokenVerified"),
            Self::FullScitt => write!(f, "FullScitt"),
        }
    }
}

/// Certificate type for status token cert entries.
///
/// Constrains the `cert_type` field to known values, preventing typos or
/// attacker-supplied garbage from bypassing cert-type-based verification logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CertType {
    /// X.509 Domain-Validated server certificate.
    #[serde(rename = "X509-DV-SERVER")]
    X509DvServer,
    /// X.509 Organization-Validated client certificate (mTLS identity).
    #[serde(rename = "X509-OV-CLIENT")]
    X509OvClient,
}

impl std::str::FromStr for CertType {
    type Err = String;

    /// Case-insensitive: ANS-6 §4.4 — implementations have emitted the CBOR
    /// form in lowercase, so consumers compare the type case-insensitively.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "X509-DV-SERVER" => Ok(Self::X509DvServer),
            "X509-OV-CLIENT" => Ok(Self::X509OvClient),
            other => Err(format!("unknown cert_type: {other}")),
        }
    }
}

impl std::fmt::Display for CertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X509DvServer => write!(f, "X509-DV-SERVER"),
            Self::X509OvClient => write!(f, "X509-OV-CLIENT"),
        }
    }
}

/// One entry in a status token's certificate fingerprint array.
///
/// Each status token contains arrays of valid server and identity certificates.
/// During verification, the presented certificate must match at least one entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CertEntry {
    /// Certificate fingerprint in `SHA256:<hex>` format.
    pub fingerprint: CertFingerprint,
    /// Certificate type.
    pub cert_type: CertType,
}

impl CertEntry {
    /// Create a new certificate entry.
    pub fn new(fingerprint: CertFingerprint, cert_type: CertType) -> Self {
        Self {
            fingerprint,
            cert_type,
        }
    }
}

impl StatusTokenPayload {
    /// Create a new status token payload.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agent_id: Uuid,
        status: BadgeStatus,
        iat: i64,
        exp: i64,
        ans_name: AnsName,
        valid_identity_certs: Vec<CertEntry>,
        valid_server_certs: Vec<CertEntry>,
        metadata_hashes: BTreeMap<String, String>,
    ) -> Self {
        Self {
            agent_id,
            status,
            iat,
            exp,
            ans_name,
            valid_identity_certs,
            valid_server_certs,
            metadata_hashes,
        }
    }
}

/// Decoded payload of a SCITT status token (after COSE signature verification).
///
/// Status tokens are `COSE_Sign1` structures with CBOR integer-keyed payloads.
/// The CBOR keys (1-8) map to the fields below. The token is time-bounded
/// by the `iat` (issued-at) and `exp` (expiry) Unix timestamps.
///
/// This struct is deserialized from CBOR by the `scitt` module in `ans-verify`.
/// It is placed here in `ans-types` because it has no crypto dependencies —
/// only standard serde types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct StatusTokenPayload {
    /// Agent's unique ID (CBOR key 1).
    pub agent_id: Uuid,
    /// Current agent status (CBOR key 2). Reuses the existing `BadgeStatus` enum.
    pub status: BadgeStatus,
    /// Issued-at timestamp as Unix seconds (CBOR key 3).
    pub iat: i64,
    /// Expiry timestamp as Unix seconds (CBOR key 4).
    pub exp: i64,
    /// Full ANS name, e.g. `"ans://v1.0.0.agent.example.com"` (CBOR key 5).
    ///
    /// Validated at deserialization time — always a well-formed ANS URI.
    pub ans_name: AnsName,
    /// Valid identity certificates for mTLS verification (CBOR key 6).
    pub valid_identity_certs: Vec<CertEntry>,
    /// Valid server certificates for TLS verification (CBOR key 7).
    pub valid_server_certs: Vec<CertEntry>,
    /// Optional metadata hashes (CBOR key 8).
    /// `BTreeMap` for deterministic serialization ordering.
    pub metadata_hashes: BTreeMap<String, String>,
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_type_parse_is_case_insensitive() {
        assert_eq!(
            "x509-ov-client".parse::<CertType>().unwrap(),
            CertType::X509OvClient
        );
        assert_eq!(
            "X509-DV-Server".parse::<CertType>().unwrap(),
            CertType::X509DvServer
        );
        assert!("X509-EV-SERVER".parse::<CertType>().is_err());
    }

    #[test]
    fn verification_tier_is_scitt() {
        assert!(!VerificationTier::BadgeOnly.is_scitt());
        assert!(VerificationTier::StatusTokenVerified.is_scitt());
        assert!(VerificationTier::FullScitt.is_scitt());
    }

    #[test]
    fn verification_tier_has_receipt() {
        assert!(!VerificationTier::BadgeOnly.has_receipt());
        assert!(!VerificationTier::StatusTokenVerified.has_receipt());
        assert!(VerificationTier::FullScitt.has_receipt());
    }

    #[test]
    fn verification_tier_display() {
        assert_eq!(VerificationTier::BadgeOnly.to_string(), "BadgeOnly");
        assert_eq!(
            VerificationTier::StatusTokenVerified.to_string(),
            "StatusTokenVerified"
        );
        assert_eq!(VerificationTier::FullScitt.to_string(), "FullScitt");
    }

    #[test]
    fn verification_tier_serde_roundtrip() {
        for tier in [
            VerificationTier::BadgeOnly,
            VerificationTier::StatusTokenVerified,
            VerificationTier::FullScitt,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let deserialized: VerificationTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, deserialized);
        }
    }

    #[test]
    fn verification_tier_equality_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(VerificationTier::BadgeOnly);
        set.insert(VerificationTier::StatusTokenVerified);
        set.insert(VerificationTier::FullScitt);
        set.insert(VerificationTier::BadgeOnly); // duplicate
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn verification_tier_clone_and_copy() {
        let tier = VerificationTier::FullScitt;
        let cloned = tier;
        assert_eq!(tier, cloned); // Copy semantics
    }

    #[test]
    fn cert_entry_new() {
        let fp = CertFingerprint::from_bytes([
            0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xa1, 0xb2,
            0xc3, 0xd4, 0xe5, 0xf6, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xa1, 0xb2, 0xc3, 0xd4,
            0xe5, 0xf6, 0xa1, 0xb2,
        ]);
        let entry = CertEntry::new(fp.clone(), CertType::X509DvServer);
        assert_eq!(entry.fingerprint, fp);
        assert_eq!(entry.cert_type, CertType::X509DvServer);
    }

    #[test]
    fn status_token_payload_serde_roundtrip() {
        let fp = CertFingerprint::from_bytes([
            0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xa1, 0xb2,
            0xc3, 0xd4, 0xe5, 0xf6, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xa1, 0xb2, 0xc3, 0xd4,
            0xe5, 0xf6, 0xa1, 0xb2,
        ]);

        let payload = StatusTokenPayload {
            agent_id: Uuid::nil(),
            status: BadgeStatus::Active,
            iat: 1_700_000_000,
            exp: 1_700_003_600,
            ans_name: AnsName::parse("ans://v1.0.0.agent.example.com").unwrap(),
            valid_identity_certs: vec![CertEntry::new(fp.clone(), CertType::X509OvClient)],
            valid_server_certs: vec![CertEntry::new(fp, CertType::X509DvServer)],
            metadata_hashes: BTreeMap::from([("key".to_string(), "value".to_string())]),
        };

        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: StatusTokenPayload = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.agent_id, payload.agent_id);
        assert_eq!(deserialized.status, payload.status);
        assert_eq!(deserialized.iat, payload.iat);
        assert_eq!(deserialized.exp, payload.exp);
        assert_eq!(deserialized.ans_name, payload.ans_name);
        assert_eq!(deserialized.valid_identity_certs.len(), 1);
        assert_eq!(deserialized.valid_server_certs.len(), 1);
        assert_eq!(deserialized.metadata_hashes.len(), 1);
    }

    #[test]
    fn status_token_payload_empty_cert_arrays() {
        let payload = StatusTokenPayload {
            agent_id: Uuid::nil(),
            status: BadgeStatus::Warning,
            iat: 0,
            exp: 3600,
            ans_name: AnsName::parse("ans://v0.1.0.test.example.com").unwrap(),
            valid_identity_certs: vec![],
            valid_server_certs: vec![],
            metadata_hashes: BTreeMap::new(),
        };

        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: StatusTokenPayload = serde_json::from_str(&json).unwrap();
        assert!(deserialized.valid_identity_certs.is_empty());
        assert!(deserialized.valid_server_certs.is_empty());
        assert!(deserialized.metadata_hashes.is_empty());
    }

    #[test]
    fn status_token_payload_all_statuses() {
        for status in [
            BadgeStatus::Active,
            BadgeStatus::Warning,
            BadgeStatus::Deprecated,
            BadgeStatus::Expired,
            BadgeStatus::Revoked,
        ] {
            let payload = StatusTokenPayload {
                agent_id: Uuid::nil(),
                status,
                iat: 0,
                exp: 3600,
                ans_name: AnsName::parse("ans://v1.0.0.test.example.com").unwrap(),
                valid_identity_certs: vec![],
                valid_server_certs: vec![],
                metadata_hashes: BTreeMap::new(),
            };
            let json = serde_json::to_string(&payload).unwrap();
            let deserialized: StatusTokenPayload = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.status, status);
        }
    }

    #[test]
    fn metadata_hashes_deterministic_ordering() {
        let mut map = BTreeMap::new();
        map.insert("zebra".to_string(), "hash_z".to_string());
        map.insert("alpha".to_string(), "hash_a".to_string());
        map.insert("middle".to_string(), "hash_m".to_string());

        let keys: Vec<&String> = map.keys().collect();
        assert_eq!(keys, vec!["alpha", "middle", "zebra"]);
    }
}
