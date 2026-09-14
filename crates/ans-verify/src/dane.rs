//! DANE/TLSA verification for certificate binding to DNS.
//!
//! DANE (DNS-Based Authentication of Named Entities) binds certificates to DNS names
//! via TLSA records, providing additional verification independent of the transparency log.

use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

use crate::error::DaneError;
use crate::verify::CertIdentity;
use ans_types::{CertFingerprint, Fqdn};

/// DANE verification policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum DanePolicy {
    /// Never check TLSA records (skip DANE verification entirely).
    #[default]
    Disabled,

    /// Validate TLSA records if present; skip if not found.
    /// This is a permissive mode that adds security when available.
    ValidateIfPresent,

    /// Require TLSA records to exist and validate.
    /// Connections are rejected if TLSA records are missing or don't match.
    Required,
}

impl DanePolicy {
    /// Check if DANE verification should be performed.
    pub fn should_verify(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Check if TLSA records are required.
    pub fn is_required(&self) -> bool {
        matches!(self, Self::Required)
    }
}

/// TLSA certificate usage field values (RFC 6698).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum TlsaUsage {
    /// CA constraint (PKIX-TA)
    CaConstraint = 0,
    /// Service certificate constraint (PKIX-EE)
    ServiceCertificateConstraint = 1,
    /// Trust anchor assertion (DANE-TA)
    TrustAnchorAssertion = 2,
    /// Domain-issued certificate (DANE-EE) - most common for ANS
    DomainIssuedCertificate = 3,
}

impl TryFrom<u8> for TlsaUsage {
    type Error = DaneError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CaConstraint),
            1 => Ok(Self::ServiceCertificateConstraint),
            2 => Ok(Self::TrustAnchorAssertion),
            3 => Ok(Self::DomainIssuedCertificate),
            _ => Err(DaneError::InvalidRecord {
                reason: format!("invalid TLSA usage: {value}"),
            }),
        }
    }
}

/// TLSA selector field values (RFC 6698).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum TlsaSelector {
    /// Full certificate
    FullCertificate = 0,
    /// `SubjectPublicKeyInfo`
    SubjectPublicKeyInfo = 1,
}

impl TryFrom<u8> for TlsaSelector {
    type Error = DaneError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::FullCertificate),
            1 => Ok(Self::SubjectPublicKeyInfo),
            _ => Err(DaneError::InvalidRecord {
                reason: format!("invalid TLSA selector: {value}"),
            }),
        }
    }
}

/// TLSA matching type field values (RFC 6698).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum TlsaMatchingType {
    /// No hash - exact match
    NoHash = 0,
    /// SHA-256 hash
    Sha256 = 1,
    /// SHA-512 hash
    Sha512 = 2,
}

impl TryFrom<u8> for TlsaMatchingType {
    type Error = DaneError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NoHash),
            1 => Ok(Self::Sha256),
            2 => Ok(Self::Sha512),
            _ => Err(DaneError::InvalidRecord {
                reason: format!("invalid TLSA matching type: {value}"),
            }),
        }
    }
}

/// A parsed TLSA record.
///
/// Format: `_port._tcp.hostname IN TLSA usage selector matching_type certificate_data`
///
/// Example: `_443._tcp.agent.example.com IN TLSA 3 0 1 <sha256-fingerprint>`
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TlsaRecord {
    /// Certificate usage (0-3)
    pub usage: TlsaUsage,
    /// Selector (0=full cert, 1=SPKI)
    pub selector: TlsaSelector,
    /// Matching type (0=exact, 1=SHA-256, 2=SHA-512)
    pub matching_type: TlsaMatchingType,
    /// Certificate association data (fingerprint or raw data)
    pub certificate_data: Vec<u8>,
}

impl TlsaRecord {
    /// Create a new TLSA record from components.
    pub fn new(
        usage: TlsaUsage,
        selector: TlsaSelector,
        matching_type: TlsaMatchingType,
        certificate_data: Vec<u8>,
    ) -> Self {
        Self {
            usage,
            selector,
            matching_type,
            certificate_data,
        }
    }

    /// Parse a TLSA record from raw RDATA bytes.
    pub fn from_rdata(rdata: &[u8]) -> Result<Self, DaneError> {
        if rdata.len() < 4 {
            return Err(DaneError::InvalidRecord {
                reason: "TLSA record too short".to_string(),
            });
        }

        let usage = TlsaUsage::try_from(rdata[0])?;
        let selector = TlsaSelector::try_from(rdata[1])?;
        let matching_type = TlsaMatchingType::try_from(rdata[2])?;
        let certificate_data = rdata[3..].to_vec();

        Ok(Self {
            usage,
            selector,
            matching_type,
            certificate_data,
        })
    }

    /// Check if this TLSA record is in a format the fingerprint-only path
    /// can verify: DANE-EE (usage=3), full certificate (selector=0),
    /// SHA-256 (`matching_type=1`), the form the ANS RA emits.
    ///
    /// [`Self::matches_cert`] evaluates every selector and matching type
    /// when the certificate DER is available; see [`Self::is_evaluable`].
    pub fn is_verifiable(&self) -> bool {
        self.usage == TlsaUsage::DomainIssuedCertificate
            && self.selector == TlsaSelector::FullCertificate
            && self.matching_type == TlsaMatchingType::Sha256
    }

    /// Check if this TLSA record can be evaluated against a certificate
    /// whose DER is known: DANE-EE (usage=3) with any selector (full
    /// certificate or `SubjectPublicKeyInfo`) and any matching type
    /// (exact, SHA-256, SHA-512), per RFC 6698 §2.1.
    pub fn is_evaluable(&self) -> bool {
        self.usage == TlsaUsage::DomainIssuedCertificate
    }

    /// Check if this TLSA record matches a certificate, honoring the
    /// record's selector and matching type (RFC 6698 §2.1.2–2.1.3).
    ///
    /// When the identity carries its DER (built via
    /// [`CertIdentity::from_der`]), the association data is recomputed for
    /// the record's own selector — the full certificate for selector 0, the
    /// `SubjectPublicKeyInfo` for selector 1 — and matching type, so a
    /// `3 1 1` record (the renewal-stable form RFC 7671 §5.1 recommends) is
    /// compared against the SPKI hash and never against the full-certificate
    /// fingerprint, and vice versa.
    ///
    /// An identity built from a bare fingerprint has no DER to select from,
    /// so it falls back to [`Self::matches_fingerprint`]: the pre-existing
    /// `3 0 1`-only comparison, unchanged, so fingerprint-only callers do not
    /// regress.
    ///
    /// Returns `None` when the record cannot be evaluated (usage other than
    /// DANE-EE), as distinct from `Some(false)` for a record that was
    /// evaluated and did not match.
    pub fn matches_cert(&self, cert: &CertIdentity) -> Option<bool> {
        let (Some(raw_der), Some(spki_der)) = (cert.raw_der(), cert.spki_der()) else {
            return self.matches_fingerprint(cert.fingerprint());
        };

        if self.usage != TlsaUsage::DomainIssuedCertificate {
            tracing::debug!(
                usage = ?self.usage,
                "TLSA usage is not DANE-EE, cannot verify"
            );
            return None;
        }

        let selected: &[u8] = match self.selector {
            TlsaSelector::FullCertificate => raw_der,
            TlsaSelector::SubjectPublicKeyInfo => spki_der,
        };
        let expected: Vec<u8> = match self.matching_type {
            TlsaMatchingType::NoHash => selected.to_vec(),
            TlsaMatchingType::Sha256 => Sha256::digest(selected).to_vec(),
            TlsaMatchingType::Sha512 => Sha512::digest(selected).to_vec(),
        };

        // Constant-time equality; a length mismatch is a plain mismatch
        // (lengths are not secret).
        let matches = self.certificate_data.len() == expected.len()
            && bool::from(self.certificate_data.ct_eq(&expected));

        tracing::debug!(
            selector = ?self.selector,
            matching_type = ?self.matching_type,
            tlsa_data = %hex::encode(&self.certificate_data),
            cert_data = %hex::encode(&expected),
            matches,
            "TLSA association comparison"
        );

        Some(matches)
    }

    /// Check if this TLSA record matches a certificate fingerprint.
    ///
    /// Fingerprint-only path: supports DANE-EE (usage=3), full certificate
    /// (selector=0), SHA-256 (`matching_type=1`), the form the ANS RA emits.
    /// Prefer [`Self::matches_cert`] when the certificate DER is available;
    /// it evaluates SPKI (selector=1) and the other matching types too.
    ///
    /// Returns `None` if the record format is not supported (different from not matching).
    pub fn matches_fingerprint(&self, cert_fingerprint: &CertFingerprint) -> Option<bool> {
        // ANS uses: DANE-EE (3), Full Certificate (0), SHA-256 (1)
        if self.usage != TlsaUsage::DomainIssuedCertificate {
            tracing::debug!(
                usage = ?self.usage,
                "TLSA usage is not DANE-EE, cannot verify"
            );
            return None;
        }

        if self.selector != TlsaSelector::FullCertificate {
            tracing::debug!(
                selector = ?self.selector,
                "TLSA selector is not full certificate (SPKI not yet supported), cannot verify"
            );
            return None;
        }

        if self.matching_type != TlsaMatchingType::Sha256 {
            tracing::debug!(
                matching_type = ?self.matching_type,
                "TLSA matching type is not SHA-256, cannot verify"
            );
            return None;
        }

        // Compare raw bytes using constant-time equality to prevent timing side-channels.
        // Both sides are SHA-256 hashes (32 bytes). If the TLSA data has wrong length,
        // the comparison fails (not a timing concern since length is not secret).
        let cert_bytes = cert_fingerprint.as_bytes();
        let matches = self.certificate_data.len() == cert_bytes.len()
            && bool::from(self.certificate_data.ct_eq(cert_bytes.as_slice()));

        tracing::debug!(
            tlsa_fingerprint = %hex::encode(&self.certificate_data),
            cert_fingerprint = %cert_fingerprint,
            matches,
            "TLSA fingerprint comparison"
        );

        Some(matches)
    }
}

/// Result of DANE verification.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DaneVerificationResult {
    /// TLSA record matched the certificate.
    Verified {
        /// The TLSA record that matched.
        matched_record: TlsaRecord,
    },
    /// No TLSA records found (not an error if policy is `ValidateIfPresent`).
    NoRecords,
    /// TLSA records found but none matched.
    Mismatch {
        /// Number of TLSA records checked.
        records_checked: usize,
    },
    /// DNSSEC validation failed.
    DnssecFailed,
    /// Verification was skipped (policy is Disabled).
    Skipped,
}

impl DaneVerificationResult {
    /// Check if verification passed or was appropriately skipped.
    pub fn is_acceptable(&self, policy: DanePolicy) -> bool {
        match self {
            Self::Verified { .. } | Self::Skipped => true,
            Self::NoRecords => !policy.is_required(),
            Self::Mismatch { .. } | Self::DnssecFailed => false,
        }
    }
}

/// Verify a certificate against TLSA records.
pub fn verify_dane(
    records: &[TlsaRecord],
    cert_fingerprint: &CertFingerprint,
    policy: DanePolicy,
    fqdn: &Fqdn,
    port: u16,
) -> Result<DaneVerificationResult, DaneError> {
    verify_dane_with(
        records,
        policy,
        fqdn,
        port,
        |record| record.matches_fingerprint(cert_fingerprint),
        "TLSA record format not supported (only usage=3, selector=0, matching_type=1)",
    )
}

/// Verify a certificate against TLSA records, honoring each record's
/// selector and matching type.
///
/// Same policy semantics as [`verify_dane`], but each record is evaluated
/// with [`TlsaRecord::matches_cert`]: when `cert` carries its DER, a
/// `3 1 1` (SPKI) record is checked against the certificate's
/// `SubjectPublicKeyInfo` hash and a `3 0 1` record against the full
/// certificate, so an operator may publish either form (or both) and be
/// verified by whichever matches. Only records with a usage other than
/// DANE-EE remain unsupported. A `cert` without DER behaves exactly like
/// [`verify_dane`].
///
/// # Errors
/// As [`verify_dane`].
pub fn verify_dane_cert(
    records: &[TlsaRecord],
    cert: &CertIdentity,
    policy: DanePolicy,
    fqdn: &Fqdn,
    port: u16,
) -> Result<DaneVerificationResult, DaneError> {
    let unsupported = if cert.raw_der().is_some() {
        "TLSA record format not supported (only usage=3 DANE-EE records are evaluated)"
    } else {
        "TLSA record format not supported (only usage=3, selector=0, matching_type=1)"
    };
    verify_dane_with(
        records,
        policy,
        fqdn,
        port,
        |record| record.matches_cert(cert),
        unsupported,
    )
}

/// Shared policy/iteration core for [`verify_dane`] and [`verify_dane_cert`].
/// `matches` returns `Some(true)` on a match, `Some(false)` on an evaluated
/// non-match, and `None` when the record cannot be evaluated at all.
fn verify_dane_with(
    records: &[TlsaRecord],
    policy: DanePolicy,
    fqdn: &Fqdn,
    port: u16,
    matches: impl Fn(&TlsaRecord) -> Option<bool>,
    unsupported_reason: &str,
) -> Result<DaneVerificationResult, DaneError> {
    if !policy.should_verify() {
        tracing::debug!("DANE verification disabled by policy");
        return Ok(DaneVerificationResult::Skipped);
    }

    if records.is_empty() {
        tracing::debug!(fqdn = %fqdn, port, "No TLSA records found");
        if policy.is_required() {
            return Err(DaneError::NoTlsaRecords {
                fqdn: fqdn.to_string(),
                port,
            });
        }
        return Ok(DaneVerificationResult::NoRecords);
    }

    tracing::debug!(
        fqdn = %fqdn,
        port,
        record_count = records.len(),
        "Checking TLSA records"
    );

    // Check each TLSA record
    let mut has_unsupported = false;

    for record in records {
        match matches(record) {
            Some(true) => {
                tracing::info!(
                    fqdn = %fqdn,
                    port,
                    "DANE verification PASSED - certificate matches TLSA record"
                );
                return Ok(DaneVerificationResult::Verified {
                    matched_record: record.clone(),
                });
            }
            Some(false) => {
                tracing::debug!("TLSA record checked but did not match");
            }
            None => {
                // Record is in unsupported format (e.g., SPKI selector)
                has_unsupported = true;
                tracing::warn!(
                    usage = ?record.usage,
                    selector = ?record.selector,
                    matching_type = ?record.matching_type,
                    "TLSA record in unsupported format"
                );
            }
        }
    }

    // If records exist but none matched, fail
    // This includes both: records in supported format that didn't match,
    // AND records in unsupported format (we can't verify them, so we fail)
    if has_unsupported {
        tracing::error!(
            fqdn = %fqdn,
            port,
            reason = unsupported_reason,
            "DANE verification FAILED - TLSA records present but in unsupported format"
        );
        return Err(DaneError::InvalidRecord {
            reason: unsupported_reason.to_string(),
        });
    }

    tracing::warn!(
        fqdn = %fqdn,
        port,
        records_checked = records.len(),
        "DANE verification FAILED - no TLSA record matched certificate"
    );

    Err(DaneError::FingerprintMismatch)
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dane_policy_defaults_to_disabled() {
        assert_eq!(DanePolicy::default(), DanePolicy::Disabled);
    }

    #[test]
    fn test_dane_policy_should_verify() {
        assert!(!DanePolicy::Disabled.should_verify());
        assert!(DanePolicy::ValidateIfPresent.should_verify());
        assert!(DanePolicy::Required.should_verify());
    }

    #[test]
    fn test_dane_policy_is_required() {
        assert!(!DanePolicy::Disabled.is_required());
        assert!(!DanePolicy::ValidateIfPresent.is_required());
        assert!(DanePolicy::Required.is_required());
    }

    #[test]
    fn test_tlsa_record_from_rdata() {
        // Usage=3, Selector=0, MatchingType=1, followed by SHA-256 hash
        let mut rdata = vec![3, 0, 1];
        let hash = hex::decode("e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
            .unwrap();
        rdata.extend(&hash);

        let record = TlsaRecord::from_rdata(&rdata).unwrap();
        assert_eq!(record.usage, TlsaUsage::DomainIssuedCertificate);
        assert_eq!(record.selector, TlsaSelector::FullCertificate);
        assert_eq!(record.matching_type, TlsaMatchingType::Sha256);
        assert_eq!(record.certificate_data, hash);
    }

    #[test]
    fn test_tlsa_record_matches_fingerprint() {
        let hash = hex::decode("e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
            .unwrap();

        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            hash,
        );

        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        assert_eq!(record.matches_fingerprint(&fingerprint), Some(true));
    }

    #[test]
    fn test_tlsa_record_does_not_match_different_fingerprint() {
        let hash = hex::decode("e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
            .unwrap();

        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            hash,
        );

        let fingerprint = CertFingerprint::parse(
            "SHA256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        assert_eq!(record.matches_fingerprint(&fingerprint), Some(false));
    }

    #[test]
    fn test_tlsa_record_unsupported_format_returns_none() {
        let hash = hex::decode("e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
            .unwrap();

        // SPKI selector is not supported
        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
            hash,
        );

        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        // Should return None because format is not supported
        assert_eq!(record.matches_fingerprint(&fingerprint), None);
    }

    #[test]
    fn test_verify_dane_disabled() {
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        let result = verify_dane(&[], &fingerprint, DanePolicy::Disabled, &fqdn, 443).unwrap();
        assert!(matches!(result, DaneVerificationResult::Skipped));
    }

    #[test]
    fn test_verify_dane_no_records_validate_if_present() {
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        let result =
            verify_dane(&[], &fingerprint, DanePolicy::ValidateIfPresent, &fqdn, 443).unwrap();
        assert!(matches!(result, DaneVerificationResult::NoRecords));
        assert!(result.is_acceptable(DanePolicy::ValidateIfPresent));
    }

    #[test]
    fn test_verify_dane_no_records_required() {
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        let result = verify_dane(&[], &fingerprint, DanePolicy::Required, &fqdn, 443);
        assert!(matches!(result, Err(DaneError::NoTlsaRecords { .. })));
    }

    #[test]
    fn test_verify_dane_match() {
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let hash = hex::decode("e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
            .unwrap();

        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            hash,
        );

        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        let result =
            verify_dane(&[record], &fingerprint, DanePolicy::Required, &fqdn, 443).unwrap();
        assert!(matches!(result, DaneVerificationResult::Verified { .. }));
    }

    #[test]
    fn test_verify_dane_mismatch() {
        let fqdn = Fqdn::new("test.example.com").unwrap();
        let hash = hex::decode("e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
            .unwrap();

        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            hash,
        );

        let fingerprint = CertFingerprint::parse(
            "SHA256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let result = verify_dane(&[record], &fingerprint, DanePolicy::Required, &fqdn, 443);
        assert!(matches!(result, Err(DaneError::FingerprintMismatch)));
    }

    #[test]
    fn test_verification_result_is_acceptable() {
        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            vec![0; 32],
        );

        // Verified is always acceptable
        let verified = DaneVerificationResult::Verified {
            matched_record: record,
        };
        assert!(verified.is_acceptable(DanePolicy::Disabled));
        assert!(verified.is_acceptable(DanePolicy::ValidateIfPresent));
        assert!(verified.is_acceptable(DanePolicy::Required));

        // NoRecords is acceptable unless Required
        let no_records = DaneVerificationResult::NoRecords;
        assert!(no_records.is_acceptable(DanePolicy::Disabled));
        assert!(no_records.is_acceptable(DanePolicy::ValidateIfPresent));
        assert!(!no_records.is_acceptable(DanePolicy::Required));

        // Skipped is always acceptable
        let skipped = DaneVerificationResult::Skipped;
        assert!(skipped.is_acceptable(DanePolicy::Disabled));
        assert!(skipped.is_acceptable(DanePolicy::ValidateIfPresent));
        assert!(skipped.is_acceptable(DanePolicy::Required));

        // Mismatch is never acceptable
        let mismatch = DaneVerificationResult::Mismatch { records_checked: 1 };
        assert!(!mismatch.is_acceptable(DanePolicy::Disabled));
        assert!(!mismatch.is_acceptable(DanePolicy::ValidateIfPresent));
        assert!(!mismatch.is_acceptable(DanePolicy::Required));
    }

    // ── TlsaRecord::from_rdata edge cases ────────────────────────────

    #[test]
    fn test_tlsa_from_rdata_too_short() {
        let result = TlsaRecord::from_rdata(&[3, 0]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DaneError::InvalidRecord { .. }
        ));
    }

    #[test]
    fn test_tlsa_from_rdata_empty() {
        let result = TlsaRecord::from_rdata(&[]);
        assert!(result.is_err());
    }

    // ── TryFrom<u8> invalid values ───────────────────────────────────

    #[test]
    fn test_tlsa_usage_invalid() {
        let result = TlsaUsage::try_from(4_u8);
        assert!(result.is_err());
    }

    #[test]
    fn test_tlsa_selector_invalid() {
        let result = TlsaSelector::try_from(2_u8);
        assert!(result.is_err());
    }

    #[test]
    fn test_tlsa_matching_type_invalid() {
        let result = TlsaMatchingType::try_from(3_u8);
        assert!(result.is_err());
    }

    // ── is_verifiable ────────────────────────────────────────────────

    #[test]
    fn test_is_verifiable_true() {
        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            vec![0; 32],
        );
        assert!(record.is_verifiable());
    }

    #[test]
    fn test_is_verifiable_wrong_usage() {
        let record = TlsaRecord::new(
            TlsaUsage::CaConstraint,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            vec![0; 32],
        );
        assert!(!record.is_verifiable());
    }

    #[test]
    fn test_is_verifiable_wrong_selector() {
        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
            vec![0; 32],
        );
        assert!(!record.is_verifiable());
    }

    #[test]
    fn test_is_verifiable_wrong_matching_type() {
        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha512,
            vec![0; 64],
        );
        assert!(!record.is_verifiable());
    }

    // ── matches_fingerprint edge cases ───────────────────────────────

    #[test]
    fn test_matches_fingerprint_non_dane_ee() {
        let hash = vec![0u8; 32];
        let record = TlsaRecord::new(
            TlsaUsage::CaConstraint,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            hash,
        );
        let fp = CertFingerprint::from_bytes([0u8; 32]);
        assert_eq!(record.matches_fingerprint(&fp), None);
    }

    #[test]
    fn test_matches_fingerprint_non_sha256() {
        let hash = vec![0u8; 64];
        let record = TlsaRecord::new(
            TlsaUsage::DomainIssuedCertificate,
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha512,
            hash,
        );
        let fp = CertFingerprint::from_bytes([0u8; 32]);
        assert_eq!(record.matches_fingerprint(&fp), None);
    }

    // ── DaneVerificationResult::DnssecFailed ─────────────────────────

    #[test]
    fn test_dnssec_failed_is_not_acceptable() {
        let result = DaneVerificationResult::DnssecFailed;
        assert!(!result.is_acceptable(DanePolicy::Disabled));
        assert!(!result.is_acceptable(DanePolicy::ValidateIfPresent));
        assert!(!result.is_acceptable(DanePolicy::Required));
    }

    // ── matches_cert / verify_dane_cert: selector + matching type ────

    /// A self-signed test certificate as DER, plus its SubjectPublicKeyInfo
    /// DER derived independently of the code under test (x509-parser).
    fn test_cert() -> (Vec<u8>, Vec<u8>) {
        use rcgen::{CertificateParams, DnType, KeyPair};
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "dane.agent.local");
        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der().to_vec();
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
        let spki = parsed.tbs_certificate.subject_pki.raw.to_vec();
        (der, spki)
    }

    fn record(selector: TlsaSelector, mt: TlsaMatchingType, data: Vec<u8>) -> TlsaRecord {
        TlsaRecord::new(TlsaUsage::DomainIssuedCertificate, selector, mt, data)
    }

    #[test]
    fn test_matches_cert_spki_sha256() {
        let (der, spki) = test_cert();
        let cert = CertIdentity::from_der(&der).unwrap();
        // 3 1 1 — the renewal-stable form (RFC 7671 §5.1).
        let rec = record(
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
            Sha256::digest(&spki).to_vec(),
        );
        assert_eq!(rec.matches_cert(&cert), Some(true));
        assert!(rec.is_evaluable());
        assert!(
            !rec.is_verifiable(),
            "fingerprint-only path still declines 3 1 1"
        );
    }

    #[test]
    fn test_matches_cert_spki_hash_never_matches_full_cert_hash() {
        let (der, _spki) = test_cert();
        let cert = CertIdentity::from_der(&der).unwrap();
        // A 3 1 1 record carrying the FULL-CERT hash must not match: the
        // selector says SPKI, so that is what gets compared.
        let rec = record(
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
            cert.fingerprint().as_bytes().to_vec(),
        );
        assert_eq!(rec.matches_cert(&cert), Some(false));
    }

    #[test]
    fn test_matches_cert_full_cert_sha256_and_sha512() {
        let (der, _spki) = test_cert();
        let cert = CertIdentity::from_der(&der).unwrap();
        let r301 = record(
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            Sha256::digest(&der).to_vec(),
        );
        let r302 = record(
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha512,
            Sha512::digest(&der).to_vec(),
        );
        assert_eq!(r301.matches_cert(&cert), Some(true));
        assert_eq!(r302.matches_cert(&cert), Some(true));
    }

    #[test]
    fn test_matches_cert_exact_spki() {
        let (der, spki) = test_cert();
        let cert = CertIdentity::from_der(&der).unwrap();
        // 3 1 0 — matching type 0 compares the raw selected data.
        let rec = record(
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::NoHash,
            spki.clone(),
        );
        assert_eq!(rec.matches_cert(&cert), Some(true));
        let mut wrong = spki;
        wrong[0] ^= 0xff;
        let rec = record(
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::NoHash,
            wrong,
        );
        assert_eq!(rec.matches_cert(&cert), Some(false));
    }

    #[test]
    fn test_matches_cert_non_dane_ee_usage_is_unsupported() {
        let (der, spki) = test_cert();
        let cert = CertIdentity::from_der(&der).unwrap();
        let mut rec = record(
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
            Sha256::digest(&spki).to_vec(),
        );
        assert_eq!(rec.matches_cert(&cert), Some(true));
        rec.usage = TlsaUsage::TrustAnchorAssertion;
        assert_eq!(rec.matches_cert(&cert), None);
    }

    #[test]
    fn test_matches_cert_without_der_falls_back_to_fingerprint_path() {
        let (der, spki) = test_cert();
        let fp = CertFingerprint::from_der(&der);
        let cert = CertIdentity::from_fingerprint_and_cn(fp, "dane.agent.local".to_string());
        assert!(cert.raw_der().is_none() && cert.spki_der().is_none());
        // Same 3 1 1 record: without DER there is nothing to select from,
        // so the pre-existing fingerprint-only answer (unsupported) stands.
        let r311 = record(
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
            Sha256::digest(&spki).to_vec(),
        );
        assert_eq!(r311.matches_cert(&cert), None);
        let r301 = record(
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            Sha256::digest(&der).to_vec(),
        );
        assert_eq!(r301.matches_cert(&cert), Some(true));
    }

    #[test]
    fn test_verify_dane_cert_spki_record_verifies() {
        let (der, spki) = test_cert();
        let cert = CertIdentity::from_der(&der).unwrap();
        let fqdn = Fqdn::new("dane.agent.local").unwrap();
        let r311 = record(
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
            Sha256::digest(&spki).to_vec(),
        );
        let result =
            verify_dane_cert(&[r311.clone()], &cert, DanePolicy::Required, &fqdn, 443).unwrap();
        assert!(matches!(
            result,
            DaneVerificationResult::Verified { ref matched_record } if *matched_record == r311
        ));
    }

    #[test]
    fn test_verify_dane_cert_publishing_both_forms_verifies_by_either() {
        // The ans#105 deployment shape: a 3 0 1 (RA-required) row that has
        // gone stale after renewal, beside a 3 1 1 row that survived it.
        let (der, spki) = test_cert();
        let cert = CertIdentity::from_der(&der).unwrap();
        let fqdn = Fqdn::new("dane.agent.local").unwrap();
        let stale_301 = record(
            TlsaSelector::FullCertificate,
            TlsaMatchingType::Sha256,
            vec![0; 32],
        );
        let live_311 = record(
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
            Sha256::digest(&spki).to_vec(),
        );
        let result = verify_dane_cert(
            &[stale_301, live_311.clone()],
            &cert,
            DanePolicy::Required,
            &fqdn,
            443,
        )
        .unwrap();
        assert!(matches!(
            result,
            DaneVerificationResult::Verified { ref matched_record } if *matched_record == live_311
        ));
    }

    #[test]
    fn test_verify_dane_cert_spki_mismatch_is_mismatch_not_unsupported() {
        let (der, _spki) = test_cert();
        let cert = CertIdentity::from_der(&der).unwrap();
        let fqdn = Fqdn::new("dane.agent.local").unwrap();
        let wrong_311 = record(
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
            vec![0; 32],
        );
        // Evaluated and rejected: a fingerprint mismatch, not the
        // "unsupported format" error the fingerprint-only path raises for 3 1 1.
        let result = verify_dane_cert(&[wrong_311], &cert, DanePolicy::Required, &fqdn, 443);
        assert!(matches!(result, Err(DaneError::FingerprintMismatch)));
    }

    #[test]
    fn test_verify_dane_cert_without_der_keeps_legacy_unsupported_error() {
        let (der, spki) = test_cert();
        let fp = CertFingerprint::from_der(&der);
        let cert = CertIdentity::from_fingerprint_and_cn(fp, "dane.agent.local".to_string());
        let fqdn = Fqdn::new("dane.agent.local").unwrap();
        let r311 = record(
            TlsaSelector::SubjectPublicKeyInfo,
            TlsaMatchingType::Sha256,
            Sha256::digest(&spki).to_vec(),
        );
        let result = verify_dane_cert(&[r311], &cert, DanePolicy::Required, &fqdn, 443);
        assert!(matches!(result, Err(DaneError::InvalidRecord { .. })));
    }
}
