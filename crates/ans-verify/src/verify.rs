//! Verification logic for ANS trust verification.
//!
//! This module provides:
//! - `ServerVerifier`: For clients verifying servers
//! - `ClientVerifier`: For servers verifying mTLS clients
//! - `AnsVerifier`: High-level facade combining both

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::join_all;

use crate::cache::{BadgeCache, CacheConfig, CacheKey};
use crate::dane::{DanePolicy, DaneVerificationResult, verify_dane};
use crate::dns::{
    BadgeRecord, DnsLookupResult, DnsResolver, DnsResolverConfig, HickoryDnsResolver,
};
use crate::error::{AnsError, AnsResult, DaneError, DnsError, TlogError, VerificationError};
use crate::tlog::{HttpTransparencyLogClient, TransparencyLogClient};
use ans_types::{AnsName, Badge, BadgeStatus, CertFingerprint, CryptoError, Fqdn, Version};

/// Parsed certificate data: (Common Name, DNS SANs, URI SANs).
type ParsedCertData = (Option<String>, Vec<String>, Vec<String>);

/// Extracted identity information from a certificate.
///
/// This struct holds the relevant identity information extracted from
/// an X.509 certificate for ANS verification purposes.
///
/// In production, construct via [`CertIdentity::from_der`]. The [`CertIdentity::new`]
/// and [`CertIdentity::from_fingerprint_and_cn`] constructors are also public
/// for programmatic use and testing.
#[derive(Debug, Clone)]
pub struct CertIdentity {
    /// Common Name (CN) from the certificate subject.
    pub(crate) common_name: Option<String>,
    /// DNS Subject Alternative Names.
    pub(crate) dns_sans: Vec<String>,
    /// URI Subject Alternative Names.
    pub(crate) uri_sans: Vec<String>,
    /// Certificate fingerprint.
    pub(crate) fingerprint: CertFingerprint,
}

impl CertIdentity {
    /// Returns the Common Name (CN) from the certificate subject.
    pub fn common_name(&self) -> Option<&str> {
        self.common_name.as_deref()
    }

    /// Returns the DNS Subject Alternative Names.
    pub fn dns_sans(&self) -> &[String] {
        &self.dns_sans
    }

    /// Returns the URI Subject Alternative Names.
    pub fn uri_sans(&self) -> &[String] {
        &self.uri_sans
    }

    /// Returns the certificate fingerprint.
    pub fn fingerprint(&self) -> &CertFingerprint {
        &self.fingerprint
    }

    /// Create a new `CertIdentity` from components.
    ///
    /// Use this when you've already extracted the certificate information
    /// using your TLS library (e.g., rustls, native-tls, openssl).
    /// If you have DER-encoded bytes, prefer [`CertIdentity::from_der`].
    pub fn new(
        common_name: Option<String>,
        dns_sans: Vec<String>,
        uri_sans: Vec<String>,
        fingerprint: CertFingerprint,
    ) -> Self {
        Self {
            common_name,
            dns_sans,
            uri_sans,
            fingerprint,
        }
    }

    /// Create from DER-encoded certificate bytes.
    ///
    /// Computes the SHA-256 fingerprint and extracts the Subject CN and
    /// Subject Alternative Names (DNS, URI) using x509-parser.
    pub fn from_der(der: &[u8]) -> Result<Self, CryptoError> {
        let fingerprint = CertFingerprint::from_der(der);
        let (common_name, dns_sans, uri_sans) = Self::parse_cert_der(der)?;

        Ok(Self {
            common_name,
            dns_sans,
            uri_sans,
            fingerprint,
        })
    }

    /// Create from fingerprint and CN only.
    ///
    /// Sets `dns_sans` to `[cn]` and `uri_sans` to empty.
    /// If you have DER-encoded bytes, prefer [`CertIdentity::from_der`].
    pub fn from_fingerprint_and_cn(fingerprint: CertFingerprint, cn: String) -> Self {
        Self {
            common_name: Some(cn.clone()),
            dns_sans: vec![cn],
            uri_sans: vec![],
            fingerprint,
        }
    }

    /// Parse DER certificate to extract CN and SANs using x509-parser.
    fn parse_cert_der(der: &[u8]) -> Result<ParsedCertData, CryptoError> {
        use x509_parser::prelude::*;

        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| CryptoError::ParseFailed(format!("X.509 parse error: {e}")))?;

        // Extract Subject CN
        let cn = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|attr| attr.as_str().ok())
            .map(String::from);

        // Extract SANs from the SubjectAlternativeName extension
        let mut dns_sans = Vec::new();
        let mut uri_sans = Vec::new();

        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                match name {
                    GeneralName::DNSName(dns) => dns_sans.push((*dns).to_string()),
                    GeneralName::URI(uri) => uri_sans.push((*uri).to_string()),
                    _ => {}
                }
            }
        }

        Ok((cn, dns_sans, uri_sans))
    }

    /// Get the FQDN from the certificate.
    ///
    /// Prefers DNS SAN over CN, following RFC 6125 recommendations.
    pub fn fqdn(&self) -> Option<&str> {
        self.dns_sans
            .first()
            .map(std::string::String::as_str)
            .or(self.common_name.as_deref())
    }

    /// Get the ANS name from URI SANs.
    pub fn ans_name(&self) -> Option<AnsName> {
        self.uri_sans
            .iter()
            .filter(|uri| uri.starts_with("ans://"))
            .find_map(|uri| AnsName::parse(uri).ok())
    }

    /// Extract version from ANS name in URI SAN.
    pub fn version(&self) -> Option<Version> {
        self.ans_name().map(|name| name.version().clone())
    }
}

/// Result of a verification operation.
#[derive(Debug)]
#[non_exhaustive]
pub enum VerificationOutcome {
    /// Verification passed.
    Verified {
        /// The verified badge.
        badge: Badge,
        /// The fingerprint that matched.
        matched_fingerprint: CertFingerprint,
    },

    /// Not an ANS agent (no badge DNS record found).
    NotAnsAgent {
        /// The FQDN that was looked up.
        fqdn: String,
    },

    /// Badge status is invalid for connections.
    InvalidStatus {
        /// The invalid status.
        status: BadgeStatus,
        /// The badge with invalid status.
        badge: Badge,
    },

    /// Certificate fingerprint does not match badge.
    FingerprintMismatch {
        /// Expected fingerprint from badge.
        expected: String,
        /// Actual fingerprint from certificate.
        actual: String,
        /// The badge that didn't match.
        badge: Badge,
    },

    /// Hostname does not match badge.
    HostnameMismatch {
        /// Expected hostname from badge.
        expected: String,
        /// Actual hostname from certificate.
        actual: String,
        /// The badge that didn't match.
        badge: Badge,
    },

    /// ANS name does not match badge (mTLS client verification).
    AnsNameMismatch {
        /// Expected ANS name from badge.
        expected: String,
        /// Actual ANS name from certificate.
        actual: String,
        /// The badge that didn't match.
        badge: Badge,
    },

    /// Verification failed due to a DNS error.
    DnsError(DnsError),

    /// Verification failed due to a transparency log error.
    TlogError(TlogError),

    /// Verification failed due to a certificate error.
    CertError(CryptoError),

    /// Verification failed due to a parse error.
    ParseError(ans_types::ParseError),

    /// Verification failed due to a DANE/TLSA error.
    DaneError(DaneError),

    /// Verification succeeded via SCITT receipt + status token (offline).
    ///
    /// This variant indicates the highest-assurance verification path: the
    /// agent's identity was verified via cryptographic proofs without any
    /// DNS or transparency log queries.
    #[cfg(feature = "scitt")]
    ScittVerified {
        /// The verified status token payload.
        status_token: crate::scitt::VerifiedStatusToken,
        /// The verification tier achieved.
        tier: ans_types::VerificationTier,
        /// The fingerprint that matched.
        matched_fingerprint: CertFingerprint,
        /// The badge, if badge verification was also performed.
        badge: Option<Badge>,
    },

    /// SCITT verification failed (cryptographic or structural error).
    #[cfg(feature = "scitt")]
    ScittError(crate::scitt::ScittError),
}

impl VerificationOutcome {
    /// Check if verification was successful.
    pub fn is_success(&self) -> bool {
        match self {
            Self::Verified { .. } => true,
            #[cfg(feature = "scitt")]
            Self::ScittVerified { .. } => true,
            _ => false,
        }
    }

    /// Check if the agent is in a terminal status (revoked, expired, etc.).
    ///
    /// Returns `true` for both badge-detected terminal status
    /// ([`Self::InvalidStatus`]) and SCITT-detected terminal status
    /// (`ScittError::TerminalStatus` / `ScittError::AgentTerminal`).
    /// Callers should use this instead of pattern-matching individual
    /// variants.
    pub fn is_terminal_status(&self) -> bool {
        match self {
            Self::InvalidStatus { status, .. } => status.should_reject(),
            #[cfg(feature = "scitt")]
            Self::ScittError(e) => e.is_terminal_status(),
            _ => false,
        }
    }

    /// Check if the agent is not registered with ANS.
    pub fn is_not_ans_agent(&self) -> bool {
        matches!(self, Self::NotAnsAgent { .. })
    }

    /// Get the badge if verification succeeded or partially completed.
    pub fn badge(&self) -> Option<&Badge> {
        match self {
            Self::Verified { badge, .. }
            | Self::InvalidStatus { badge, .. }
            | Self::FingerprintMismatch { badge, .. }
            | Self::HostnameMismatch { badge, .. }
            | Self::AnsNameMismatch { badge, .. } => Some(badge),
            #[cfg(feature = "scitt")]
            Self::ScittVerified {
                badge: Some(badge), ..
            } => Some(badge),
            _ => None,
        }
    }

    /// Convert to a `Result`, returning the [`Badge`] on success.
    ///
    /// For badge-based verification, this is the natural accessor. For
    /// SCITT-verified outcomes that may not carry a badge, prefer
    /// [`into_scitt_result`](Self::into_scitt_result) which returns
    /// `Option<Badge>` on success.
    ///
    /// When the `scitt` feature is enabled:
    /// - `ScittVerified` with a badge → `Ok(badge)`
    /// - `ScittVerified` without a badge → `Err(Configuration)` (use
    ///   `into_scitt_result()` instead)
    /// - `ScittError` → `Err(Scitt(..))`
    pub fn into_result(self) -> AnsResult<Badge> {
        match self {
            Self::Verified { badge, .. } => Ok(badge),
            Self::NotAnsAgent { fqdn } => Err(AnsError::Dns(DnsError::NotFound { fqdn })),
            Self::InvalidStatus { status, .. } => {
                Err(AnsError::Verification(VerificationError::InvalidStatus {
                    status,
                }))
            }
            Self::FingerprintMismatch {
                expected, actual, ..
            } => Err(AnsError::Verification(
                VerificationError::FingerprintMismatch { expected, actual },
            )),
            Self::HostnameMismatch {
                expected, actual, ..
            } => Err(AnsError::Verification(
                VerificationError::HostnameMismatch { expected, actual },
            )),
            Self::AnsNameMismatch {
                expected, actual, ..
            } => Err(AnsError::Verification(VerificationError::AnsNameMismatch {
                expected,
                actual,
            })),
            Self::DnsError(e) => Err(AnsError::Dns(e)),
            Self::TlogError(e) => Err(AnsError::TransparencyLog(e)),
            Self::CertError(e) => Err(AnsError::Certificate(e)),
            Self::ParseError(e) => Err(AnsError::Parse(e)),
            Self::DaneError(e) => Err(AnsError::Verification(
                VerificationError::DaneVerificationFailed(e),
            )),
            #[cfg(feature = "scitt")]
            Self::ScittVerified { badge: Some(b), .. } => Ok(b),
            #[cfg(feature = "scitt")]
            Self::ScittVerified { badge: None, .. } => Err(AnsError::Verification(
                VerificationError::Configuration(
                    "SCITT verification succeeded without badge; use into_scitt_result() for SCITT-aware callers".to_string(),
                ),
            )),
            #[cfg(feature = "scitt")]
            Self::ScittError(e) => Err(AnsError::Scitt(e)),
        }
    }

    /// Convert a SCITT-aware outcome to a `Result`.
    ///
    /// Returns `Ok(Some(badge))` for badge or SCITT+badge verification,
    /// `Ok(None)` for pure SCITT verification without a badge, and
    /// `Err(..)` for any failure.
    ///
    /// This method is consistent with [`is_success()`](Self::is_success):
    /// every outcome where `is_success()` returns `true` maps to `Ok(..)`.
    #[cfg(feature = "scitt")]
    pub fn into_scitt_result(self) -> AnsResult<Option<Badge>> {
        match self {
            Self::Verified { badge, .. } => Ok(Some(badge)),
            Self::ScittVerified { badge, .. } => Ok(badge),
            other => other.into_result().map(Some),
        }
    }
}

/// SCITT verification tier policy.
///
/// Controls how SCITT and badge verification interact.
#[cfg(feature = "scitt")]
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub enum ScittTierPolicy {
    /// Try SCITT first, fall back to badge if headers absent (recommended).
    ///
    /// Present headers are final: any SCITT failure (including `TokenExpired`)
    /// is a hard reject with no badge fallback. Badge fallback only occurs
    /// when SCITT headers are completely absent.
    #[default]
    ScittWithBadgeFallback,

    /// SCITT required; fail if SCITT verification doesn't succeed.
    ///
    /// Only safe when 100% of peers support SCITT. `TokenExpired` is a
    /// hard failure under this policy (no badge fallback available).
    RequireScitt,

    /// Badge first, enhance with SCITT if headers present.
    ///
    /// For gradual migration: existing badge verification runs first,
    /// SCITT supplements the result if headers are available.
    BadgeWithScittEnhancement,
}

/// Configuration for SCITT verification.
#[cfg(feature = "scitt")]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ScittConfig {
    /// How SCITT and badge verification interact.
    pub tier_policy: ScittTierPolicy,
    /// Clock skew tolerance for status token expiry checks.
    pub clock_skew_tolerance: Duration,
}

#[cfg(feature = "scitt")]
impl Default for ScittConfig {
    fn default() -> Self {
        Self {
            tier_policy: ScittTierPolicy::default(),
            clock_skew_tolerance: Duration::from_secs(60),
        }
    }
}

#[cfg(feature = "scitt")]
impl ScittConfig {
    /// Create with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the tier policy.
    pub fn with_tier_policy(mut self, policy: ScittTierPolicy) -> Self {
        self.tier_policy = policy;
        self
    }

    /// Set the clock skew tolerance.
    pub fn with_clock_skew(mut self, tolerance: Duration) -> Self {
        self.clock_skew_tolerance = tolerance;
        self
    }
}

/// Failure handling policy.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub enum FailurePolicy {
    /// Reject on any failure (most secure).
    #[default]
    FailClosed,

    /// Use cached badge if available, otherwise reject.
    FailOpenWithCache {
        /// Maximum age of cached badge to accept.
        max_staleness: Duration,
    },
}

/// Validate that a badge URL's domain is in the trusted RA domains set.
///
/// Returns `Ok(())` if:
/// - `trusted` is `None` (no restriction configured — allow all domains)
/// - The URL's host is present in the trusted set
///
/// Returns `Err(TlogError::UntrustedDomain)` if the host is not trusted.
fn validate_badge_domain(trusted: Option<&HashSet<String>>, url: &str) -> Result<(), TlogError> {
    let Some(trusted) = trusted else {
        return Ok(());
    };
    let parsed = url::Url::parse(url)
        .map_err(|e| TlogError::InvalidUrl(format!("Badge URL is invalid: {e}")))?;
    let domain = parsed
        .host_str()
        .ok_or_else(|| TlogError::InvalidUrl(format!("Badge URL has no host: {url}")))?;
    if trusted.contains(domain) {
        Ok(())
    } else {
        Err(TlogError::UntrustedDomain {
            domain: domain.to_string(),
            trusted: trusted.iter().cloned().collect(),
        })
    }
}

/// Server verifier for clients verifying agent servers.
pub struct ServerVerifier {
    dns_resolver: Arc<dyn DnsResolver>,
    tlog_client: Arc<dyn TransparencyLogClient>,
    cache: Option<Arc<BadgeCache>>,
    failure_policy: FailurePolicy,
    dane_policy: DanePolicy,
    /// Port to use for TLSA lookups (default: 443).
    dane_port: u16,
    /// Optional set of trusted RA domains for badge URL validation.
    trusted_ra_domains: Option<HashSet<String>>,
}

impl fmt::Debug for ServerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerVerifier")
            .field("failure_policy", &self.failure_policy)
            .field("dane_policy", &self.dane_policy)
            .field("dane_port", &self.dane_port)
            .field("has_cache", &self.cache.is_some())
            .field("has_trusted_ra_domains", &self.trusted_ra_domains.is_some())
            .finish_non_exhaustive()
    }
}

impl ServerVerifier {
    /// Create a new builder.
    pub fn builder() -> ServerVerifierBuilder {
        ServerVerifierBuilder::default()
    }

    /// Verify an agent server.
    ///
    /// # Steps
    /// 1. DNS lookup for `_ans-badge` TXT record (with `_ra-badge` fallback)
    /// 2. Fetch preferred badge from transparency log (newest ACTIVE first)
    /// 3. Validate badge status
    /// 4. Compare certificate fingerprint to badge
    /// 5. On mismatch with multiple records, try all badges by fingerprint
    ///    (handles multi-version transitions where both versions are ACTIVE)
    /// 6. If still no match, refresh-on-mismatch (handles cert renewal)
    /// 7. Compare certificate CN to badge agent.host
    pub async fn verify(&self, fqdn: &Fqdn, server_cert: &CertIdentity) -> VerificationOutcome {
        tracing::info!(fqdn = %fqdn, "Starting server verification");
        tracing::debug!(
            cert_cn = ?server_cert.common_name,
            cert_fingerprint = %server_cert.fingerprint,
            "Certificate details"
        );

        // Check cache first — scan all versioned badges by fingerprint
        if let Some(cache) = &self.cache {
            let cached_badges = cache.get_all_for_fqdn(fqdn).await;
            if !cached_badges.is_empty() {
                tracing::debug!(fqdn = %fqdn, count = cached_badges.len(), "Scanning cached badges");
                for cached in &cached_badges {
                    let outcome = self.verify_against_badge(&cached.badge, server_cert, true);
                    if outcome.is_success() {
                        tracing::debug!(fqdn = %fqdn, "Cache hit — badge matched");
                        return outcome;
                    }
                }
                // No cached badge matched — fall through to DNS+TLog
                tracing::info!(fqdn = %fqdn, "No cached badge matched fingerprint, fetching fresh");
            }
        }

        // DNS lookup
        tracing::debug!(fqdn = %fqdn, "Performing DNS lookup for _ans-badge / _ra-badge");
        let records = match self.dns_resolver.lookup_badge(fqdn).await {
            Ok(DnsLookupResult::Found(records)) => {
                tracing::debug!(count = records.len(), "Found badge records");
                for (i, r) in records.iter().enumerate() {
                    tracing::debug!(index = i, version = ?r.version, url = %r.url, "Badge record");
                }
                records
            }
            Ok(DnsLookupResult::NotFound) => {
                tracing::warn!(fqdn = %fqdn, "No badge record found - not an ANS agent");
                return VerificationOutcome::NotAnsAgent {
                    fqdn: fqdn.to_string(),
                };
            }
            Err(e) => {
                tracing::error!(fqdn = %fqdn, error = %e, "DNS lookup failed");
                return self.handle_dns_error(e, fqdn, server_cert).await;
            }
        };

        // Server certs don't contain version info. Try all badge records by
        // fingerprint to handle multi-version transitions where both versions
        // are ACTIVE (see AGENT_TO_AGENT_FLOW §5.3).
        let outcome = self
            .verify_against_records(&records, fqdn, server_cert)
            .await;

        if !outcome.is_success() {
            return outcome;
        }

        // Perform DANE verification if enabled
        if self.dane_policy.should_verify() {
            match self.verify_dane(fqdn, server_cert).await {
                Ok(result) => {
                    if !result.is_acceptable(self.dane_policy) {
                        tracing::error!(
                            fqdn = %fqdn,
                            dane_policy = ?self.dane_policy,
                            "DANE verification failed"
                        );
                        return VerificationOutcome::DaneError(DaneError::FingerprintMismatch);
                    }
                }
                Err(e) => {
                    tracing::error!(fqdn = %fqdn, error = %e, "DANE verification error");
                    return VerificationOutcome::DaneError(e);
                }
            }
        }

        outcome
    }

    /// Try all badge records to find one matching the server certificate.
    ///
    /// Server certificates don't contain version info, so during multi-version
    /// transitions (where multiple versions are ACTIVE), we must try each badge
    /// by fingerprint comparison. Prefers newest ACTIVE badge, falls back to
    /// older versions and AHP-deprecated badges.
    ///
    /// If no badge matches from any record, falls back to refresh-on-mismatch
    /// (handles the certificate renewal case where the `TLog` was recently updated).
    async fn verify_against_records(
        &self,
        records: &[BadgeRecord],
        fqdn: &Fqdn,
        server_cert: &CertIdentity,
    ) -> VerificationOutcome {
        // Sort by version descending (newest first)
        let mut sorted: Vec<_> = records.iter().collect();
        sorted.sort_by(|a, b| b.version.cmp(&a.version));

        // Pre-populate the version index from DNS records
        if let Some(cache) = &self.cache {
            let versions: Vec<Version> =
                sorted.iter().filter_map(|r| r.version().cloned()).collect();
            if !versions.is_empty() {
                cache.set_version_index(fqdn, versions).await;
            }
        }

        // Fetch all badges in parallel
        let results = self.fetch_badges_parallel(&sorted).await;

        let mut last_mismatch: Option<VerificationOutcome> = None;
        let mut last_error: Option<AnsError> = None;

        for (record, result) in results {
            let badge = match result {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(url = %record.url, error = %e, "Failed to fetch badge, trying next");
                    last_error = Some(AnsError::TransparencyLog(e));
                    continue;
                }
            };

            tracing::debug!(
                version = ?record.version,
                status = ?badge.status,
                "Checking badge record"
            );

            // Cache every successfully fetched badge by version
            if let Some(cache) = &self.cache {
                let version = record
                    .version()
                    .cloned()
                    .or_else(|| badge.agent_version().parse::<Version>().ok());
                if let Some(v) = &version {
                    cache.insert_for_fqdn_version(fqdn, v, badge.clone()).await;
                    tracing::debug!(fqdn = %fqdn, version = %v, "Cached badge by version");
                }
            }

            let outcome = self.verify_against_badge(&badge, server_cert, true);

            match &outcome {
                VerificationOutcome::Verified { .. } => {
                    return outcome;
                }
                VerificationOutcome::FingerprintMismatch { .. } => {
                    tracing::debug!(version = ?record.version, "Fingerprint mismatch, trying next record");
                    last_mismatch = Some(outcome);
                }
                // Non-fingerprint failures (status rejected, hostname mismatch) are terminal
                _ => return outcome,
            }
        }

        // No badge matched by fingerprint. Try refresh-on-mismatch for the
        // cert renewal case (TLog updated after our DNS lookup).
        if last_mismatch.is_some() {
            tracing::info!(fqdn = %fqdn, "No badge matched, attempting refresh-on-mismatch");
            return self.verify_with_refresh(fqdn, server_cert).await;
        }

        // All fetches failed
        match last_error {
            Some(e) => self.handle_ans_error(e, fqdn, server_cert).await,
            None => VerificationOutcome::NotAnsAgent {
                fqdn: fqdn.to_string(),
            },
        }
    }

    /// Perform DANE/TLSA verification.
    async fn verify_dane(
        &self,
        fqdn: &Fqdn,
        cert: &CertIdentity,
    ) -> Result<DaneVerificationResult, DaneError> {
        tracing::debug!(
            fqdn = %fqdn,
            port = self.dane_port,
            policy = ?self.dane_policy,
            "Starting DANE verification"
        );

        let tlsa_records = self
            .dns_resolver
            .get_tlsa_records(fqdn, self.dane_port)
            .await?;

        verify_dane(
            &tlsa_records,
            &cert.fingerprint,
            self.dane_policy,
            fqdn,
            self.dane_port,
        )
    }

    /// Pre-fetch badges for caching (before TLS connection).
    ///
    /// Fetches ALL badge records from DNS, then fetches and caches each badge
    /// by version. Returns the preferred (newest active) badge.
    pub async fn prefetch(&self, fqdn: &Fqdn) -> Result<Badge, AnsError> {
        let records = match self.dns_resolver.lookup_badge(fqdn).await {
            Ok(DnsLookupResult::Found(records)) => records,
            Ok(DnsLookupResult::NotFound) => {
                return Err(AnsError::Dns(DnsError::NotFound {
                    fqdn: fqdn.to_string(),
                }));
            }
            Err(e) => return Err(AnsError::Dns(e)),
        };

        // Sort by version descending (newest first)
        let mut sorted: Vec<_> = records.iter().collect();
        sorted.sort_by(|a, b| b.version.cmp(&a.version));

        // Pre-populate the version index from DNS records
        if let Some(cache) = &self.cache {
            let versions: Vec<Version> =
                sorted.iter().filter_map(|r| r.version().cloned()).collect();
            if !versions.is_empty() {
                cache.set_version_index(fqdn, versions).await;
            }
        }

        // Fetch ALL badges in parallel, then process results
        let results = self.fetch_badges_parallel(&sorted).await;

        let mut preferred: Option<Badge> = None;
        let mut last_error = None;

        for (record, result) in results {
            match result {
                Ok(badge) => {
                    // Cache by version
                    if let Some(cache) = &self.cache {
                        let version = record
                            .version()
                            .cloned()
                            .or_else(|| badge.agent_version().parse::<Version>().ok());
                        if let Some(v) = &version {
                            cache.insert_for_fqdn_version(fqdn, v, badge.clone()).await;
                            tracing::debug!(fqdn = %fqdn, version = %v, "Prefetch: cached badge");
                        }
                    }

                    // Track preferred (first active, then deprecated, as fallback)
                    if preferred.is_none()
                        && (badge.status.is_active() || badge.status == BadgeStatus::Deprecated)
                    {
                        preferred = Some(badge);
                    }
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        match preferred {
            Some(badge) => Ok(badge),
            None => match last_error {
                Some(e) => Err(AnsError::TransparencyLog(e)),
                None => Err(AnsError::TransparencyLog(TlogError::InvalidResponse(
                    "no badge records available".to_string(),
                ))),
            },
        }
    }

    /// Refresh-on-mismatch: invalidate cache, re-fetch from DNS and `TLog`, re-verify.
    ///
    /// Called when no badge record matched by fingerprint. Handles the cert
    /// renewal case where the `TLog` was updated after the initial fetch.
    /// Tries all records to also handle multi-version transitions.
    async fn verify_with_refresh(
        &self,
        fqdn: &Fqdn,
        server_cert: &CertIdentity,
    ) -> VerificationOutcome {
        // Invalidate all cached badges for this FQDN
        if let Some(cache) = &self.cache {
            cache.invalidate_fqdn(fqdn).await;
        }

        // Re-fetch from DNS + tlog, trying all records
        let records = match self.dns_resolver.lookup_badge(fqdn).await {
            Ok(DnsLookupResult::Found(records)) => records,
            Ok(DnsLookupResult::NotFound) => {
                return VerificationOutcome::NotAnsAgent {
                    fqdn: fqdn.to_string(),
                };
            }
            Err(e) => return VerificationOutcome::DnsError(e),
        };

        // Try all records — this is the final answer (no further refresh)
        self.verify_against_records_final(&records, fqdn, server_cert)
            .await
    }

    /// Try all badge records without further refresh fallback (terminal attempt).
    async fn verify_against_records_final(
        &self,
        records: &[BadgeRecord],
        fqdn: &Fqdn,
        server_cert: &CertIdentity,
    ) -> VerificationOutcome {
        let mut sorted: Vec<_> = records.iter().collect();
        sorted.sort_by(|a, b| b.version.cmp(&a.version));

        // Pre-populate the version index from DNS records
        if let Some(cache) = &self.cache {
            let versions: Vec<Version> =
                sorted.iter().filter_map(|r| r.version().cloned()).collect();
            if !versions.is_empty() {
                cache.set_version_index(fqdn, versions).await;
            }
        }

        // Fetch all badges in parallel
        let results = self.fetch_badges_parallel(&sorted).await;

        let mut last_mismatch: Option<VerificationOutcome> = None;
        let mut last_error: Option<AnsError> = None;

        for (record, result) in results {
            let badge = match result {
                Ok(b) => b,
                Err(e) => {
                    last_error = Some(AnsError::TransparencyLog(e));
                    continue;
                }
            };

            // Cache every successfully fetched badge by version
            if let Some(cache) = &self.cache {
                let version = record
                    .version()
                    .cloned()
                    .or_else(|| badge.agent_version().parse::<Version>().ok());
                if let Some(v) = &version {
                    cache.insert_for_fqdn_version(fqdn, v, badge.clone()).await;
                }
            }

            let outcome = self.verify_against_badge(&badge, server_cert, true);

            match &outcome {
                VerificationOutcome::Verified { .. } => {
                    return outcome;
                }
                VerificationOutcome::FingerprintMismatch { .. } => {
                    last_mismatch = Some(outcome);
                }
                _ => return outcome,
            }
        }

        // Return last mismatch or last error
        if let Some(mismatch) = last_mismatch {
            return mismatch;
        }
        match last_error {
            Some(e) => self.handle_ans_error(e, fqdn, server_cert).await,
            None => VerificationOutcome::NotAnsAgent {
                fqdn: fqdn.to_string(),
            },
        }
    }

    /// Fetch badges from the transparency log in parallel.
    ///
    /// Validates badge domains first (pure check), then fires all HTTP requests
    /// concurrently via `join_all`. Returns results paired with their records,
    /// preserving the input ordering.
    async fn fetch_badges_parallel<'a>(
        &self,
        records: &'a [&'a BadgeRecord],
    ) -> Vec<(&'a BadgeRecord, Result<Badge, TlogError>)> {
        // Pair each record with a future: domain-invalid records get an
        // immediate Err, valid ones get a real TLog fetch.
        let futures: Vec<_> = records
            .iter()
            .map(|record| {
                let tlog = &self.tlog_client;
                let trusted = &self.trusted_ra_domains;
                async move {
                    if let Err(e) = validate_badge_domain(trusted.as_ref(), &record.url) {
                        (*record, Err(e))
                    } else {
                        let result = tlog.fetch_badge(&record.url).await;
                        (*record, result)
                    }
                }
            })
            .collect();

        join_all(futures).await
    }

    #[allow(clippy::unused_self)] // logically part of ServerVerifier; may use self in future
    fn verify_against_badge(
        &self,
        badge: &Badge,
        cert: &CertIdentity,
        is_server: bool,
    ) -> VerificationOutcome {
        let cert_type = if is_server { "server" } else { "identity" };
        tracing::debug!(cert_type, "Verifying certificate against badge");

        // Check status
        if badge.status.should_reject() {
            tracing::warn!(
                status = ?badge.status,
                "Badge status is not valid for connections"
            );
            return VerificationOutcome::InvalidStatus {
                status: badge.status,
                badge: badge.clone(),
            };
        }
        tracing::debug!(status = ?badge.status, "Badge status is valid");

        // Compare fingerprint
        let expected_fp = if is_server {
            badge.server_cert_fingerprint()
        } else {
            badge.identity_cert_fingerprint()
        };

        tracing::debug!(
            expected = %expected_fp,
            actual = %cert.fingerprint,
            "Comparing certificate fingerprints"
        );

        if !cert.fingerprint.matches(expected_fp) {
            tracing::error!(
                expected = %expected_fp,
                actual = %cert.fingerprint,
                "Certificate fingerprint MISMATCH"
            );
            return VerificationOutcome::FingerprintMismatch {
                expected: expected_fp.to_string(),
                actual: cert.fingerprint.to_string(),
                badge: badge.clone(),
            };
        }
        tracing::debug!("Fingerprint matches");

        // Compare hostname
        let expected_host = badge.agent_host();
        let actual_host = cert.fqdn().unwrap_or("");

        tracing::debug!(
            expected = %expected_host,
            actual = %actual_host,
            "Comparing hostnames"
        );

        if !actual_host.eq_ignore_ascii_case(expected_host) {
            tracing::error!(
                expected = %expected_host,
                actual = %actual_host,
                "Hostname MISMATCH"
            );
            return VerificationOutcome::HostnameMismatch {
                expected: expected_host.to_string(),
                actual: actual_host.to_string(),
                badge: badge.clone(),
            };
        }

        tracing::info!(
            agent = %badge.agent_name(),
            host = %badge.agent_host(),
            "Verification SUCCESSFUL"
        );
        VerificationOutcome::Verified {
            badge: badge.clone(),
            matched_fingerprint: cert.fingerprint.clone(),
        }
    }

    async fn handle_dns_error(
        &self,
        error: DnsError,
        fqdn: &Fqdn,
        cert: &CertIdentity,
    ) -> VerificationOutcome {
        match self.failure_policy {
            FailurePolicy::FailClosed => VerificationOutcome::DnsError(error),
            FailurePolicy::FailOpenWithCache { max_staleness } => {
                if let Some(cache) = &self.cache {
                    for cached in cache.get_all_for_fqdn(fqdn).await {
                        if cached.fetched_at.elapsed() < max_staleness {
                            let outcome = self.verify_against_badge(&cached.badge, cert, true);
                            if outcome.is_success() {
                                return outcome;
                            }
                        }
                    }
                }
                VerificationOutcome::DnsError(error)
            }
        }
    }

    async fn handle_ans_error(
        &self,
        error: AnsError,
        fqdn: &Fqdn,
        cert: &CertIdentity,
    ) -> VerificationOutcome {
        match self.failure_policy {
            FailurePolicy::FailClosed => match error {
                AnsError::TransparencyLog(e) => VerificationOutcome::TlogError(e),
                AnsError::Dns(e) => VerificationOutcome::DnsError(e),
                AnsError::Certificate(e) => VerificationOutcome::CertError(e),
                AnsError::Parse(e) => VerificationOutcome::ParseError(e),
                AnsError::Verification(_) => VerificationOutcome::NotAnsAgent {
                    fqdn: fqdn.to_string(),
                },
                // SCITT errors should not reach badge-path error handling;
                // if they do, log loudly and treat as a generic verification failure.
                #[cfg(feature = "scitt")]
                AnsError::Scitt(ref e) => {
                    tracing::error!(
                        error = %e,
                        fqdn = %fqdn,
                        "BUG: ScittError reached badge-path error handler — treating as NotAnsAgent"
                    );
                    VerificationOutcome::NotAnsAgent {
                        fqdn: fqdn.to_string(),
                    }
                }
            },
            FailurePolicy::FailOpenWithCache { max_staleness } => {
                if let Some(cache) = &self.cache {
                    for cached in cache.get_all_for_fqdn(fqdn).await {
                        if cached.fetched_at.elapsed() < max_staleness {
                            let outcome = self.verify_against_badge(&cached.badge, cert, true);
                            if outcome.is_success() {
                                return outcome;
                            }
                        }
                    }
                }
                match error {
                    AnsError::TransparencyLog(e) => VerificationOutcome::TlogError(e),
                    AnsError::Dns(e) => VerificationOutcome::DnsError(e),
                    AnsError::Certificate(e) => VerificationOutcome::CertError(e),
                    AnsError::Parse(e) => VerificationOutcome::ParseError(e),
                    AnsError::Verification(_) => VerificationOutcome::NotAnsAgent {
                        fqdn: fqdn.to_string(),
                    },
                    // SCITT errors should not reach badge-path error handling;
                    // if they do, log loudly and treat as a generic verification failure.
                    #[cfg(feature = "scitt")]
                    AnsError::Scitt(ref e) => {
                        tracing::error!(
                            error = %e,
                            fqdn = %fqdn,
                            "BUG: ScittError reached badge-path error handler — treating as NotAnsAgent"
                        );
                        VerificationOutcome::NotAnsAgent {
                            fqdn: fqdn.to_string(),
                        }
                    }
                }
            }
        }
    }
}

/// Builder for `ServerVerifier`.
#[derive(Default)]
pub struct ServerVerifierBuilder {
    dns_resolver: Option<Arc<dyn DnsResolver>>,
    tlog_client: Option<Arc<dyn TransparencyLogClient>>,
    cache: Option<Arc<BadgeCache>>,
    failure_policy: FailurePolicy,
    dane_policy: DanePolicy,
    dane_port: Option<u16>,
    trusted_ra_domains: Option<HashSet<String>>,
}

impl fmt::Debug for ServerVerifierBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerVerifierBuilder")
            .field("failure_policy", &self.failure_policy)
            .field("dane_policy", &self.dane_policy)
            .field("dane_port", &self.dane_port)
            .field("has_dns_resolver", &self.dns_resolver.is_some())
            .field("has_tlog_client", &self.tlog_client.is_some())
            .field("has_cache", &self.cache.is_some())
            .finish_non_exhaustive()
    }
}

impl ServerVerifierBuilder {
    /// Set a custom DNS resolver.
    pub fn dns_resolver(mut self, resolver: Arc<dyn DnsResolver>) -> Self {
        self.dns_resolver = Some(resolver);
        self
    }

    /// Set a custom transparency log client.
    pub fn tlog_client(mut self, client: Arc<dyn TransparencyLogClient>) -> Self {
        self.tlog_client = Some(client);
        self
    }

    /// Enable caching with default configuration.
    pub fn with_cache(mut self) -> Self {
        self.cache = Some(Arc::new(BadgeCache::with_defaults()));
        self
    }

    /// Enable caching with custom configuration.
    pub fn with_cache_config(mut self, config: CacheConfig) -> Self {
        self.cache = Some(Arc::new(BadgeCache::new(config)));
        self
    }

    /// Use an existing cache.
    pub fn cache(mut self, cache: Arc<BadgeCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Set the failure policy.
    pub fn failure_policy(mut self, policy: FailurePolicy) -> Self {
        self.failure_policy = policy;
        self
    }

    /// Set the DANE/TLSA verification policy.
    ///
    /// - `DanePolicy::Disabled`: Skip DANE verification entirely (default)
    /// - `DanePolicy::ValidateIfPresent`: Verify TLSA if records exist, skip if not
    /// - `DanePolicy::Required`: Require TLSA records to exist and match
    pub fn dane_policy(mut self, policy: DanePolicy) -> Self {
        self.dane_policy = policy;
        self
    }

    /// Enable DANE verification if TLSA records are present.
    ///
    /// This is a convenience method equivalent to `.dane_policy(DanePolicy::ValidateIfPresent)`.
    pub fn with_dane_if_present(mut self) -> Self {
        self.dane_policy = DanePolicy::ValidateIfPresent;
        self
    }

    /// Require DANE verification (fail if no TLSA records).
    ///
    /// This is a convenience method equivalent to `.dane_policy(DanePolicy::Required)`.
    pub fn require_dane(mut self) -> Self {
        self.dane_policy = DanePolicy::Required;
        self
    }

    /// Set the port for TLSA lookups (default: 443).
    pub fn dane_port(mut self, port: u16) -> Self {
        self.dane_port = Some(port);
        self
    }

    /// Restrict badge URL fetches to a set of trusted RA domains.
    ///
    /// When configured, badge URLs discovered via DNS TXT records will be
    /// validated against this set before any HTTP request is made. URLs
    /// pointing to hosts not in the set are rejected with
    /// `TlogError::UntrustedDomain`.
    ///
    /// By default (`None`), all domains are allowed.
    pub fn trusted_ra_domains(
        mut self,
        domains: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.trusted_ra_domains = Some(domains.into_iter().map(Into::into).collect());
        self
    }

    /// Build the verifier.
    pub async fn build(self) -> AnsResult<ServerVerifier> {
        let dns_resolver = match self.dns_resolver {
            Some(r) => r,
            None => Arc::new(
                HickoryDnsResolver::new()
                    .await
                    .map_err(|e| AnsError::Dns(DnsError::ResolverError(e.to_string())))?,
            ),
        };

        let tlog_client = self
            .tlog_client
            .unwrap_or_else(|| Arc::new(HttpTransparencyLogClient::new()));

        Ok(ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: self.cache,
            failure_policy: self.failure_policy,
            dane_policy: self.dane_policy,
            dane_port: self.dane_port.unwrap_or(443),
            trusted_ra_domains: self.trusted_ra_domains,
        })
    }
}

/// Client verifier for servers verifying mTLS agent clients.
pub struct ClientVerifier {
    dns_resolver: Arc<dyn DnsResolver>,
    tlog_client: Arc<dyn TransparencyLogClient>,
    cache: Option<Arc<BadgeCache>>,
    failure_policy: FailurePolicy,
    /// Optional set of trusted RA domains for badge URL validation.
    trusted_ra_domains: Option<HashSet<String>>,
}

impl fmt::Debug for ClientVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientVerifier")
            .field("failure_policy", &self.failure_policy)
            .field("has_cache", &self.cache.is_some())
            .field("has_trusted_ra_domains", &self.trusted_ra_domains.is_some())
            .finish_non_exhaustive()
    }
}

impl ClientVerifier {
    /// Create a new builder.
    pub fn builder() -> ClientVerifierBuilder {
        ClientVerifierBuilder::default()
    }

    /// Verify an mTLS client certificate.
    ///
    /// # Steps
    /// 1. Extract CN (FQDN) and URI SAN (`ANSName`) from certificate
    /// 2. Parse version from `ANSName`
    /// 3. DNS lookup for `_ans-badge` (with `_ra-badge` fallback) using CN as FQDN
    /// 4. Select badge matching version from certificate
    /// 5. Compare identity cert fingerprint, CN, and URI SAN to badge
    /// 6. On fingerprint mismatch, refresh badge and re-verify once
    #[allow(clippy::too_many_lines)] // verification flow reads best as a single method
    pub async fn verify(&self, client_cert: &CertIdentity) -> VerificationOutcome {
        tracing::info!("Starting mTLS client verification");
        tracing::debug!(
            cn = ?client_cert.common_name,
            dns_sans = ?client_cert.dns_sans,
            uri_sans = ?client_cert.uri_sans,
            fingerprint = %client_cert.fingerprint,
            "Client certificate details"
        );

        // Extract FQDN from certificate
        let Some(fqdn_str) = client_cert.fqdn() else {
            tracing::error!("No CN or DNS SAN found in client certificate");
            return VerificationOutcome::CertError(CryptoError::NoCommonName);
        };

        let fqdn = match Fqdn::new(fqdn_str) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(fqdn = %fqdn_str, error = %e, "Invalid FQDN in certificate");
                return VerificationOutcome::ParseError(e);
            }
        };
        tracing::debug!(fqdn = %fqdn, "Extracted FQDN from certificate");

        // Extract ANS name and version from URI SAN
        let ans_name = if let Some(n) = client_cert.ans_name() {
            tracing::debug!(ans_name = %n, "Found ANS name in URI SAN");
            n
        } else {
            tracing::error!(uri_sans = ?client_cert.uri_sans, "No ANS name (ans://) found in URI SANs");
            return VerificationOutcome::CertError(CryptoError::NoUriSan);
        };

        let version = ans_name.version().clone();
        tracing::debug!(version = %version, "Parsed version from ANS name");

        // Check cache first
        if let Some(cache) = &self.cache
            && let Some(cached) = cache.get_by_fqdn_version(&fqdn, &version).await
        {
            tracing::debug!(fqdn = %fqdn, version = %version, "Using cached badge");
            let outcome = self.verify_client_against_badge(&cached.badge, client_cert, &ans_name);
            // Refresh-on-mismatch for cached badges
            if matches!(outcome, VerificationOutcome::FingerprintMismatch { .. }) {
                tracing::info!(fqdn = %fqdn, "Fingerprint mismatch on cached badge, refreshing");
                return self
                    .verify_client_with_refresh(&fqdn, &version, client_cert, &ans_name)
                    .await;
            }
            return outcome;
        }

        // DNS lookup
        tracing::debug!(fqdn = %fqdn, version = %version, "Looking up badge for version");
        let badge_record = match self
            .dns_resolver
            .find_badge_for_version(&fqdn, &version)
            .await
        {
            Ok(Some(record)) => {
                tracing::debug!(url = %record.url, "Found badge record for version");
                record
            }
            Ok(None) => {
                tracing::debug!("No badge for specific version, trying preferred badge");
                // Try to find any badge
                match self.dns_resolver.find_preferred_badge(&fqdn).await {
                    Ok(Some(record)) => {
                        tracing::debug!(url = %record.url, version = ?record.version, "Using preferred badge");
                        record
                    }
                    Ok(None) => {
                        tracing::warn!(fqdn = %fqdn, "No badge record found - not an ANS agent");
                        return VerificationOutcome::NotAnsAgent {
                            fqdn: fqdn.to_string(),
                        };
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "DNS lookup failed");
                        return self
                            .handle_dns_error(e, &fqdn, &version, client_cert, &ans_name)
                            .await;
                    }
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "DNS lookup failed");
                return self
                    .handle_dns_error(e, &fqdn, &version, client_cert, &ans_name)
                    .await;
            }
        };

        // Validate badge URL domain before fetching
        if let Err(e) = validate_badge_domain(self.trusted_ra_domains.as_ref(), &badge_record.url) {
            return self
                .handle_tlog_error(e, &fqdn, &version, client_cert, &ans_name)
                .await;
        }

        // Fetch badge
        tracing::debug!(url = %badge_record.url, "Fetching badge from transparency log");
        let badge = match self.tlog_client.fetch_badge(&badge_record.url).await {
            Ok(b) => {
                tracing::debug!(
                    status = ?b.status,
                    agent_host = %b.agent_host(),
                    ans_name = %b.agent_name(),
                    "Fetched badge successfully"
                );
                b
            }
            Err(e) => {
                tracing::error!(url = %badge_record.url, error = %e, "Failed to fetch badge");
                return self
                    .handle_tlog_error(e, &fqdn, &version, client_cert, &ans_name)
                    .await;
            }
        };

        // Cache the badge (tracked for multi-version lookups)
        if let Some(cache) = &self.cache {
            cache
                .insert_for_fqdn_version(&fqdn, &version, badge.clone())
                .await;
            tracing::debug!(fqdn = %fqdn, version = %version, "Cached badge");
        }

        let outcome = self.verify_client_against_badge(&badge, client_cert, &ans_name);
        // Refresh-on-mismatch for freshly fetched badges
        if matches!(outcome, VerificationOutcome::FingerprintMismatch { .. }) {
            tracing::info!(fqdn = %fqdn, "Fingerprint mismatch, attempting refresh");
            return self
                .verify_client_with_refresh(&fqdn, &version, client_cert, &ans_name)
                .await;
        }
        outcome
    }

    #[allow(clippy::unused_self)] // logically part of ClientVerifier; may use self in future
    fn verify_client_against_badge(
        &self,
        badge: &Badge,
        cert: &CertIdentity,
        ans_name: &AnsName,
    ) -> VerificationOutcome {
        tracing::debug!("Verifying client certificate against badge");

        // Check status
        if badge.status.should_reject() {
            tracing::warn!(status = ?badge.status, "Badge status is not valid for connections");
            return VerificationOutcome::InvalidStatus {
                status: badge.status,
                badge: badge.clone(),
            };
        }
        tracing::debug!(status = ?badge.status, "Badge status is valid");

        // Compare fingerprint (identity cert for mTLS clients)
        let expected_fp = badge.identity_cert_fingerprint();
        tracing::debug!(
            expected = %expected_fp,
            actual = %cert.fingerprint,
            "Comparing identity certificate fingerprints"
        );

        if !cert.fingerprint.matches(expected_fp) {
            tracing::error!(
                expected = %expected_fp,
                actual = %cert.fingerprint,
                "Identity certificate fingerprint MISMATCH"
            );
            return VerificationOutcome::FingerprintMismatch {
                expected: expected_fp.to_string(),
                actual: cert.fingerprint.to_string(),
                badge: badge.clone(),
            };
        }
        tracing::debug!("Identity fingerprint matches");

        // Compare hostname
        let expected_host = badge.agent_host();
        let actual_host = cert.fqdn().unwrap_or("");
        tracing::debug!(
            expected = %expected_host,
            actual = %actual_host,
            "Comparing hostnames"
        );

        if !actual_host.eq_ignore_ascii_case(expected_host) {
            tracing::error!(
                expected = %expected_host,
                actual = %actual_host,
                "Hostname MISMATCH"
            );
            return VerificationOutcome::HostnameMismatch {
                expected: expected_host.to_string(),
                actual: actual_host.to_string(),
                badge: badge.clone(),
            };
        }
        tracing::debug!("Hostname matches");

        // Compare ANS name
        let expected_ans_name = badge.agent_name();
        tracing::debug!(
            expected = %expected_ans_name,
            actual = %ans_name,
            "Comparing ANS names"
        );

        if ans_name.to_string() != expected_ans_name {
            tracing::error!(
                expected = %expected_ans_name,
                actual = %ans_name,
                "ANS name MISMATCH"
            );
            return VerificationOutcome::AnsNameMismatch {
                expected: expected_ans_name.to_string(),
                actual: ans_name.to_string(),
                badge: badge.clone(),
            };
        }

        tracing::info!(
            agent = %badge.agent_name(),
            host = %badge.agent_host(),
            "Client verification SUCCESSFUL"
        );
        VerificationOutcome::Verified {
            badge: badge.clone(),
            matched_fingerprint: cert.fingerprint.clone(),
        }
    }

    /// Refresh-on-mismatch for client verification.
    ///
    /// Invalidates the cache, re-fetches the badge from the transparency log,
    /// and re-verifies. This handles certificate renewals where the badge
    /// was updated but the verifier had a stale copy.
    async fn verify_client_with_refresh(
        &self,
        fqdn: &Fqdn,
        version: &Version,
        client_cert: &CertIdentity,
        ans_name: &AnsName,
    ) -> VerificationOutcome {
        // Invalidate cache
        if let Some(cache) = &self.cache {
            cache
                .invalidate(&CacheKey::fqdn_version(fqdn, version))
                .await;
        }

        // Re-fetch from DNS
        let badge_record = match self
            .dns_resolver
            .find_badge_for_version(fqdn, version)
            .await
        {
            Ok(Some(record)) => record,
            Ok(None) => match self.dns_resolver.find_preferred_badge(fqdn).await {
                Ok(Some(record)) => record,
                Ok(None) => {
                    return VerificationOutcome::NotAnsAgent {
                        fqdn: fqdn.to_string(),
                    };
                }
                Err(e) => return VerificationOutcome::DnsError(e),
            },
            Err(e) => return VerificationOutcome::DnsError(e),
        };

        // Validate badge URL domain before re-fetch
        if let Err(e) = validate_badge_domain(self.trusted_ra_domains.as_ref(), &badge_record.url) {
            return VerificationOutcome::TlogError(e);
        }

        // Re-fetch badge from transparency log
        let badge = match self.tlog_client.fetch_badge(&badge_record.url).await {
            Ok(b) => b,
            Err(e) => return VerificationOutcome::TlogError(e),
        };

        // Cache the refreshed badge (tracked for multi-version lookups)
        if let Some(cache) = &self.cache {
            cache
                .insert_for_fqdn_version(fqdn, version, badge.clone())
                .await;
        }

        // Re-verify — this is the final answer
        self.verify_client_against_badge(&badge, client_cert, ans_name)
    }

    async fn handle_dns_error(
        &self,
        error: DnsError,
        fqdn: &Fqdn,
        version: &Version,
        cert: &CertIdentity,
        ans_name: &AnsName,
    ) -> VerificationOutcome {
        match self.failure_policy {
            FailurePolicy::FailClosed => VerificationOutcome::DnsError(error),
            FailurePolicy::FailOpenWithCache { max_staleness } => {
                if let Some(cache) = &self.cache
                    && let Some(cached) = cache.get_by_fqdn_version(fqdn, version).await
                    && cached.fetched_at.elapsed() < max_staleness
                {
                    return self.verify_client_against_badge(&cached.badge, cert, ans_name);
                }
                VerificationOutcome::DnsError(error)
            }
        }
    }

    async fn handle_tlog_error(
        &self,
        error: TlogError,
        fqdn: &Fqdn,
        version: &Version,
        cert: &CertIdentity,
        ans_name: &AnsName,
    ) -> VerificationOutcome {
        match self.failure_policy {
            FailurePolicy::FailClosed => VerificationOutcome::TlogError(error),
            FailurePolicy::FailOpenWithCache { max_staleness } => {
                if let Some(cache) = &self.cache
                    && let Some(cached) = cache.get_by_fqdn_version(fqdn, version).await
                    && cached.fetched_at.elapsed() < max_staleness
                {
                    return self.verify_client_against_badge(&cached.badge, cert, ans_name);
                }
                VerificationOutcome::TlogError(error)
            }
        }
    }
}

/// Builder for `ClientVerifier`.
#[derive(Default)]
pub struct ClientVerifierBuilder {
    dns_resolver: Option<Arc<dyn DnsResolver>>,
    tlog_client: Option<Arc<dyn TransparencyLogClient>>,
    cache: Option<Arc<BadgeCache>>,
    failure_policy: FailurePolicy,
    trusted_ra_domains: Option<HashSet<String>>,
}

impl fmt::Debug for ClientVerifierBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientVerifierBuilder")
            .field("failure_policy", &self.failure_policy)
            .field("has_dns_resolver", &self.dns_resolver.is_some())
            .field("has_tlog_client", &self.tlog_client.is_some())
            .field("has_cache", &self.cache.is_some())
            .finish_non_exhaustive()
    }
}

impl ClientVerifierBuilder {
    /// Set a custom DNS resolver.
    pub fn dns_resolver(mut self, resolver: Arc<dyn DnsResolver>) -> Self {
        self.dns_resolver = Some(resolver);
        self
    }

    /// Set a custom transparency log client.
    pub fn tlog_client(mut self, client: Arc<dyn TransparencyLogClient>) -> Self {
        self.tlog_client = Some(client);
        self
    }

    /// Enable caching with default configuration.
    pub fn with_cache(mut self) -> Self {
        self.cache = Some(Arc::new(BadgeCache::with_defaults()));
        self
    }

    /// Enable caching with custom configuration.
    pub fn with_cache_config(mut self, config: CacheConfig) -> Self {
        self.cache = Some(Arc::new(BadgeCache::new(config)));
        self
    }

    /// Use an existing cache.
    pub fn cache(mut self, cache: Arc<BadgeCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Set the failure policy.
    pub fn failure_policy(mut self, policy: FailurePolicy) -> Self {
        self.failure_policy = policy;
        self
    }

    /// Restrict badge URL fetches to a set of trusted RA domains.
    ///
    /// When configured, badge URLs discovered via DNS TXT records will be
    /// validated against this set before any HTTP request is made. URLs
    /// pointing to hosts not in the set are rejected with
    /// `TlogError::UntrustedDomain`.
    ///
    /// By default (`None`), all domains are allowed.
    pub fn trusted_ra_domains(
        mut self,
        domains: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.trusted_ra_domains = Some(domains.into_iter().map(Into::into).collect());
        self
    }

    /// Build the verifier.
    pub async fn build(self) -> AnsResult<ClientVerifier> {
        let dns_resolver = match self.dns_resolver {
            Some(r) => r,
            None => Arc::new(
                HickoryDnsResolver::new()
                    .await
                    .map_err(|e| AnsError::Dns(DnsError::ResolverError(e.to_string())))?,
            ),
        };

        let tlog_client = self
            .tlog_client
            .unwrap_or_else(|| Arc::new(HttpTransparencyLogClient::new()));

        Ok(ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: self.cache,
            failure_policy: self.failure_policy,
            trusted_ra_domains: self.trusted_ra_domains,
        })
    }
}

/// High-level ANS verifier combining server and client verification.
pub struct AnsVerifier {
    server_verifier: ServerVerifier,
    client_verifier: ClientVerifier,
    #[cfg(feature = "rustls")]
    private_ca_pem: Option<Vec<u8>>,
    #[cfg(feature = "scitt")]
    scitt_config: Option<ScittConfig>,
    #[cfg(feature = "scitt")]
    scitt_key_store: Option<Arc<crate::scitt::RefreshableKeyStore>>,
    #[cfg(feature = "scitt")]
    scitt_verification_cache: Option<Arc<crate::scitt::ScittVerificationCache>>,
}

impl fmt::Debug for AnsVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let builder = &mut f.debug_struct("AnsVerifier");
        builder
            .field("server_verifier", &self.server_verifier)
            .field("client_verifier", &self.client_verifier);
        #[cfg(feature = "scitt")]
        builder.field("has_scitt_config", &self.scitt_config.is_some());
        #[cfg(feature = "scitt")]
        builder.field(
            "has_scitt_verification_cache",
            &self.scitt_verification_cache.is_some(),
        );
        builder.finish_non_exhaustive()
    }
}

impl AnsVerifier {
    /// Create a new verifier with default configuration.
    pub async fn new() -> AnsResult<Self> {
        Self::builder().build().await
    }

    /// Create a builder for custom configuration.
    pub fn builder() -> AnsVerifierBuilder {
        AnsVerifierBuilder::default()
    }

    /// Verify an agent server (client-side verification).
    pub async fn verify_server(
        &self,
        fqdn: impl AsRef<str>,
        server_cert: &CertIdentity,
    ) -> VerificationOutcome {
        let fqdn = match Fqdn::new(fqdn.as_ref()) {
            Ok(f) => f,
            Err(e) => return VerificationOutcome::ParseError(e),
        };
        self.server_verifier.verify(&fqdn, server_cert).await
    }

    /// Verify an mTLS client (server-side verification).
    pub async fn verify_client(&self, client_cert: &CertIdentity) -> VerificationOutcome {
        self.client_verifier.verify(client_cert).await
    }

    /// Pre-fetch a badge for caching (before TLS connection).
    pub async fn prefetch(&self, fqdn: impl AsRef<str>) -> AnsResult<Badge> {
        let fqdn = Fqdn::new(fqdn.as_ref())?;
        self.server_verifier.prefetch(&fqdn).await
    }

    /// Create a rustls [`AnsClientCertVerifier`](crate::AnsClientCertVerifier) for server-side mTLS.
    ///
    /// Requires `private_ca_pem` to have been set on the builder.
    /// Returns a verifier that validates client certificate chains against the ANS Private CA.
    /// Client certificates are **required**.
    #[cfg(feature = "rustls")]
    pub fn client_cert_verifier(&self) -> AnsResult<crate::AnsClientCertVerifier> {
        let pem = self.private_ca_pem.as_ref().ok_or_else(|| {
            AnsError::Verification(VerificationError::Configuration(
                "private_ca_pem is required for client_cert_verifier".into(),
            ))
        })?;
        crate::AnsClientCertVerifier::from_pem(pem).map_err(|e| {
            AnsError::Verification(VerificationError::Configuration(format!(
                "Failed to build client cert verifier: {e}"
            )))
        })
    }

    /// Create a rustls [`AnsClientCertVerifier`](crate::AnsClientCertVerifier) that allows optional client certs.
    ///
    /// Requires `private_ca_pem` to have been set on the builder.
    /// Use this when the server should accept both authenticated and unauthenticated clients.
    #[cfg(feature = "rustls")]
    pub fn client_cert_verifier_optional(&self) -> AnsResult<crate::AnsClientCertVerifier> {
        let pem = self.private_ca_pem.as_ref().ok_or_else(|| {
            AnsError::Verification(VerificationError::Configuration(
                "private_ca_pem is required for client_cert_verifier_optional".into(),
            ))
        })?;
        crate::AnsClientCertVerifier::from_pem_optional(pem).map_err(|e| {
            AnsError::Verification(VerificationError::Configuration(format!(
                "Failed to build optional client cert verifier: {e}"
            )))
        })
    }

    /// Create a rustls [`AnsServerCertVerifier`](crate::AnsServerCertVerifier) for a specific badge fingerprint.
    ///
    /// Typically called after [`prefetch()`](Self::prefetch) to get the expected fingerprint
    /// from the badge's `attestations.server_cert.fingerprint` field.
    #[cfg(feature = "rustls")]
    pub fn server_cert_verifier(
        &self,
        fingerprint: &CertFingerprint,
    ) -> AnsResult<crate::AnsServerCertVerifier> {
        crate::AnsServerCertVerifier::new(fingerprint.clone()).map_err(|e| {
            AnsError::Verification(VerificationError::Configuration(format!(
                "Failed to build server cert verifier: {e}"
            )))
        })
    }

    /// Verify an agent server with SCITT artifacts from HTTP headers.
    ///
    /// This implements the SCITT verification flow:
    /// 1. If SCITT headers are present, verify status token signature + expiry + cert fingerprint
    /// 2. If receipt is also present, verify Merkle inclusion proof → `FullScitt` tier
    /// 3. If headers are absent, fall back to badge-based verification (per `ScittTierPolicy`)
    ///
    /// **Present headers are final**: if SCITT headers are present but
    /// invalid/expired/corrupt, the result is a hard reject — badge
    /// verification is never used as fallback. This prevents MITM downgrade.
    ///
    /// If `scitt_config` was not set on the builder, falls through to
    /// badge-based `verify_server`.
    #[cfg(feature = "scitt")]
    pub async fn verify_server_with_scitt(
        &self,
        fqdn: impl AsRef<str>,
        server_cert: &CertIdentity,
        headers: &crate::scitt::ScittHeaders,
    ) -> VerificationOutcome {
        let fqdn_str = fqdn.as_ref();
        let parsed_fqdn = match Fqdn::new(fqdn_str) {
            Ok(f) => f,
            Err(e) => return VerificationOutcome::ParseError(e),
        };

        let Some(config) = &self.scitt_config else {
            // SCITT not configured — fall through to badge
            return self.server_verifier.verify(&parsed_fqdn, server_cert).await;
        };

        let Some(key_store) = &self.scitt_key_store else {
            // Defensive: builder.build() rejects this combination, but guard
            // against direct struct construction in tests.
            tracing::error!("BUG: scitt_config present but no key store — falling back to badge");
            return self.server_verifier.verify(&parsed_fqdn, server_cert).await;
        };

        match config.tier_policy {
            ScittTierPolicy::ScittWithBadgeFallback => {
                self.verify_scitt_first(&parsed_fqdn, server_cert, headers, key_store, config, true)
                    .await
            }
            ScittTierPolicy::RequireScitt => {
                self.verify_scitt_first(
                    &parsed_fqdn,
                    server_cert,
                    headers,
                    key_store,
                    config,
                    false,
                )
                .await
            }
            ScittTierPolicy::BadgeWithScittEnhancement => {
                // Badge first, then optionally enhance with SCITT
                let badge_outcome = self.server_verifier.verify(&parsed_fqdn, server_cert).await;
                if !badge_outcome.is_success() || headers.is_empty() {
                    return badge_outcome;
                }
                // Badge succeeded and SCITT headers present — try to upgrade.
                // If SCITT headers are present but corrupt, REJECT (no fallback
                // to badge) — prevents MITM downgrade via header injection.
                let scitt_cache = self.scitt_verification_cache.as_deref();
                let scitt_outcome = Self::try_scitt_verification(
                    server_cert,
                    headers,
                    key_store,
                    config,
                    true,
                    scitt_cache,
                )
                .await;
                match scitt_outcome {
                    Some(VerificationOutcome::ScittVerified {
                        status_token,
                        tier,
                        matched_fingerprint,
                        badge: _,
                    }) => {
                        // Carry the badge from badge_outcome into ScittVerified
                        let badge = badge_outcome.badge().cloned();
                        VerificationOutcome::ScittVerified {
                            status_token,
                            tier,
                            matched_fingerprint,
                            badge,
                        }
                    }
                    // Any SCITT failure when headers are present = hard reject.
                    // Present-but-corrupt headers must never fall back to badge.
                    Some(outcome) => outcome,
                    // None = no status token in headers (shouldn't happen since
                    // we checked !headers.is_empty() above, but defensively
                    // return the badge outcome).
                    None => badge_outcome,
                }
            }
        }
    }

    /// Verify an mTLS client with SCITT artifacts from HTTP headers.
    ///
    /// Same SCITT-first flow as server verification, but matches against
    /// identity certificate fingerprints instead of server certificates.
    #[cfg(feature = "scitt")]
    pub async fn verify_client_with_scitt(
        &self,
        client_cert: &CertIdentity,
        headers: &crate::scitt::ScittHeaders,
    ) -> VerificationOutcome {
        let Some(config) = &self.scitt_config else {
            return self.client_verifier.verify(client_cert).await;
        };

        let Some(key_store) = &self.scitt_key_store else {
            // Defensive: builder.build() rejects this combination, but guard
            // against direct struct construction in tests.
            tracing::error!("BUG: scitt_config present but no key store — falling back to badge");
            return self.client_verifier.verify(client_cert).await;
        };

        match config.tier_policy {
            ScittTierPolicy::ScittWithBadgeFallback => {
                self.verify_client_scitt_first(client_cert, headers, key_store, config, true)
                    .await
            }
            ScittTierPolicy::RequireScitt => {
                self.verify_client_scitt_first(client_cert, headers, key_store, config, false)
                    .await
            }
            ScittTierPolicy::BadgeWithScittEnhancement => {
                let badge_outcome = self.client_verifier.verify(client_cert).await;
                if !badge_outcome.is_success() || headers.is_empty() {
                    return badge_outcome;
                }
                // Headers present — try SCITT upgrade. Corrupt headers = reject.
                let scitt_cache = self.scitt_verification_cache.as_deref();
                let scitt_outcome = Self::try_scitt_verification(
                    client_cert,
                    headers,
                    key_store,
                    config,
                    false,
                    scitt_cache,
                )
                .await;
                match scitt_outcome {
                    Some(VerificationOutcome::ScittVerified {
                        status_token,
                        tier,
                        matched_fingerprint,
                        badge: _,
                    }) => {
                        let badge = badge_outcome.badge().cloned();
                        VerificationOutcome::ScittVerified {
                            status_token,
                            tier,
                            matched_fingerprint,
                            badge,
                        }
                    }
                    Some(outcome) => outcome, // present-but-corrupt = reject
                    None => badge_outcome,
                }
            }
        }
    }

    /// SCITT-first verification: try SCITT, optionally fall back to badge
    /// **only when headers are completely absent**.
    ///
    /// When headers are present, the SCITT result is final — no badge
    /// fallback for any error, including `TokenExpired`. This prevents
    /// MITM downgrade via header injection/corruption.
    #[cfg(feature = "scitt")]
    async fn verify_scitt_first(
        &self,
        fqdn: &Fqdn,
        server_cert: &CertIdentity,
        headers: &crate::scitt::ScittHeaders,
        key_store: &Arc<crate::scitt::RefreshableKeyStore>,
        config: &ScittConfig,
        allow_badge_fallback: bool,
    ) -> VerificationOutcome {
        // If no SCITT headers at all, the peer doesn't support SCITT
        if headers.is_empty() {
            if allow_badge_fallback {
                tracing::debug!(fqdn = %fqdn, "No SCITT headers — falling back to badge");
                return self.server_verifier.verify(fqdn, server_cert).await;
            }
            return VerificationOutcome::ScittError(crate::scitt::ScittError::MissingTokenField(
                "No SCITT headers present and RequireScitt policy is active".to_string(),
            ));
        }

        // Headers are present — SCITT result is final, no badge fallback.
        let scitt_cache = self.scitt_verification_cache.as_deref();
        match Self::try_scitt_verification(
            server_cert,
            headers,
            key_store,
            config,
            true,
            scitt_cache,
        )
        .await
        {
            Some(outcome) => outcome,
            None => {
                // Headers present but no status token decoded — hard reject.
                VerificationOutcome::ScittError(crate::scitt::ScittError::MissingTokenField(
                    "SCITT headers present but no valid status token found".to_string(),
                ))
            }
        }
    }

    /// SCITT-first client verification with optional badge fallback
    /// **only when headers are completely absent**.
    #[cfg(feature = "scitt")]
    async fn verify_client_scitt_first(
        &self,
        client_cert: &CertIdentity,
        headers: &crate::scitt::ScittHeaders,
        key_store: &Arc<crate::scitt::RefreshableKeyStore>,
        config: &ScittConfig,
        allow_badge_fallback: bool,
    ) -> VerificationOutcome {
        if headers.is_empty() {
            if allow_badge_fallback {
                tracing::debug!("No SCITT headers on client — falling back to badge");
                return self.client_verifier.verify(client_cert).await;
            }
            return VerificationOutcome::ScittError(crate::scitt::ScittError::MissingTokenField(
                "No SCITT headers present and RequireScitt policy is active".to_string(),
            ));
        }

        // Headers are present — SCITT result is final, no badge fallback.
        let scitt_cache = self.scitt_verification_cache.as_deref();
        match Self::try_scitt_verification(
            client_cert,
            headers,
            key_store,
            config,
            false,
            scitt_cache,
        )
        .await
        {
            Some(outcome) => outcome,
            None => VerificationOutcome::ScittError(crate::scitt::ScittError::MissingTokenField(
                "SCITT headers present but no valid status token found".to_string(),
            )),
        }
    }

    /// Attempt SCITT verification from headers. Returns `None` if no status token.
    ///
    /// Uses a two-layer caching strategy to avoid redundant cryptographic work:
    /// - **Layer 2**: Full outcome cache keyed by `(cert_fp, token_hash, receipt_hash?)`.
    ///   A hit returns immediately with zero crypto.
    /// - **Layer 1**: Content-addressed token and receipt caches. A hit skips
    ///   ECDSA signature verification (~1ms saved per hit).
    ///
    /// On [`UnknownKeyId`](crate::scitt::ScittError::UnknownKeyId), triggers
    /// an on-demand key refresh (respects cooldown) and retries once. This
    /// handles key rotations between periodic refresh cycles without allowing
    /// amplification attacks from garbage `kid` values.
    ///
    /// Only successful verifications are cached. Errors are never stored.
    ///
    /// The `is_server` flag controls which cert array to match:
    /// - `true`: matches against `valid_server_certs`
    /// - `false`: matches against `valid_identity_certs`
    #[cfg(feature = "scitt")]
    #[allow(clippy::too_many_lines)] // verification + caching flow reads best as a single method
    async fn try_scitt_verification(
        cert: &CertIdentity,
        headers: &crate::scitt::ScittHeaders,
        key_store: &Arc<crate::scitt::RefreshableKeyStore>,
        config: &ScittConfig,
        is_server: bool,
        cache: Option<&crate::scitt::ScittVerificationCache>,
    ) -> Option<VerificationOutcome> {
        let token_bytes = headers.status_token.as_ref()?;

        // Compute content hashes for cache lookups (cheap: ~1μs each)
        let token_hash = crate::scitt::hash_bytes(token_bytes);
        let receipt_hash = headers
            .receipt
            .as_ref()
            .map(|b| crate::scitt::hash_bytes(b));

        // ── Layer 2: Full outcome cache ─────────────────────────────────
        if let Some(cache) = cache
            && let Some(outcome) = cache
                .get_outcome(cert.fingerprint(), &token_hash, receipt_hash.as_ref())
                .await
        {
            tracing::debug!("SCITT verification cache hit (Layer 2 — full outcome)");
            return Some(VerificationOutcome::ScittVerified {
                status_token: (*outcome.verified_token).clone(),
                tier: outcome.tier,
                matched_fingerprint: outcome.matched_fingerprint.clone(),
                badge: None,
            });
        }

        // ── Layer 1: Token verification cache ───────────────────────────
        let verified_token = if let Some(cached_token) = match cache {
            Some(c) => c.get_verified_token(&token_hash).await,
            None => None,
        } {
            tracing::debug!("SCITT token cache hit (Layer 1 — skipping ECDSA)");
            (*cached_token).clone()
        } else {
            // Full COSE signature verification
            let snapshot = key_store.current_snapshot().await;
            let first_result = crate::scitt::verify_status_token(
                token_bytes,
                &snapshot,
                config.clock_skew_tolerance,
            );

            // On UnknownKeyId: attempt on-demand refresh (respects cooldown) and retry once
            let vt = match first_result {
                Err(original_err @ crate::scitt::ScittError::UnknownKeyId(_)) => {
                    let refreshed = match key_store.refresh_if_cooldown_elapsed().await {
                        Ok(did_refresh) => did_refresh,
                        Err(refresh_err) => {
                            tracing::warn!(error = %refresh_err, "On-demand key refresh failed");
                            false
                        }
                    };

                    if refreshed {
                        let new_snapshot = key_store.current_snapshot().await;
                        match crate::scitt::verify_status_token(
                            token_bytes,
                            &new_snapshot,
                            config.clock_skew_tolerance,
                        ) {
                            Ok(vt) => vt,
                            Err(e) => return Some(VerificationOutcome::ScittError(e)),
                        }
                    } else {
                        return Some(VerificationOutcome::ScittError(original_err));
                    }
                }
                Ok(vt) => vt,
                Err(e) => return Some(VerificationOutcome::ScittError(e)),
            };

            // Store in Layer 1 token cache
            if let Some(cache) = cache {
                cache
                    .insert_verified_token(token_hash, Arc::new(vt.clone()))
                    .await;
            }

            vt
        };

        // ── Fingerprint comparison (always, cheap) ──────────────────────
        let fingerprint_matches = if is_server {
            crate::scitt::matches_server_cert(&verified_token.payload, cert.fingerprint())
        } else {
            crate::scitt::matches_identity_cert(&verified_token.payload, cert.fingerprint())
        };

        if !fingerprint_matches {
            return Some(VerificationOutcome::ScittError(
                crate::scitt::ScittError::MissingTokenField(format!(
                    "Certificate fingerprint {} not found in status token's {} cert list ({} entries)",
                    cert.fingerprint(),
                    if is_server { "server" } else { "identity" },
                    if is_server {
                        verified_token.payload.valid_server_certs.len()
                    } else {
                        verified_token.payload.valid_identity_certs.len()
                    }
                )),
            ));
        }

        // ── Receipt verification (Layer 1 cached) ──────────────────────
        let tier = if let Some(receipt_bytes) = &headers.receipt {
            // Safety: receipt_hash is always Some when receipt bytes are present
            // (computed at the top of this function from the same Option).
            let Some(rh) = receipt_hash.as_ref() else {
                // Defensive: should be unreachable, but fall back gracefully
                tracing::warn!("receipt_hash missing despite receipt bytes present");
                return Some(VerificationOutcome::ScittError(
                    crate::scitt::ScittError::MissingTokenField(
                        "Internal error: receipt hash not computed".to_string(),
                    ),
                ));
            };

            if let Some(_cached_receipt) = match cache {
                Some(c) => c.get_verified_receipt(rh).await,
                None => None,
            } {
                tracing::debug!("SCITT receipt cache hit (Layer 1 — skipping Merkle)");
                ans_types::VerificationTier::FullScitt
            } else {
                // Full receipt verification — needs a key store snapshot
                let snapshot = key_store.current_snapshot().await;
                match crate::scitt::verify_receipt(receipt_bytes, &snapshot) {
                    Ok(receipt) => {
                        tracing::debug!("SCITT receipt verified — FullScitt tier");
                        if let Some(cache) = cache {
                            cache.insert_verified_receipt(*rh, Arc::new(receipt)).await;
                        }
                        ans_types::VerificationTier::FullScitt
                    }
                    Err(e) => {
                        if matches!(config.tier_policy, ScittTierPolicy::RequireScitt) {
                            tracing::error!(error = %e, "Receipt verification failed under RequireScitt — rejecting");
                            return Some(VerificationOutcome::ScittError(e));
                        }
                        tracing::warn!(error = %e, "Receipt verification failed — StatusTokenVerified tier");
                        ans_types::VerificationTier::StatusTokenVerified
                    }
                }
            }
        } else {
            ans_types::VerificationTier::StatusTokenVerified
        };

        // ── Store in Layer 2 outcome cache ──────────────────────────────
        if let Some(cache) = cache {
            cache
                .insert_outcome(
                    cert.fingerprint(),
                    &token_hash,
                    receipt_hash.as_ref(),
                    crate::scitt::CachedScittOutcome {
                        verified_token: Arc::new(verified_token.clone()),
                        tier,
                        matched_fingerprint: cert.fingerprint().clone(),
                        exp: verified_token.payload.exp,
                    },
                )
                .await;
        }

        Some(VerificationOutcome::ScittVerified {
            status_token: verified_token,
            tier,
            matched_fingerprint: cert.fingerprint().clone(),
            badge: None,
        })
    }
}

/// Builder for `AnsVerifier`.
#[derive(Default)]
pub struct AnsVerifierBuilder {
    dns_resolver: Option<Arc<dyn DnsResolver>>,
    dns_config: Option<DnsResolverConfig>,
    dns_nameservers: Option<Vec<std::net::Ipv4Addr>>,
    tlog_client: Option<Arc<dyn TransparencyLogClient>>,
    cache_config: Option<CacheConfig>,
    failure_policy: FailurePolicy,
    dane_policy: DanePolicy,
    dane_port: Option<u16>,
    trusted_ra_domains: Option<HashSet<String>>,
    #[cfg(feature = "rustls")]
    private_ca_pem: Option<Vec<u8>>,
    #[cfg(feature = "scitt")]
    scitt_config: Option<ScittConfig>,
    #[cfg(feature = "scitt")]
    scitt_key_store: Option<Arc<crate::scitt::RefreshableKeyStore>>,
    #[cfg(feature = "scitt")]
    scitt_verification_cache: Option<Arc<crate::scitt::ScittVerificationCache>>,
}

impl fmt::Debug for AnsVerifierBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let builder = &mut f.debug_struct("AnsVerifierBuilder");
        builder
            .field("dns_config", &self.dns_config)
            .field("failure_policy", &self.failure_policy)
            .field("dane_policy", &self.dane_policy)
            .field("dane_port", &self.dane_port)
            .field("has_dns_resolver", &self.dns_resolver.is_some())
            .field("has_tlog_client", &self.tlog_client.is_some())
            .field("has_cache_config", &self.cache_config.is_some());
        #[cfg(feature = "scitt")]
        builder
            .field("has_scitt_config", &self.scitt_config.is_some())
            .field("has_scitt_key_store", &self.scitt_key_store.is_some());
        builder.finish_non_exhaustive()
    }
}

impl AnsVerifierBuilder {
    /// Set a custom DNS resolver.
    pub fn dns_resolver(mut self, resolver: Arc<dyn DnsResolver>) -> Self {
        self.dns_resolver = Some(resolver);
        self
    }

    /// Use a preset DNS resolver configuration (Cloudflare, Google, etc.).
    ///
    /// # Example
    /// ```rust,no_run
    /// use ans_verify::{AnsVerifier, DnsResolverConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let verifier = AnsVerifier::builder()
    ///     .dns_preset(DnsResolverConfig::CloudflareTls)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn dns_preset(mut self, preset: DnsResolverConfig) -> Self {
        self.dns_config = Some(preset);
        self
    }

    /// Use Cloudflare DNS (1.1.1.1).
    pub fn dns_cloudflare(self) -> Self {
        self.dns_preset(DnsResolverConfig::Cloudflare)
    }

    /// Use Cloudflare DNS over TLS.
    pub fn dns_cloudflare_tls(self) -> Self {
        self.dns_preset(DnsResolverConfig::CloudflareTls)
    }

    /// Use Google Public DNS (8.8.8.8).
    pub fn dns_google(self) -> Self {
        self.dns_preset(DnsResolverConfig::Google)
    }

    /// Use Google DNS over TLS.
    pub fn dns_google_tls(self) -> Self {
        self.dns_preset(DnsResolverConfig::GoogleTls)
    }

    /// Use Quad9 DNS (9.9.9.9).
    pub fn dns_quad9(self) -> Self {
        self.dns_preset(DnsResolverConfig::Quad9)
    }

    /// Use custom DNS nameservers.
    ///
    /// # Example
    /// ```rust,no_run
    /// use ans_verify::AnsVerifier;
    /// use std::net::Ipv4Addr;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let verifier = AnsVerifier::builder()
    ///     .dns_nameservers(&[
    ///         Ipv4Addr::new(1, 1, 1, 1),
    ///         Ipv4Addr::new(8, 8, 8, 8),
    ///     ])
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn dns_nameservers(mut self, nameservers: &[std::net::Ipv4Addr]) -> Self {
        self.dns_nameservers = Some(nameservers.to_vec());
        self
    }

    /// Set a custom transparency log client.
    pub fn tlog_client(mut self, client: Arc<dyn TransparencyLogClient>) -> Self {
        self.tlog_client = Some(client);
        self
    }

    /// Enable caching with default configuration.
    pub fn with_caching(mut self) -> Self {
        self.cache_config = Some(CacheConfig::default());
        #[cfg(feature = "scitt")]
        if self.scitt_verification_cache.is_none() {
            self.scitt_verification_cache = Some(Arc::new(
                crate::scitt::ScittVerificationCache::with_defaults(),
            ));
        }
        self
    }

    /// Enable caching with custom configuration.
    pub fn with_cache_config(mut self, config: CacheConfig) -> Self {
        self.cache_config = Some(config);
        self
    }

    /// Set the failure policy.
    pub fn failure_policy(mut self, policy: FailurePolicy) -> Self {
        self.failure_policy = policy;
        self
    }

    /// Set the DANE/TLSA verification policy.
    ///
    /// - `DanePolicy::Disabled`: Skip DANE verification entirely (default)
    /// - `DanePolicy::ValidateIfPresent`: Verify TLSA if records exist, skip if not
    /// - `DanePolicy::Required`: Require TLSA records to exist and match
    pub fn dane_policy(mut self, policy: DanePolicy) -> Self {
        self.dane_policy = policy;
        self
    }

    /// Enable DANE verification if TLSA records are present.
    pub fn with_dane_if_present(mut self) -> Self {
        self.dane_policy = DanePolicy::ValidateIfPresent;
        self
    }

    /// Require DANE verification (fail if no TLSA records).
    pub fn require_dane(mut self) -> Self {
        self.dane_policy = DanePolicy::Required;
        self
    }

    /// Set the port for TLSA lookups (default: 443).
    pub fn dane_port(mut self, port: u16) -> Self {
        self.dane_port = Some(port);
        self
    }

    /// Restrict badge URL fetches to a set of trusted RA domains.
    ///
    /// When configured, badge URLs discovered via DNS TXT records will be
    /// validated against this set before any HTTP request is made.
    pub fn trusted_ra_domains(
        mut self,
        domains: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.trusted_ra_domains = Some(domains.into_iter().map(Into::into).collect());
        self
    }

    /// Set the ANS Private CA certificate (PEM-encoded).
    ///
    /// Required for mTLS client verification. The Private CA is used during
    /// the TLS handshake to validate that client certificates chain to the
    /// ANS Private CA. Different environments (OTE, PROD) use different CAs.
    ///
    /// The PEM bytes are typically loaded from configuration, not hardcoded.
    #[cfg(feature = "rustls")]
    pub fn private_ca_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.private_ca_pem = Some(pem.into());
        self
    }

    /// Enable SCITT verification with the given configuration.
    ///
    /// When set, the `verify_server_with_scitt` and `verify_client_with_scitt`
    /// methods become available on the resulting `AnsVerifier`.
    #[cfg(feature = "scitt")]
    pub fn scitt_config(mut self, config: ScittConfig) -> Self {
        self.scitt_config = Some(config);
        self
    }

    /// Pre-configure SCITT root keys (static, no refresh).
    ///
    /// Use this for tests or offline environments where root keys are known
    /// ahead of time. The keys are wrapped in a static
    /// [`RefreshableKeyStore`](crate::scitt::RefreshableKeyStore) with no
    /// refresh capability.
    ///
    /// For production use with automatic key refresh, use
    /// [`scitt_refreshable_key_store`](Self::scitt_refreshable_key_store).
    #[cfg(feature = "scitt")]
    #[allow(clippy::needless_pass_by_value)] // Arc param is intentional public API
    pub fn scitt_key_store(mut self, key_store: Arc<crate::scitt::ScittKeyStore>) -> Self {
        self.scitt_key_store = Some(Arc::new(crate::scitt::RefreshableKeyStore::from_static(
            (*key_store).clone(),
        )));
        self
    }

    /// Configure a refreshable SCITT root key store with periodic and
    /// on-demand refresh support.
    ///
    /// Use this for production environments. See
    /// [`RefreshableKeyStore`](crate::scitt::RefreshableKeyStore) for details
    /// on refresh behavior and anti-amplification cooldown.
    #[cfg(feature = "scitt")]
    pub fn scitt_refreshable_key_store(
        mut self,
        key_store: Arc<crate::scitt::RefreshableKeyStore>,
    ) -> Self {
        self.scitt_key_store = Some(key_store);
        self
    }

    /// Configure a custom SCITT verification cache.
    ///
    /// Overrides the default cache created by
    /// [`with_caching`](Self::with_caching). Use this when you need
    /// custom cache sizing.
    #[cfg(feature = "scitt")]
    pub fn with_scitt_verification_cache(
        mut self,
        cache: crate::scitt::ScittVerificationCache,
    ) -> Self {
        self.scitt_verification_cache = Some(Arc::new(cache));
        self
    }

    /// Build the verifier.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError::Configuration`] if `scitt_config` is set
    /// without a key store. Use [`scitt_key_store`](Self::scitt_key_store) or
    /// [`scitt_refreshable_key_store`](Self::scitt_refreshable_key_store) to
    /// provide one.
    pub async fn build(self) -> AnsResult<AnsVerifier> {
        // Validate SCITT configuration: config requires a key store.
        #[cfg(feature = "scitt")]
        if self.scitt_config.is_some() && self.scitt_key_store.is_none() {
            return Err(AnsError::Verification(VerificationError::Configuration(
                "scitt_config requires a key store — call scitt_key_store() or \
                 scitt_refreshable_key_store() on the builder"
                    .to_string(),
            )));
        }

        // Determine DNS resolver: custom > nameservers > preset > default
        let dns_resolver: Arc<dyn DnsResolver> = if let Some(r) = self.dns_resolver {
            r
        } else if let Some(nameservers) = self.dns_nameservers {
            Arc::new(
                HickoryDnsResolver::with_nameservers(&nameservers)
                    .await
                    .map_err(|e| AnsError::Dns(DnsError::ResolverError(e.to_string())))?,
            )
        } else if let Some(preset) = self.dns_config {
            Arc::new(
                HickoryDnsResolver::with_preset(preset)
                    .await
                    .map_err(|e| AnsError::Dns(DnsError::ResolverError(e.to_string())))?,
            )
        } else {
            Arc::new(
                HickoryDnsResolver::new()
                    .await
                    .map_err(|e| AnsError::Dns(DnsError::ResolverError(e.to_string())))?,
            )
        };

        let tlog_client: Arc<dyn TransparencyLogClient> = self
            .tlog_client
            .unwrap_or_else(|| Arc::new(HttpTransparencyLogClient::new()));

        let cache = self.cache_config.map(|c| Arc::new(BadgeCache::new(c)));
        let dane_port = self.dane_port.unwrap_or(443);

        let server_verifier = ServerVerifier {
            dns_resolver: dns_resolver.clone(),
            tlog_client: tlog_client.clone(),
            cache: cache.clone(),
            failure_policy: self.failure_policy,
            dane_policy: self.dane_policy,
            dane_port,
            trusted_ra_domains: self.trusted_ra_domains.clone(),
        };

        let client_verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache,
            failure_policy: self.failure_policy,
            trusted_ra_domains: self.trusted_ra_domains,
        };

        Ok(AnsVerifier {
            server_verifier,
            client_verifier,
            #[cfg(feature = "rustls")]
            private_ca_pem: self.private_ca_pem,
            #[cfg(feature = "scitt")]
            scitt_config: self.scitt_config,
            #[cfg(feature = "scitt")]
            scitt_key_store: self.scitt_key_store,
            #[cfg(feature = "scitt")]
            scitt_verification_cache: self.scitt_verification_cache,
        })
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::MockDnsResolver;
    use crate::tlog::MockTransparencyLogClient;
    use chrono::Utc;
    use uuid::Uuid;

    // Compile-time thread safety proof — fails compilation if any field
    // breaks Send/Sync (e.g., Rc, RefCell added to a struct).
    const fn _assert_send_sync<T: Send + Sync>() {}
    const _: () = _assert_send_sync::<ServerVerifier>();
    const _: () = _assert_send_sync::<ClientVerifier>();
    const _: () = _assert_send_sync::<AnsVerifier>();
    const _: () = _assert_send_sync::<BadgeCache>();

    fn create_test_badge(host: &str, version: &str, server_fp: &str, identity_fp: &str) -> Badge {
        serde_json::from_value(serde_json::json!({
            "status": "ACTIVE",
            "schemaVersion": "V1",
            "payload": {
                "logId": Uuid::new_v4().to_string(),
                "producer": {
                    "event": {
                        "ansId": Uuid::new_v4().to_string(),
                        "ansName": format!("ans://{version}.{host}"),
                        "eventType": "AGENT_REGISTERED",
                        "agent": { "host": host, "name": "Test Agent", "version": version },
                        "attestations": {
                            "domainValidation": "ACME-DNS-01",
                            "identityCert": { "fingerprint": identity_fp, "type": "X509-OV-CLIENT" },
                            "serverCert": { "fingerprint": server_fp, "type": "X509-DV-SERVER" }
                        },
                        "expiresAt": (Utc::now() + chrono::Duration::days(365)).to_rfc3339(),
                        "issuedAt": Utc::now().to_rfc3339(),
                        "raId": "test-ra",
                        "timestamp": Utc::now().to_rfc3339()
                    },
                    "keyId": "test-key",
                    "signature": "test-sig"
                }
            }
        })).expect("test badge JSON should be valid")
    }

    fn create_test_cert_identity(cn: &str, fingerprint: &str) -> CertIdentity {
        CertIdentity {
            common_name: Some(cn.to_string()),
            dns_sans: vec![cn.to_string()],
            uri_sans: vec![],
            fingerprint: CertFingerprint::parse(fingerprint).unwrap(),
        }
    }

    #[tokio::test]
    async fn test_server_verification_success() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));

        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, fingerprint);
        let fqdn = Fqdn::new(host).unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(outcome.is_success());
    }

    #[tokio::test]
    async fn test_server_verification_not_ans_agent() {
        let dns_resolver = Arc::new(MockDnsResolver::new());
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(
            "unknown.example.com",
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        );
        let fqdn = Fqdn::new("unknown.example.com").unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(outcome.is_not_ans_agent());
    }

    #[tokio::test]
    async fn test_server_verification_fingerprint_mismatch() {
        let host = "test.example.com";
        let badge_fingerprint =
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
        let cert_fingerprint =
            "SHA256:0000000000000000000000000000000000000000000000000000000000000000";

        let badge = create_test_badge(host, "v1.0.0", badge_fingerprint, "SHA256:aaa");
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));

        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, cert_fingerprint);
        let fqdn = Fqdn::new(host).unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(matches!(
            outcome,
            VerificationOutcome::FingerprintMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn test_server_verification_invalid_status() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let mut badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        badge.status = BadgeStatus::Revoked;

        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));

        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, fingerprint);
        let fqdn = Fqdn::new(host).unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(matches!(
            outcome,
            VerificationOutcome::InvalidStatus {
                status: BadgeStatus::Revoked,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_verification_outcome_is_success() {
        let badge = create_test_badge(
            "test.example.com",
            "v1.0.0",
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            "SHA256:aaa",
        );

        let outcome = VerificationOutcome::Verified {
            badge,
            matched_fingerprint: CertFingerprint::parse(
                "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            )
            .unwrap(),
        };

        assert!(outcome.is_success());
        assert!(!outcome.is_not_ans_agent());
    }

    #[tokio::test]
    async fn test_verification_with_cache() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let cache = Arc::new(BadgeCache::with_defaults());
        let fqdn = Fqdn::new(host).unwrap();

        // Pre-populate cache
        cache
            .insert_for_fqdn_version(&fqdn, &Version::new(1, 0, 0), badge)
            .await;

        // Create verifier with empty DNS/TLog (should use cache)
        let dns_resolver = Arc::new(MockDnsResolver::new());
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: Some(cache),
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, fingerprint);

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(outcome.is_success());
    }

    #[test]
    fn test_cert_identity_from_components() {
        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        let identity = CertIdentity::new(
            Some("test.example.com".to_string()),
            vec!["test.example.com".to_string()],
            vec!["ans://v1.0.0.test.example.com".to_string()],
            fingerprint,
        );

        assert_eq!(identity.fqdn(), Some("test.example.com"));
        assert!(identity.ans_name().is_some());
        assert_eq!(identity.version(), Some(Version::new(1, 0, 0)));
    }

    #[test]
    fn test_cert_identity_from_fingerprint_and_cn() {
        let fingerprint = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();

        let identity =
            CertIdentity::from_fingerprint_and_cn(fingerprint, "test.example.com".to_string());

        assert_eq!(identity.fqdn(), Some("test.example.com"));
        assert!(identity.ans_name().is_none()); // No URI SANs
    }

    // =========================================================================
    // ClientVerifier Tests
    // =========================================================================

    fn create_mtls_cert_identity(host: &str, version: &str, fingerprint: &str) -> CertIdentity {
        CertIdentity {
            common_name: Some(host.to_string()),
            dns_sans: vec![host.to_string()],
            uri_sans: vec![format!("ans://{}.{}", version, host)],
            fingerprint: CertFingerprint::parse(fingerprint).unwrap(),
        }
    }

    #[tokio::test]
    async fn test_client_verification_success() {
        let host = "test.example.com";
        let version = "v1.0.0";
        let identity_fp = "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496";
        let server_fp = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge = create_test_badge(host, version, server_fp, identity_fp);
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            trusted_ra_domains: None,
        };

        let cert = create_mtls_cert_identity(host, version, identity_fp);
        let outcome = verifier.verify(&cert).await;

        assert!(outcome.is_success(), "Expected success, got: {:?}", outcome);
    }

    #[tokio::test]
    async fn test_client_verification_no_fqdn() {
        let dns_resolver = Arc::new(MockDnsResolver::new());
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            trusted_ra_domains: None,
        };

        // Create cert with no CN or DNS SANs
        let cert = CertIdentity {
            common_name: None,
            dns_sans: vec![],
            uri_sans: vec!["ans://v1.0.0.test.example.com".to_string()],
            fingerprint: CertFingerprint::parse(
                "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            )
            .unwrap(),
        };

        let outcome = verifier.verify(&cert).await;
        assert!(matches!(outcome, VerificationOutcome::CertError(_)));
    }

    #[tokio::test]
    async fn test_client_verification_no_ans_name() {
        let dns_resolver = Arc::new(MockDnsResolver::new());
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            trusted_ra_domains: None,
        };

        // Create cert with CN but no URI SANs
        let cert = CertIdentity {
            common_name: Some("test.example.com".to_string()),
            dns_sans: vec!["test.example.com".to_string()],
            uri_sans: vec![],
            fingerprint: CertFingerprint::parse(
                "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            )
            .unwrap(),
        };

        let outcome = verifier.verify(&cert).await;
        assert!(matches!(outcome, VerificationOutcome::CertError(_)));
    }

    #[tokio::test]
    async fn test_client_verification_fingerprint_mismatch() {
        let host = "test.example.com";
        let version = "v1.0.0";
        let badge_identity_fp =
            "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496";
        let cert_identity_fp =
            "SHA256:0000000000000000000000000000000000000000000000000000000000000000";

        let badge = create_test_badge(host, version, "SHA256:server", badge_identity_fp);
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            trusted_ra_domains: None,
        };

        let cert = create_mtls_cert_identity(host, version, cert_identity_fp);
        let outcome = verifier.verify(&cert).await;

        assert!(matches!(
            outcome,
            VerificationOutcome::FingerprintMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn test_client_verification_ans_name_mismatch() {
        let host = "test.example.com";
        let badge_version = "v1.0.0";
        let cert_version = "v2.0.0";
        let identity_fp = "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496";

        // Badge has v1.0.0, cert has v2.0.0
        let badge = create_test_badge(host, badge_version, "SHA256:server", identity_fp);
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(2, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            trusted_ra_domains: None,
        };

        let cert = create_mtls_cert_identity(host, cert_version, identity_fp);
        let outcome = verifier.verify(&cert).await;

        assert!(matches!(
            outcome,
            VerificationOutcome::AnsNameMismatch { .. }
        ));
    }

    // =========================================================================
    // VerificationOutcome Tests
    // =========================================================================

    #[test]
    fn test_verification_outcome_badge() {
        let badge = create_test_badge(
            "test.example.com",
            "v1.0.0",
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            "SHA256:aaa",
        );

        // Verified has badge
        let outcome = VerificationOutcome::Verified {
            badge: badge.clone(),
            matched_fingerprint: CertFingerprint::parse(
                "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            )
            .unwrap(),
        };
        assert!(outcome.badge().is_some());

        // InvalidStatus has badge
        let outcome = VerificationOutcome::InvalidStatus {
            status: BadgeStatus::Revoked,
            badge: badge.clone(),
        };
        assert!(outcome.badge().is_some());

        // FingerprintMismatch has badge
        let outcome = VerificationOutcome::FingerprintMismatch {
            expected: "SHA256:a".to_string(),
            actual: "SHA256:b".to_string(),
            badge: badge.clone(),
        };
        assert!(outcome.badge().is_some());

        // HostnameMismatch has badge
        let outcome = VerificationOutcome::HostnameMismatch {
            expected: "a.com".to_string(),
            actual: "b.com".to_string(),
            badge: badge.clone(),
        };
        assert!(outcome.badge().is_some());

        // AnsNameMismatch has badge
        let outcome = VerificationOutcome::AnsNameMismatch {
            expected: "ans://v1.0.0.a.com".to_string(),
            actual: "ans://v2.0.0.a.com".to_string(),
            badge,
        };
        assert!(outcome.badge().is_some());

        // NotAnsAgent has no badge
        let outcome = VerificationOutcome::NotAnsAgent {
            fqdn: "test.com".to_string(),
        };
        assert!(outcome.badge().is_none());

        // DnsError has no badge
        let outcome = VerificationOutcome::DnsError(DnsError::NotFound {
            fqdn: "test.com".to_string(),
        });
        assert!(outcome.badge().is_none());
    }

    #[test]
    fn test_verification_outcome_into_result() {
        let badge = create_test_badge(
            "test.example.com",
            "v1.0.0",
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            "SHA256:aaa",
        );

        // Verified -> Ok
        let outcome = VerificationOutcome::Verified {
            badge: badge.clone(),
            matched_fingerprint: CertFingerprint::parse(
                "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            )
            .unwrap(),
        };
        assert!(outcome.into_result().is_ok());

        // NotAnsAgent -> Err
        let outcome = VerificationOutcome::NotAnsAgent {
            fqdn: "test.com".to_string(),
        };
        assert!(outcome.into_result().is_err());

        // InvalidStatus -> Err
        let outcome = VerificationOutcome::InvalidStatus {
            status: BadgeStatus::Revoked,
            badge: badge.clone(),
        };
        assert!(outcome.into_result().is_err());

        // FingerprintMismatch -> Err
        let outcome = VerificationOutcome::FingerprintMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
            badge: badge.clone(),
        };
        assert!(outcome.into_result().is_err());

        // HostnameMismatch -> Err
        let outcome = VerificationOutcome::HostnameMismatch {
            expected: "a.com".to_string(),
            actual: "b.com".to_string(),
            badge: badge.clone(),
        };
        assert!(outcome.into_result().is_err());

        // AnsNameMismatch -> Err
        let outcome = VerificationOutcome::AnsNameMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
            badge,
        };
        assert!(outcome.into_result().is_err());

        // DnsError -> Err
        let outcome = VerificationOutcome::DnsError(DnsError::NotFound {
            fqdn: "test.com".to_string(),
        });
        assert!(outcome.into_result().is_err());

        // TlogError -> Err
        let outcome = VerificationOutcome::TlogError(TlogError::ServiceUnavailable);
        assert!(outcome.into_result().is_err());

        // DaneError -> Err
        let outcome = VerificationOutcome::DaneError(DaneError::FingerprintMismatch);
        assert!(outcome.into_result().is_err());
    }

    // =========================================================================
    // Hostname Mismatch Tests
    // =========================================================================

    #[tokio::test]
    async fn test_server_verification_hostname_mismatch() {
        let badge_host = "badge.example.com";
        let cert_host = "different.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge = create_test_badge(badge_host, "v1.0.0", fingerprint, "SHA256:aaa");
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        // DNS lookup uses cert_host but badge contains badge_host
        let dns_resolver =
            Arc::new(MockDnsResolver::new().with_records(cert_host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(cert_host, fingerprint);
        let fqdn = Fqdn::new(cert_host).unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(
            matches!(outcome, VerificationOutcome::HostnameMismatch { .. }),
            "Expected HostnameMismatch, got: {:?}",
            outcome
        );
    }

    // =========================================================================
    // Prefetch Tests
    // =========================================================================

    #[tokio::test]
    async fn test_server_verifier_prefetch_success() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client =
            Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge.clone()));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: Some(Arc::new(BadgeCache::with_defaults())),
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let fqdn = Fqdn::new(host).unwrap();
        let result = verifier.prefetch(&fqdn).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().agent_host(), host);
    }

    #[tokio::test]
    async fn test_server_verifier_prefetch_not_found() {
        let dns_resolver = Arc::new(MockDnsResolver::new());
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let fqdn = Fqdn::new("unknown.example.com").unwrap();
        let result = verifier.prefetch(&fqdn).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AnsError::Dns(_)));
    }

    // =========================================================================
    // FailurePolicy Tests
    // =========================================================================

    #[tokio::test]
    async fn test_failure_policy_fail_open_with_cache_no_cache() {
        let dns_resolver = Arc::new(MockDnsResolver::new().with_error(
            "test.example.com",
            DnsError::LookupFailed {
                fqdn: "test.example.com".to_string(),
                reason: "timeout".to_string(),
            },
        ));
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: Some(Arc::new(BadgeCache::with_defaults())),
            failure_policy: FailurePolicy::FailOpenWithCache {
                max_staleness: Duration::from_secs(600),
            },
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(
            "test.example.com",
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        );
        let fqdn = Fqdn::new("test.example.com").unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        // No cached badge, so returns DNS error
        assert!(matches!(outcome, VerificationOutcome::DnsError(_)));
    }

    #[tokio::test]
    async fn test_failure_policy_fail_open_with_cache_uses_cache() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let cache = Arc::new(BadgeCache::with_defaults());
        let fqdn = Fqdn::new(host).unwrap();

        // Pre-populate cache
        cache
            .insert_for_fqdn_version(&fqdn, &Version::new(1, 0, 0), badge)
            .await;

        let dns_resolver = Arc::new(MockDnsResolver::new().with_error(
            host,
            DnsError::LookupFailed {
                fqdn: host.to_string(),
                reason: "timeout".to_string(),
            },
        ));
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: Some(cache),
            failure_policy: FailurePolicy::FailOpenWithCache {
                max_staleness: Duration::from_secs(600),
            },
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, fingerprint);

        let outcome = verifier.verify(&fqdn, &cert).await;
        // Should use cached badge and verify successfully
        assert!(
            outcome.is_success(),
            "Expected success with cache, got: {:?}",
            outcome
        );
    }

    #[test]
    fn test_cert_identity_from_der_server_cert() {
        use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, SanType};

        // Generate a server certificate on the fly
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "test.agent.local");
        params.subject_alt_names.push(SanType::DnsName(
            "test.agent.local".to_string().try_into().unwrap(),
        ));
        params.subject_alt_names.push(SanType::URI(
            "ans://v1.0.0.test.agent.local".try_into().unwrap(),
        ));
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der();

        let identity = CertIdentity::from_der(der).expect("should parse DER certificate");

        // Verify CN
        assert_eq!(
            identity.common_name.as_deref(),
            Some("test.agent.local"),
            "CN should be test.agent.local"
        );

        // Verify DNS SAN
        assert!(
            identity.dns_sans.contains(&"test.agent.local".to_string()),
            "DNS SANs should contain test.agent.local, got: {:?}",
            identity.dns_sans
        );

        // Verify URI SAN (ANS name)
        assert!(
            identity
                .uri_sans
                .contains(&"ans://v1.0.0.test.agent.local".to_string()),
            "URI SANs should contain ans://v1.0.0.test.agent.local, got: {:?}",
            identity.uri_sans
        );

        // Verify fingerprint matches what we compute from the same DER bytes
        let expected_fp = CertFingerprint::from_der(der);
        assert_eq!(
            identity.fingerprint, expected_fp,
            "Fingerprint should match computed fingerprint from same DER"
        );

        // Verify convenience methods
        assert_eq!(identity.fqdn(), Some("test.agent.local"));
        let ans_name = identity.ans_name().expect("should have ANS name");
        assert_eq!(ans_name.fqdn().as_str(), "test.agent.local");
        assert_eq!(identity.version(), Some(Version::new(1, 0, 0)));
    }

    #[test]
    fn test_cert_identity_from_der_client_cert() {
        use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, SanType};

        // Generate a client (identity) certificate on the fly
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "test.agent.local");
        params.subject_alt_names.push(SanType::DnsName(
            "test.agent.local".to_string().try_into().unwrap(),
        ));
        params.subject_alt_names.push(SanType::URI(
            "ans://v1.0.0.test.agent.local".try_into().unwrap(),
        ));
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

        let cert = params.self_signed(&key_pair).unwrap();
        let der = cert.der();

        let identity = CertIdentity::from_der(der).expect("should parse DER certificate");

        assert_eq!(identity.common_name.as_deref(), Some("test.agent.local"));
        assert!(identity.dns_sans.contains(&"test.agent.local".to_string()));
        assert!(
            identity
                .uri_sans
                .contains(&"ans://v1.0.0.test.agent.local".to_string())
        );

        let expected_fp = CertFingerprint::from_der(der);
        assert_eq!(identity.fingerprint, expected_fp);
    }

    #[test]
    fn test_cert_identity_from_der_invalid_bytes() {
        let result = CertIdentity::from_der(b"not a certificate");
        assert!(result.is_err(), "Should fail on invalid DER bytes");
    }

    #[tokio::test]
    async fn test_server_verifier_builder_dane_policy() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        // with_dane_if_present convenience method
        let verifier = ServerVerifier::builder()
            .dns_resolver(dns.clone())
            .tlog_client(tlog.clone())
            .with_dane_if_present()
            .build()
            .await
            .unwrap();
        assert_eq!(verifier.dane_policy, DanePolicy::ValidateIfPresent);

        // require_dane convenience method
        let verifier = ServerVerifier::builder()
            .dns_resolver(dns.clone())
            .tlog_client(tlog.clone())
            .require_dane()
            .build()
            .await
            .unwrap();
        assert_eq!(verifier.dane_policy, DanePolicy::Required);

        // explicit dane_policy
        let verifier = ServerVerifier::builder()
            .dns_resolver(dns.clone())
            .tlog_client(tlog.clone())
            .dane_policy(DanePolicy::Disabled)
            .build()
            .await
            .unwrap();
        assert_eq!(verifier.dane_policy, DanePolicy::Disabled);
    }

    #[tokio::test]
    async fn test_server_verifier_builder_dane_port() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        // Default port is 443
        let verifier = ServerVerifier::builder()
            .dns_resolver(dns.clone())
            .tlog_client(tlog.clone())
            .build()
            .await
            .unwrap();
        assert_eq!(verifier.dane_port, 443);

        // Custom port
        let verifier = ServerVerifier::builder()
            .dns_resolver(dns.clone())
            .tlog_client(tlog.clone())
            .dane_port(8443)
            .build()
            .await
            .unwrap();
        assert_eq!(verifier.dane_port, 8443);
    }

    #[tokio::test]
    async fn test_server_verifier_builder_failure_policy() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier::builder()
            .dns_resolver(dns)
            .tlog_client(tlog)
            .failure_policy(FailurePolicy::FailClosed)
            .build()
            .await
            .unwrap();
        assert!(matches!(verifier.failure_policy, FailurePolicy::FailClosed));
    }

    // =========================================================================
    // Refresh-on-Mismatch Tests
    // =========================================================================

    #[tokio::test]
    async fn test_server_verification_refresh_on_mismatch_succeeds() {
        let host = "test.example.com";
        let old_fp = "SHA256:0000000000000000000000000000000000000000000000000000000000000000";
        let new_fp = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        // First badge has old fingerprint (will mismatch)
        // After refresh, tlog returns badge with new fingerprint
        let badge_url = "https://tlog.example.com/v1/agents/test-id";
        let updated_badge = create_test_badge(host, "v1.0.0", new_fp, "SHA256:aaa");

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        // Mock always returns updated badge (simulates tlog updated after cert renewal)
        let tlog_client =
            Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, updated_badge));

        let cache = Arc::new(BadgeCache::with_defaults());
        let fqdn = Fqdn::new(host).unwrap();

        // Pre-populate cache with stale badge (old fingerprint)
        let stale_badge = create_test_badge(host, "v1.0.0", old_fp, "SHA256:aaa");
        cache
            .insert_for_fqdn_version(&fqdn, &Version::new(1, 0, 0), stale_badge)
            .await;

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: Some(cache),
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        // Cert has the NEW fingerprint — cache has OLD → mismatch → refresh → success
        let cert = create_test_cert_identity(host, new_fp);
        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(
            outcome.is_success(),
            "Expected success after refresh, got: {:?}",
            outcome
        );
    }

    #[tokio::test]
    async fn test_server_verification_refresh_on_mismatch_still_fails() {
        let host = "test.example.com";
        let badge_fp = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
        let cert_fp = "SHA256:0000000000000000000000000000000000000000000000000000000000000000";

        let badge_url = "https://tlog.example.com/v1/agents/test-id";
        // Badge always has badge_fp, cert always has cert_fp — never matches
        let badge = create_test_badge(host, "v1.0.0", badge_fp, "SHA256:aaa");

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, cert_fp);
        let fqdn = Fqdn::new(host).unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(
            matches!(outcome, VerificationOutcome::FingerprintMismatch { .. }),
            "Expected FingerprintMismatch after refresh still fails, got: {:?}",
            outcome
        );
    }

    #[tokio::test]
    async fn test_client_verification_refresh_on_mismatch_succeeds() {
        let host = "test.example.com";
        let version = "v1.0.0";
        let old_identity_fp =
            "SHA256:0000000000000000000000000000000000000000000000000000000000000000";
        let new_identity_fp =
            "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496";
        let server_fp = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge_url = "https://tlog.example.com/v1/agents/test-id";
        // Tlog returns updated badge with new identity fingerprint
        let updated_badge = create_test_badge(host, version, server_fp, new_identity_fp);

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client =
            Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, updated_badge));

        let cache = Arc::new(BadgeCache::with_defaults());
        let fqdn = Fqdn::new(host).unwrap();
        let ver = Version::new(1, 0, 0);

        // Pre-populate cache with stale badge (old identity fingerprint)
        let stale_badge = create_test_badge(host, version, server_fp, old_identity_fp);
        cache
            .insert_for_fqdn_version(&fqdn, &ver, stale_badge)
            .await;

        let verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: Some(cache),
            failure_policy: FailurePolicy::FailClosed,
            trusted_ra_domains: None,
        };

        // Client cert has new fingerprint — cache has old → mismatch → refresh → success
        let cert = create_mtls_cert_identity(host, version, new_identity_fp);
        let outcome = verifier.verify(&cert).await;
        assert!(
            outcome.is_success(),
            "Expected success after client refresh, got: {:?}",
            outcome
        );
    }

    // =========================================================================
    // Trusted RA Domain Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_badge_domain_unit_allows_when_none() {
        assert!(validate_badge_domain(None, "https://tlog.example.com/v1/agents/test").is_ok());
    }

    #[test]
    fn test_validate_badge_domain_unit_allows_trusted() {
        let trusted: HashSet<String> = ["tlog.example.com".to_string()].into();
        assert!(
            validate_badge_domain(Some(&trusted), "https://tlog.example.com/v1/agents/test")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_badge_domain_unit_rejects_untrusted() {
        let trusted: HashSet<String> = ["tlog.example.com".to_string()].into();
        let err = validate_badge_domain(Some(&trusted), "https://evil.attacker.com/v1/agents/test")
            .unwrap_err();
        assert!(
            matches!(err, TlogError::UntrustedDomain { domain, .. } if domain == "evil.attacker.com")
        );
    }

    #[test]
    fn test_validate_badge_domain_unit_multiple_trusted() {
        let trusted: HashSet<String> = [
            "tlog1.example.com".to_string(),
            "tlog2.example.com".to_string(),
        ]
        .into();
        assert!(validate_badge_domain(Some(&trusted), "https://tlog1.example.com/badge").is_ok());
        assert!(validate_badge_domain(Some(&trusted), "https://tlog2.example.com/badge").is_ok());
        assert!(validate_badge_domain(Some(&trusted), "https://tlog3.example.com/badge").is_err());
    }

    #[tokio::test]
    async fn test_trusted_ra_none_allows_all() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let badge_url = "https://any-domain.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };
        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, fingerprint);
        let fqdn = Fqdn::new(host).unwrap();
        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(outcome.is_success(), "None should allow all domains");
    }

    #[tokio::test]
    async fn test_trusted_ra_allows_trusted_domain() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };
        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: Some(["tlog.example.com".to_string()].into()),
        };

        let cert = create_test_cert_identity(host, fingerprint);
        let fqdn = Fqdn::new(host).unwrap();
        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(outcome.is_success(), "Trusted domain should succeed");
    }

    #[tokio::test]
    async fn test_trusted_ra_rejects_untrusted_domain() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let badge_url = "https://evil.attacker.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };
        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Disabled,
            dane_port: 443,
            trusted_ra_domains: Some(["tlog.example.com".to_string()].into()),
        };

        let cert = create_test_cert_identity(host, fingerprint);
        let fqdn = Fqdn::new(host).unwrap();
        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(
            matches!(
                outcome,
                VerificationOutcome::TlogError(TlogError::UntrustedDomain { .. })
            ),
            "Untrusted domain should be rejected, got: {:?}",
            outcome
        );
    }

    #[tokio::test]
    async fn test_trusted_ra_client_rejects_untrusted() {
        let host = "test.example.com";
        let version = "v1.0.0";
        let identity_fp = "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496";
        let server_fp = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
        let badge = create_test_badge(host, version, server_fp, identity_fp);
        let badge_url = "https://evil.attacker.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };
        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ClientVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            trusted_ra_domains: Some(["tlog.example.com".to_string()].into()),
        };

        let cert = create_mtls_cert_identity(host, version, identity_fp);
        let outcome = verifier.verify(&cert).await;
        assert!(
            matches!(
                outcome,
                VerificationOutcome::TlogError(TlogError::UntrustedDomain { .. })
            ),
            "Client verifier should reject untrusted domain, got: {:?}",
            outcome
        );
    }

    #[tokio::test]
    async fn test_trusted_ra_builder_propagation() {
        let dns_resolver = Arc::new(MockDnsResolver::new());
        let tlog_client = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier::builder()
            .dns_resolver(dns_resolver as Arc<dyn DnsResolver>)
            .tlog_client(tlog_client as Arc<dyn TransparencyLogClient>)
            .trusted_ra_domains(["tlog.example.com", "tlog2.example.com"])
            .build()
            .await
            .unwrap();

        // Verify the builder propagated the trusted domains correctly
        let trusted = verifier.trusted_ra_domains.as_ref().unwrap();
        assert!(trusted.contains("tlog.example.com"));
        assert!(trusted.contains("tlog2.example.com"));
        assert_eq!(trusted.len(), 2);
    }

    // =========================================================================
    // 7a: VerificationOutcome::into_result() — CertError and ParseError branches
    // =========================================================================

    #[test]
    fn test_outcome_into_result_cert_error() {
        let outcome =
            VerificationOutcome::CertError(CryptoError::ParseFailed("bad cert".to_string()));
        let err = outcome.into_result().unwrap_err();
        assert!(matches!(err, AnsError::Certificate(_)));
    }

    #[test]
    fn test_outcome_into_result_parse_error() {
        let outcome = VerificationOutcome::ParseError(ans_types::ParseError::InvalidFqdn(
            "bad fqdn".to_string(),
        ));
        let err = outcome.into_result().unwrap_err();
        assert!(matches!(err, AnsError::Parse(_)));
    }

    #[test]
    fn test_outcome_into_result_dane_error() {
        let outcome = VerificationOutcome::DaneError(DaneError::FingerprintMismatch);
        let err = outcome.into_result().unwrap_err();
        assert!(matches!(
            err,
            AnsError::Verification(VerificationError::DaneVerificationFailed(_))
        ));
    }

    #[test]
    fn test_outcome_into_result_dns_error() {
        let outcome = VerificationOutcome::DnsError(DnsError::Timeout {
            fqdn: "test.example.com".to_string(),
        });
        let err = outcome.into_result().unwrap_err();
        assert!(matches!(err, AnsError::Dns(DnsError::Timeout { .. })));
    }

    #[test]
    fn test_outcome_into_result_tlog_error() {
        let outcome = VerificationOutcome::TlogError(TlogError::ServiceUnavailable);
        let err = outcome.into_result().unwrap_err();
        assert!(matches!(
            err,
            AnsError::TransparencyLog(TlogError::ServiceUnavailable)
        ));
    }

    // =========================================================================
    // 7b: AnsVerifierBuilder DNS presets
    // =========================================================================

    #[tokio::test]
    async fn test_builder_dns_cloudflare() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        // Test that the builder method configures correctly
        let verifier = AnsVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .dns_cloudflare() // preset is ignored when custom resolver is set
            .build()
            .await
            .unwrap();

        // Verify the builder produces a working verifier
        let dbg = format!("{verifier:?}");
        assert!(dbg.contains("AnsVerifier"));
    }

    #[tokio::test]
    async fn test_builder_dns_nameservers() {
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_nameservers(&[std::net::Ipv4Addr::new(1, 1, 1, 1)])
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .build()
            .await
            .unwrap();

        let dbg = format!("{verifier:?}");
        assert!(dbg.contains("AnsVerifier"));
    }

    #[tokio::test]
    async fn test_builder_dns_preset_path() {
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_preset(DnsResolverConfig::Cloudflare)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .build()
            .await
            .unwrap();

        let dbg = format!("{verifier:?}");
        assert!(dbg.contains("AnsVerifier"));
    }

    // =========================================================================
    // 7c: AnsVerifier rustls methods
    // =========================================================================

    #[cfg(feature = "rustls")]
    #[tokio::test]
    async fn test_client_cert_verifier_without_pem() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .build()
            .await
            .unwrap();

        let result = verifier.client_cert_verifier();
        assert!(result.is_err());
    }

    #[cfg(feature = "rustls")]
    #[tokio::test]
    async fn test_client_cert_verifier_with_pem() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = rcgen::generate_simple_self_signed(vec!["ANS Test CA".to_string()]).unwrap();
        let ca_pem = ca.cert.pem();

        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .private_ca_pem(ca_pem.as_bytes().to_vec())
            .build()
            .await
            .unwrap();

        let cv = verifier.client_cert_verifier().unwrap();
        assert!(cv.requires_client_cert());
    }

    #[cfg(feature = "rustls")]
    #[tokio::test]
    async fn test_client_cert_verifier_optional_with_pem() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = rcgen::generate_simple_self_signed(vec!["ANS Test CA".to_string()]).unwrap();
        let ca_pem = ca.cert.pem();

        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .private_ca_pem(ca_pem.as_bytes().to_vec())
            .build()
            .await
            .unwrap();

        let cv = verifier.client_cert_verifier_optional().unwrap();
        assert!(!cv.requires_client_cert());
    }

    #[cfg(feature = "rustls")]
    #[tokio::test]
    async fn test_server_cert_verifier() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .build()
            .await
            .unwrap();

        let fp = CertFingerprint::parse(
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
        )
        .unwrap();
        let sv = verifier.server_cert_verifier(&fp).unwrap();
        assert_eq!(sv.expected_fingerprint(), &fp);
    }

    // =========================================================================
    // 7d: Builder configuration methods
    // =========================================================================

    #[tokio::test]
    async fn test_builder_with_caching() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .with_caching()
            .build()
            .await
            .unwrap();

        // Verify the verifier was built with caching
        assert!(format!("{verifier:?}").contains("has_cache"));
    }

    #[tokio::test]
    async fn test_builder_with_cache_config() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = AnsVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .with_cache_config(CacheConfig::default())
            .build()
            .await
            .unwrap();

        assert!(format!("{verifier:?}").contains("AnsVerifier"));
    }

    #[tokio::test]
    async fn test_builder_with_dane_if_present() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .with_dane_if_present()
            .build()
            .await
            .unwrap();

        assert_eq!(verifier.dane_policy, DanePolicy::ValidateIfPresent);
    }

    #[tokio::test]
    async fn test_builder_require_dane() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .require_dane()
            .build()
            .await
            .unwrap();

        assert_eq!(verifier.dane_policy, DanePolicy::Required);
    }

    #[tokio::test]
    async fn test_builder_dane_port() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .dane_port(8443)
            .build()
            .await
            .unwrap();

        assert_eq!(verifier.dane_port, 8443);
    }

    #[tokio::test]
    async fn test_builder_trusted_ra_domains() {
        let dns = Arc::new(MockDnsResolver::new());
        let tlog = Arc::new(MockTransparencyLogClient::new());

        let verifier = ServerVerifier::builder()
            .dns_resolver(dns as Arc<dyn DnsResolver>)
            .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
            .trusted_ra_domains(["tlog.example.com"])
            .build()
            .await
            .unwrap();

        assert!(verifier.trusted_ra_domains.is_some());
        assert!(
            verifier
                .trusted_ra_domains
                .unwrap()
                .contains("tlog.example.com")
        );
    }

    // =========================================================================
    // 7e: DANE Required failure path
    // =========================================================================

    #[tokio::test]
    async fn test_dane_required_no_tlsa_records() {
        let host = "test.example.com";
        let fingerprint = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";

        let badge = create_test_badge(host, "v1.0.0", fingerprint, "SHA256:aaa");
        let badge_url = "https://tlog.example.com/v1/agents/test-id";

        let dns_record = BadgeRecord {
            format_version: "ans-badge1".to_string(),
            version: Some(Version::new(1, 0, 0)),
            url: badge_url.to_string(),
        };

        // No TLSA records configured — DANE Required should fail
        let dns_resolver = Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
        let tlog_client = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

        let verifier = ServerVerifier {
            dns_resolver,
            tlog_client,
            cache: None,
            failure_policy: FailurePolicy::FailClosed,
            dane_policy: DanePolicy::Required,
            dane_port: 443,
            trusted_ra_domains: None,
        };

        let cert = create_test_cert_identity(host, fingerprint);
        let fqdn = Fqdn::new(host).unwrap();

        let outcome = verifier.verify(&fqdn, &cert).await;
        assert!(
            matches!(outcome, VerificationOutcome::DaneError(_)),
            "Expected DaneError for required DANE with no TLSA records, got: {outcome:?}"
        );
    }

    // =========================================================================
    // VerificationOutcome helpers
    // =========================================================================

    #[test]
    fn test_outcome_badge_returns_none_for_errors() {
        let outcome = VerificationOutcome::DnsError(DnsError::Timeout {
            fqdn: "test.example.com".to_string(),
        });
        assert!(outcome.badge().is_none());

        let outcome = VerificationOutcome::NotAnsAgent {
            fqdn: "test.example.com".to_string(),
        };
        assert!(outcome.badge().is_none());
    }

    #[test]
    fn test_outcome_badge_returns_some_for_mismatches() {
        let badge = create_test_badge(
            "test.example.com",
            "v1.0.0",
            "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
            "SHA256:aaa",
        );

        let outcome = VerificationOutcome::HostnameMismatch {
            expected: "test.example.com".to_string(),
            actual: "other.example.com".to_string(),
            badge,
        };
        assert!(outcome.badge().is_some());
    }

    #[test]
    fn test_server_verifier_debug_format() {
        let dbg = format!("{:?}", ServerVerifierBuilder::default());
        assert!(dbg.contains("ServerVerifierBuilder"));
    }

    // ── SCITT integration tests ─────────────────────────────────────────────

    #[cfg(feature = "scitt")]
    mod scitt_integration {
        use super::*;
        use crate::scitt::{
            RefreshableKeyStore, ScittError, ScittHeaders, ScittKeyStore,
            compute_sig_structure_digest, verify_status_token,
        };
        use base64::prelude::{BASE64_STANDARD, Engine as _};
        use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner as _};
        use p256::pkcs8::EncodePublicKey as _;
        use sha2::{Digest, Sha256};

        // ── Test helpers ────────────────────────────────────────────────

        fn make_key_and_store(seed: u8) -> (SigningKey, ScittKeyStore) {
            let signing_key = SigningKey::from_slice(&[seed; 32]).unwrap();
            let verifying_key = signing_key.verifying_key();
            let spki_doc = verifying_key.to_public_key_der().unwrap();
            let spki_der = spki_doc.as_bytes();
            let digest = Sha256::digest(spki_der);
            let kid: [u8; 4] = [digest[0], digest[1], digest[2], digest[3]];
            let key_hash_hex = hex::encode(kid);
            let spki_b64 = BASE64_STANDARD.encode(spki_der);
            let key_string = format!("tl.example.com+{key_hash_hex}+{spki_b64}");
            let store = ScittKeyStore::from_c2sp_keys(&[key_string]).unwrap();
            (signing_key, store)
        }

        fn build_protected_bytes(signing_key: &SigningKey) -> Vec<u8> {
            let spki_doc = signing_key.verifying_key().to_public_key_der().unwrap();
            let spki_der = spki_doc.as_bytes();
            let digest = Sha256::digest(spki_der);
            let kid = vec![digest[0], digest[1], digest[2], digest[3]];
            let pairs = vec![
                (
                    ciborium::Value::Integer(1.into()),
                    ciborium::Value::Integer((-7_i64).into()),
                ),
                (
                    ciborium::Value::Integer(4.into()),
                    ciborium::Value::Bytes(kid),
                ),
            ];
            let map = ciborium::Value::Map(pairs);
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&map, &mut buf).unwrap();
            buf
        }

        fn build_cbor_payload(
            agent_id: &str,
            status: &str,
            iat: i64,
            exp: i64,
            ans_name: &str,
            identity_certs: &[(String, String)],
            server_certs: &[(String, String)],
        ) -> Vec<u8> {
            let mut pairs: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
            pairs.push((
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Text(agent_id.to_string()),
            ));
            pairs.push((
                ciborium::Value::Integer(2.into()),
                ciborium::Value::Text(status.to_string()),
            ));
            pairs.push((
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Integer(iat.into()),
            ));
            pairs.push((
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Integer(exp.into()),
            ));
            pairs.push((
                ciborium::Value::Integer(5.into()),
                ciborium::Value::Text(ans_name.to_string()),
            ));
            let id_certs: Vec<ciborium::Value> = identity_certs
                .iter()
                .map(|(fp, ct)| {
                    ciborium::Value::Map(vec![
                        (
                            ciborium::Value::Text("fingerprint".to_string()),
                            ciborium::Value::Text(fp.clone()),
                        ),
                        (
                            ciborium::Value::Text("cert_type".to_string()),
                            ciborium::Value::Text(ct.clone()),
                        ),
                    ])
                })
                .collect();
            pairs.push((
                ciborium::Value::Integer(6.into()),
                ciborium::Value::Array(id_certs),
            ));
            let srv_certs: Vec<ciborium::Value> = server_certs
                .iter()
                .map(|(fp, ct)| {
                    ciborium::Value::Map(vec![
                        (
                            ciborium::Value::Text("fingerprint".to_string()),
                            ciborium::Value::Text(fp.clone()),
                        ),
                        (
                            ciborium::Value::Text("cert_type".to_string()),
                            ciborium::Value::Text(ct.clone()),
                        ),
                    ])
                })
                .collect();
            pairs.push((
                ciborium::Value::Integer(7.into()),
                ciborium::Value::Array(srv_certs),
            ));
            pairs.push((
                ciborium::Value::Integer(8.into()),
                ciborium::Value::Map(vec![]),
            ));
            let map = ciborium::Value::Map(pairs);
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&map, &mut buf).unwrap();
            buf
        }

        fn make_token(signing_key: &SigningKey, payload: &[u8]) -> Vec<u8> {
            let protected_bytes = build_protected_bytes(signing_key);
            let digest = compute_sig_structure_digest(&protected_bytes, payload).unwrap();
            let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
            let sig_bytes = sig.to_bytes().to_vec();
            let array = ciborium::Value::Array(vec![
                ciborium::Value::Bytes(protected_bytes),
                ciborium::Value::Map(vec![]),
                ciborium::Value::Bytes(payload.to_vec()),
                ciborium::Value::Bytes(sig_bytes),
            ]);
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&array, &mut buf).unwrap();
            buf
        }

        fn future_exp() -> i64 {
            4_102_444_800 // 2100-01-01 00:00:00 UTC
        }

        fn past_exp() -> i64 {
            946_684_800 // 2000-01-01 00:00:00 UTC
        }

        fn nil_uuid() -> String {
            "00000000-0000-0000-0000-000000000000".to_string()
        }

        fn test_fp() -> String {
            format!("SHA256:{}", "00".repeat(32))
        }

        fn test_fp2() -> String {
            format!("SHA256:{}", "11".repeat(32))
        }

        fn make_verifier_with_scitt(
            host: &str,
            badge_fingerprint: &str,
            key_store: Arc<ScittKeyStore>,
            tier_policy: ScittTierPolicy,
        ) -> AnsVerifier {
            let identity_fp = format!("SHA256:{}", "22".repeat(32));
            let badge = create_test_badge(host, "v1.0.0", badge_fingerprint, &identity_fp);
            let badge_url = "https://tlog.example.com/v1/agents/test-id";
            let dns_record = BadgeRecord {
                format_version: "ans-badge1".to_string(),
                version: Some(Version::new(1, 0, 0)),
                url: badge_url.to_string(),
            };
            let dns_resolver =
                Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
            let tlog_client =
                Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

            let server_verifier = ServerVerifier {
                dns_resolver: dns_resolver.clone(),
                tlog_client: tlog_client.clone(),
                cache: None,
                failure_policy: FailurePolicy::FailClosed,
                dane_policy: DanePolicy::Disabled,
                dane_port: 443,
                trusted_ra_domains: None,
            };
            let client_verifier = ClientVerifier {
                dns_resolver,
                tlog_client,
                cache: None,
                failure_policy: FailurePolicy::FailClosed,
                trusted_ra_domains: None,
            };

            AnsVerifier {
                server_verifier,
                client_verifier,
                #[cfg(feature = "rustls")]
                private_ca_pem: None,
                scitt_config: Some(ScittConfig::new().with_tier_policy(tier_policy)),
                scitt_key_store: Some(Arc::new(RefreshableKeyStore::from_static(
                    (*key_store).clone(),
                ))),
                scitt_verification_cache: None,
            }
        }

        fn make_valid_token(signing_key: &SigningKey, server_fp: &str) -> Vec<u8> {
            let payload = build_cbor_payload(
                &nil_uuid(),
                "ACTIVE",
                0,
                future_exp(),
                "ans://v1.0.0.agent.example.com",
                &[],
                &[(server_fp.to_string(), "X509-DV-SERVER".to_string())],
            );
            make_token(signing_key, &payload)
        }

        fn make_valid_identity_token(signing_key: &SigningKey, identity_fp: &str) -> Vec<u8> {
            let payload = build_cbor_payload(
                &nil_uuid(),
                "ACTIVE",
                0,
                future_exp(),
                "ans://v1.0.0.agent.example.com",
                &[(identity_fp.to_string(), "X509-OV-CLIENT".to_string())],
                &[],
            );
            make_token(signing_key, &payload)
        }

        // ── ScittConfig / ScittTierPolicy tests ─────────────────────────

        #[test]
        fn scitt_config_default() {
            let config = ScittConfig::default();
            assert!(matches!(
                config.tier_policy,
                ScittTierPolicy::ScittWithBadgeFallback
            ));
            assert_eq!(config.clock_skew_tolerance, Duration::from_secs(60));
        }

        #[test]
        fn scitt_config_builder_chain() {
            let config = ScittConfig::new()
                .with_tier_policy(ScittTierPolicy::RequireScitt)
                .with_clock_skew(Duration::from_secs(120));
            assert!(matches!(config.tier_policy, ScittTierPolicy::RequireScitt));
            assert_eq!(config.clock_skew_tolerance, Duration::from_secs(120));
        }

        // ── VerificationOutcome SCITT variants ──────────────────────────

        #[test]
        fn scitt_verified_is_success() {
            let (signing_key, store) = make_key_and_store(1);
            let token_bytes = make_valid_token(&signing_key, &test_fp());
            let verified =
                verify_status_token(&token_bytes, &store, Duration::from_secs(0)).unwrap();

            let outcome = VerificationOutcome::ScittVerified {
                status_token: verified,
                tier: ans_types::VerificationTier::FullScitt,
                matched_fingerprint: CertFingerprint::parse(&test_fp()).unwrap(),
                badge: None,
            };
            assert!(outcome.is_success());
            assert!(!outcome.is_not_ans_agent());
        }

        #[test]
        fn scitt_verified_badge_accessor_with_badge() {
            let (signing_key, store) = make_key_and_store(1);
            let token_bytes = make_valid_token(&signing_key, &test_fp());
            let verified =
                verify_status_token(&token_bytes, &store, Duration::from_secs(0)).unwrap();

            let badge = create_test_badge("agent.example.com", "v1.0.0", &test_fp(), "SHA256:aaa");
            let outcome = VerificationOutcome::ScittVerified {
                status_token: verified,
                tier: ans_types::VerificationTier::FullScitt,
                matched_fingerprint: CertFingerprint::parse(&test_fp()).unwrap(),
                badge: Some(badge),
            };
            assert!(outcome.badge().is_some());
        }

        #[test]
        fn scitt_verified_badge_accessor_without_badge() {
            let (signing_key, store) = make_key_and_store(1);
            let token_bytes = make_valid_token(&signing_key, &test_fp());
            let verified =
                verify_status_token(&token_bytes, &store, Duration::from_secs(0)).unwrap();

            let outcome = VerificationOutcome::ScittVerified {
                status_token: verified,
                tier: ans_types::VerificationTier::StatusTokenVerified,
                matched_fingerprint: CertFingerprint::parse(&test_fp()).unwrap(),
                badge: None,
            };
            assert!(outcome.badge().is_none());
        }

        #[test]
        fn scitt_error_is_not_success() {
            let outcome = VerificationOutcome::ScittError(ScittError::SignatureInvalid);
            assert!(!outcome.is_success());
        }

        #[test]
        fn scitt_error_into_result() {
            let outcome = VerificationOutcome::ScittError(ScittError::SignatureInvalid);
            let result = outcome.into_result();
            assert!(result.is_err());
        }

        #[test]
        fn scitt_verified_into_scitt_result_with_badge() {
            let (signing_key, store) = make_key_and_store(1);
            let token_bytes = make_valid_token(&signing_key, &test_fp());
            let verified =
                verify_status_token(&token_bytes, &store, Duration::from_secs(0)).unwrap();
            let badge = create_test_badge("agent.example.com", "v1.0.0", &test_fp(), "SHA256:aaa");

            let outcome = VerificationOutcome::ScittVerified {
                status_token: verified,
                tier: ans_types::VerificationTier::FullScitt,
                matched_fingerprint: CertFingerprint::parse(&test_fp()).unwrap(),
                badge: Some(badge),
            };
            let result = outcome.into_scitt_result();
            assert!(result.is_ok());
            assert!(result.unwrap().is_some());
        }

        #[test]
        fn scitt_verified_into_scitt_result_without_badge() {
            let (signing_key, store) = make_key_and_store(1);
            let token_bytes = make_valid_token(&signing_key, &test_fp());
            let verified =
                verify_status_token(&token_bytes, &store, Duration::from_secs(0)).unwrap();

            let outcome = VerificationOutcome::ScittVerified {
                status_token: verified,
                tier: ans_types::VerificationTier::StatusTokenVerified,
                matched_fingerprint: CertFingerprint::parse(&test_fp()).unwrap(),
                badge: None,
            };
            // into_scitt_result is consistent with is_success(): both say "success"
            let result = outcome.into_scitt_result();
            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }

        #[test]
        fn scitt_error_into_scitt_result() {
            let outcome = VerificationOutcome::ScittError(ScittError::SignatureInvalid);
            let result = outcome.into_scitt_result();
            assert!(result.is_err());
        }

        // ── verify_server_with_scitt ────────────────────────────────────

        #[tokio::test]
        async fn scitt_server_verification_success_token_only() {
            let fp = test_fp();
            let (signing_key, store) = make_key_and_store(1);
            let store = Arc::new(store);
            let token_bytes = make_valid_token(&signing_key, &fp);
            let token_b64 = BASE64_STANDARD.encode(&token_bytes);

            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &fp,
                store,
                ScittTierPolicy::ScittWithBadgeFallback,
            );
            let cert = create_test_cert_identity("agent.example.com", &fp);
            let headers = ScittHeaders::from_base64(None, Some(&token_b64)).unwrap();

            let outcome = verifier
                .verify_server_with_scitt("agent.example.com", &cert, &headers)
                .await;
            assert!(outcome.is_success());
            match outcome {
                VerificationOutcome::ScittVerified { tier, .. } => {
                    assert_eq!(tier, ans_types::VerificationTier::StatusTokenVerified);
                }
                other => panic!("Expected ScittVerified, got: {other:?}"),
            }
        }

        #[tokio::test]
        async fn scitt_server_no_headers_fallback_to_badge() {
            let fp = test_fp();
            let (_, store) = make_key_and_store(1);
            let store = Arc::new(store);

            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &fp,
                store,
                ScittTierPolicy::ScittWithBadgeFallback,
            );
            let cert = create_test_cert_identity("agent.example.com", &fp);
            let headers = ScittHeaders::new(None, None);

            let outcome = verifier
                .verify_server_with_scitt("agent.example.com", &cert, &headers)
                .await;
            // Should fall back to badge and succeed
            assert!(outcome.is_success());
            assert!(matches!(outcome, VerificationOutcome::Verified { .. }));
        }

        #[tokio::test]
        async fn scitt_server_no_headers_require_scitt_fails() {
            let fp = test_fp();
            let (_, store) = make_key_and_store(1);
            let store = Arc::new(store);

            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &fp,
                store,
                ScittTierPolicy::RequireScitt,
            );
            let cert = create_test_cert_identity("agent.example.com", &fp);
            let headers = ScittHeaders::new(None, None);

            let outcome = verifier
                .verify_server_with_scitt("agent.example.com", &cert, &headers)
                .await;
            assert!(!outcome.is_success());
            assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
        }

        #[tokio::test]
        async fn scitt_server_corrupt_token_rejects() {
            let fp = test_fp();
            let (_, store) = make_key_and_store(1);
            let store = Arc::new(store);
            // Valid base64 but garbage COSE
            let bad_token_b64 = BASE64_STANDARD.encode(b"not-a-cose-structure");

            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &fp,
                store,
                ScittTierPolicy::ScittWithBadgeFallback,
            );
            let cert = create_test_cert_identity("agent.example.com", &fp);
            let headers = ScittHeaders::from_base64(None, Some(&bad_token_b64)).unwrap();

            let outcome = verifier
                .verify_server_with_scitt("agent.example.com", &cert, &headers)
                .await;
            // Present but corrupt → hard reject, NOT badge fallback
            assert!(!outcome.is_success());
            assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
        }

        #[tokio::test]
        async fn scitt_server_fingerprint_mismatch() {
            let fp = test_fp();
            let different_fp = test_fp2();
            let (signing_key, store) = make_key_and_store(1);
            let store = Arc::new(store);
            // Token lists fp, but cert has different_fp
            let token_bytes = make_valid_token(&signing_key, &fp);
            let token_b64 = BASE64_STANDARD.encode(&token_bytes);

            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &fp,
                store,
                ScittTierPolicy::ScittWithBadgeFallback,
            );
            let cert = create_test_cert_identity("agent.example.com", &different_fp);
            let headers = ScittHeaders::from_base64(None, Some(&token_b64)).unwrap();

            let outcome = verifier
                .verify_server_with_scitt("agent.example.com", &cert, &headers)
                .await;
            assert!(!outcome.is_success());
            assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
        }

        #[tokio::test]
        async fn scitt_server_expired_token_with_headers_rejects() {
            let fp = test_fp();
            let (signing_key, store) = make_key_and_store(1);
            let store = Arc::new(store);
            // Build an expired token
            let payload = build_cbor_payload(
                &nil_uuid(),
                "ACTIVE",
                0,
                past_exp(),
                "ans://v1.0.0.agent.example.com",
                &[],
                &[(fp.clone(), "X509-DV-SERVER".to_string())],
            );
            let token_bytes = make_token(&signing_key, &payload);
            let token_b64 = BASE64_STANDARD.encode(&token_bytes);

            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &fp,
                store,
                ScittTierPolicy::ScittWithBadgeFallback,
            );
            let cert = create_test_cert_identity("agent.example.com", &fp);
            let headers = ScittHeaders::from_base64(None, Some(&token_b64)).unwrap();

            let outcome = verifier
                .verify_server_with_scitt("agent.example.com", &cert, &headers)
                .await;
            // Headers present + expired token = hard reject (no badge fallback)
            assert!(!outcome.is_success());
            assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
        }

        #[tokio::test]
        async fn scitt_server_expired_token_require_scitt_fails() {
            let fp = test_fp();
            let (signing_key, store) = make_key_and_store(1);
            let store = Arc::new(store);
            let payload = build_cbor_payload(
                &nil_uuid(),
                "ACTIVE",
                0,
                past_exp(),
                "ans://v1.0.0.agent.example.com",
                &[],
                &[(fp.clone(), "X509-DV-SERVER".to_string())],
            );
            let token_bytes = make_token(&signing_key, &payload);
            let token_b64 = BASE64_STANDARD.encode(&token_bytes);

            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &fp,
                store,
                ScittTierPolicy::RequireScitt,
            );
            let cert = create_test_cert_identity("agent.example.com", &fp);
            let headers = ScittHeaders::from_base64(None, Some(&token_b64)).unwrap();

            let outcome = verifier
                .verify_server_with_scitt("agent.example.com", &cert, &headers)
                .await;
            // RequireScitt + expired = hard fail
            assert!(!outcome.is_success());
            assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
        }

        #[tokio::test]
        async fn scitt_server_terminal_status_rejects() {
            let fp = test_fp();
            let (signing_key, store) = make_key_and_store(1);
            let store = Arc::new(store);
            // Token with REVOKED status
            let payload = build_cbor_payload(
                &nil_uuid(),
                "REVOKED",
                0,
                future_exp(),
                "ans://v1.0.0.agent.example.com",
                &[],
                &[(fp.clone(), "X509-DV-SERVER".to_string())],
            );
            let token_bytes = make_token(&signing_key, &payload);
            let token_b64 = BASE64_STANDARD.encode(&token_bytes);

            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &fp,
                store,
                ScittTierPolicy::ScittWithBadgeFallback,
            );
            let cert = create_test_cert_identity("agent.example.com", &fp);
            let headers = ScittHeaders::from_base64(None, Some(&token_b64)).unwrap();

            let outcome = verifier
                .verify_server_with_scitt("agent.example.com", &cert, &headers)
                .await;
            // Terminal status = hard reject even with fallback policy
            assert!(!outcome.is_success());
            assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
        }

        #[tokio::test]
        async fn scitt_server_badge_enhancement_policy() {
            let fp = test_fp();
            let (signing_key, store) = make_key_and_store(1);
            let store = Arc::new(store);
            let token_bytes = make_valid_token(&signing_key, &fp);
            let token_b64 = BASE64_STANDARD.encode(&token_bytes);

            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &fp,
                store,
                ScittTierPolicy::BadgeWithScittEnhancement,
            );
            let cert = create_test_cert_identity("agent.example.com", &fp);
            let headers = ScittHeaders::from_base64(None, Some(&token_b64)).unwrap();

            let outcome = verifier
                .verify_server_with_scitt("agent.example.com", &cert, &headers)
                .await;
            // Badge succeeds, SCITT enhances → ScittVerified
            assert!(outcome.is_success());
            assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
        }

        #[tokio::test]
        async fn scitt_server_badge_enhancement_no_headers() {
            let fp = test_fp();
            let (_, store) = make_key_and_store(1);
            let store = Arc::new(store);

            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &fp,
                store,
                ScittTierPolicy::BadgeWithScittEnhancement,
            );
            let cert = create_test_cert_identity("agent.example.com", &fp);
            let headers = ScittHeaders::new(None, None);

            let outcome = verifier
                .verify_server_with_scitt("agent.example.com", &cert, &headers)
                .await;
            // No SCITT headers → badge result only
            assert!(outcome.is_success());
            assert!(matches!(outcome, VerificationOutcome::Verified { .. }));
        }

        // ── verify_client_with_scitt ────────────────────────────────────

        #[tokio::test]
        async fn scitt_client_no_headers_fallback_to_badge() {
            let identity_fp = test_fp2(); // identity cert fingerprint
            let (_, store) = make_key_and_store(1);
            let store = Arc::new(store);

            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &test_fp(), // server cert fp in badge
                store,
                ScittTierPolicy::ScittWithBadgeFallback,
            );
            // Client cert with URI SAN for mTLS
            let cert = CertIdentity {
                common_name: Some("agent.example.com".to_string()),
                dns_sans: vec!["agent.example.com".to_string()],
                uri_sans: vec!["ans://v1.0.0.agent.example.com".to_string()],
                fingerprint: CertFingerprint::parse(&identity_fp).unwrap(),
            };
            let headers = ScittHeaders::new(None, None);

            let outcome = verifier.verify_client_with_scitt(&cert, &headers).await;
            // No SCITT headers → falls back to badge client verification.
            // Client verification tries to match identity cert fingerprint against
            // the badge's identity_cert fingerprint.
            // Our test badge uses "SHA256:00...00" as identity_fp, so this will
            // either match or not depending on the badge setup.
            // The key thing is it falls back (not ScittError).
            assert!(!matches!(outcome, VerificationOutcome::ScittError(_)));
        }

        #[tokio::test]
        async fn scitt_client_no_headers_require_scitt_fails() {
            let identity_fp = test_fp2();
            let (_, store) = make_key_and_store(1);
            let store = Arc::new(store);

            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &test_fp(),
                store,
                ScittTierPolicy::RequireScitt,
            );
            let cert = CertIdentity {
                common_name: Some("agent.example.com".to_string()),
                dns_sans: vec![],
                uri_sans: vec!["ans://v1.0.0.agent.example.com".to_string()],
                fingerprint: CertFingerprint::parse(&identity_fp).unwrap(),
            };
            let headers = ScittHeaders::new(None, None);

            let outcome = verifier.verify_client_with_scitt(&cert, &headers).await;
            assert!(!outcome.is_success());
            assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
        }

        #[tokio::test]
        async fn scitt_client_verification_success_with_token() {
            let identity_fp = test_fp2();
            let (signing_key, store) = make_key_and_store(1);
            let store = Arc::new(store);
            let token_bytes = make_valid_identity_token(&signing_key, &identity_fp);
            let token_b64 = BASE64_STANDARD.encode(&token_bytes);

            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &test_fp(),
                store,
                ScittTierPolicy::ScittWithBadgeFallback,
            );
            let cert = CertIdentity {
                common_name: Some("agent.example.com".to_string()),
                dns_sans: vec!["agent.example.com".to_string()],
                uri_sans: vec!["ans://v1.0.0.agent.example.com".to_string()],
                fingerprint: CertFingerprint::parse(&identity_fp).unwrap(),
            };
            let headers = ScittHeaders::from_base64(None, Some(&token_b64)).unwrap();

            let outcome = verifier.verify_client_with_scitt(&cert, &headers).await;
            assert!(outcome.is_success());
            assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
        }

        // ── Builder extensions ──────────────────────────────────────────

        #[test]
        fn builder_scitt_config_sets_field() {
            let builder = AnsVerifier::builder()
                .scitt_config(ScittConfig::new().with_tier_policy(ScittTierPolicy::RequireScitt));
            assert!(builder.scitt_config.is_some());
            assert!(matches!(
                builder.scitt_config.unwrap().tier_policy,
                ScittTierPolicy::RequireScitt
            ));
        }

        #[test]
        fn builder_scitt_key_store_sets_field() {
            let (_, store) = make_key_and_store(1);
            let builder = AnsVerifier::builder().scitt_key_store(Arc::new(store));
            assert!(builder.scitt_key_store.is_some());
        }

        #[test]
        fn builder_debug_includes_scitt() {
            let builder = AnsVerifier::builder().scitt_config(ScittConfig::default());
            let dbg = format!("{builder:?}");
            assert!(dbg.contains("has_scitt_config"));
            assert!(dbg.contains("true"));
        }

        // ── AnsVerifier debug with SCITT ────────────────────────────────

        #[test]
        fn verifier_debug_includes_scitt() {
            let fp = test_fp();
            let (_, store) = make_key_and_store(1);
            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &fp,
                Arc::new(store),
                ScittTierPolicy::ScittWithBadgeFallback,
            );
            let dbg = format!("{verifier:?}");
            assert!(dbg.contains("has_scitt_config"));
        }

        // ── No key store graceful fallback ──────────────────────────────

        #[tokio::test]
        async fn scitt_no_key_store_falls_back_to_badge() {
            let fp = test_fp();
            let host = "agent.example.com";
            let badge = create_test_badge(host, "v1.0.0", &fp, "SHA256:aaa");
            let badge_url = "https://tlog.example.com/v1/agents/test-id";
            let dns_record = BadgeRecord {
                format_version: "ans-badge1".to_string(),
                version: Some(Version::new(1, 0, 0)),
                url: badge_url.to_string(),
            };
            let dns_resolver =
                Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
            let tlog_client =
                Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

            let server_verifier = ServerVerifier {
                dns_resolver: dns_resolver.clone(),
                tlog_client: tlog_client.clone(),
                cache: None,
                failure_policy: FailurePolicy::FailClosed,
                dane_policy: DanePolicy::Disabled,
                dane_port: 443,
                trusted_ra_domains: None,
            };
            let client_verifier = ClientVerifier {
                dns_resolver,
                tlog_client,
                cache: None,
                failure_policy: FailurePolicy::FailClosed,
                trusted_ra_domains: None,
            };

            // Config present, but NO key store
            let verifier = AnsVerifier {
                server_verifier,
                client_verifier,
                #[cfg(feature = "rustls")]
                private_ca_pem: None,
                scitt_config: Some(ScittConfig::default()),
                scitt_key_store: None,
                scitt_verification_cache: None,
            };

            let cert = create_test_cert_identity(host, &fp);
            let headers = ScittHeaders::from_base64(None, Some("aGVsbG8=")).unwrap();

            let outcome = verifier
                .verify_server_with_scitt(host, &cert, &headers)
                .await;
            // No key store → graceful badge fallback
            assert!(outcome.is_success());
            assert!(matches!(outcome, VerificationOutcome::Verified { .. }));
        }

        // ── No SCITT config passes through to badge ─────────────────────

        #[tokio::test]
        async fn scitt_no_config_passes_through() {
            let fp = test_fp();
            let host = "agent.example.com";
            let badge = create_test_badge(host, "v1.0.0", &fp, "SHA256:aaa");
            let badge_url = "https://tlog.example.com/v1/agents/test-id";
            let dns_record = BadgeRecord {
                format_version: "ans-badge1".to_string(),
                version: Some(Version::new(1, 0, 0)),
                url: badge_url.to_string(),
            };
            let dns_resolver =
                Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record]));
            let tlog_client =
                Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

            let server_verifier = ServerVerifier {
                dns_resolver: dns_resolver.clone(),
                tlog_client: tlog_client.clone(),
                cache: None,
                failure_policy: FailurePolicy::FailClosed,
                dane_policy: DanePolicy::Disabled,
                dane_port: 443,
                trusted_ra_domains: None,
            };
            let client_verifier = ClientVerifier {
                dns_resolver,
                tlog_client,
                cache: None,
                failure_policy: FailurePolicy::FailClosed,
                trusted_ra_domains: None,
            };

            let verifier = AnsVerifier {
                server_verifier,
                client_verifier,
                #[cfg(feature = "rustls")]
                private_ca_pem: None,
                scitt_config: None,
                scitt_key_store: None,
                scitt_verification_cache: None,
            };

            let cert = create_test_cert_identity(host, &fp);
            let headers = ScittHeaders::from_base64(None, Some("aGVsbG8=")).unwrap();

            let outcome = verifier
                .verify_server_with_scitt(host, &cert, &headers)
                .await;
            // No SCITT config → pass-through to badge
            assert!(outcome.is_success());
            assert!(matches!(outcome, VerificationOutcome::Verified { .. }));
        }

        // ── Invalid FQDN ────────────────────────────────────────────────

        #[tokio::test]
        async fn scitt_server_invalid_fqdn() {
            let (_, store) = make_key_and_store(1);
            let store = Arc::new(store);

            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &test_fp(),
                store,
                ScittTierPolicy::ScittWithBadgeFallback,
            );
            let cert = create_test_cert_identity("agent.example.com", &test_fp());
            let headers = ScittHeaders::new(None, None);

            let outcome = verifier.verify_server_with_scitt("", &cert, &headers).await;
            assert!(matches!(outcome, VerificationOutcome::ParseError(_)));
        }

        // ── Wrong key rejects ───────────────────────────────────────────

        #[tokio::test]
        async fn scitt_server_wrong_key_rejects() {
            let fp = test_fp();
            let (signing_key, _store) = make_key_and_store(1);
            let (_, wrong_store) = make_key_and_store(2); // Different key
            let wrong_store = Arc::new(wrong_store);

            let token_bytes = make_valid_token(&signing_key, &fp);
            let token_b64 = BASE64_STANDARD.encode(&token_bytes);

            let verifier = make_verifier_with_scitt(
                "agent.example.com",
                &fp,
                wrong_store,
                ScittTierPolicy::ScittWithBadgeFallback,
            );
            let cert = create_test_cert_identity("agent.example.com", &fp);
            let headers = ScittHeaders::from_base64(None, Some(&token_b64)).unwrap();

            let outcome = verifier
                .verify_server_with_scitt("agent.example.com", &cert, &headers)
                .await;
            // Wrong key → crypto failure → hard reject (not fallback)
            assert!(!outcome.is_success());
            assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
        }
    }
}
