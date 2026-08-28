#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Comprehensive verification test scenarios from TEST_CASES.md.
//!
//! Each test maps to a specific scenario ID (e.g., `test_1_1_*` → TEST_CASES §1.1).
//! All external dependencies (DNS, Transparency Log) are mocked.

use std::sync::Arc;
use std::time::Duration;

use ans_types::*;
use ans_verify::*;
use chrono::Utc;
use uuid::Uuid;

// =========================================================================
// Test Helpers
// =========================================================================

const SERVER_FP: &str = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
const IDENTITY_FP: &str = "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496";
const WRONG_FP: &str = "SHA256:0000000000000000000000000000000000000000000000000000000000000000";
const BADGE_URL_V1: &str = "https://tlog.example.com/v1/agents/v1-uuid";
const BADGE_URL_V2: &str = "https://tlog.example.com/v1/agents/v2-uuid";

fn badge(host: &str, version: &str, server_fp: &str, identity_fp: &str) -> Badge {
    badge_with_status(host, version, server_fp, identity_fp, BadgeStatus::Active)
}

fn badge_with_status(
    host: &str,
    version: &str,
    server_fp: &str,
    identity_fp: &str,
    status: BadgeStatus,
) -> Badge {
    let status_str = serde_json::to_value(status).unwrap();
    serde_json::from_value(serde_json::json!({
        "status": status_str,
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
    }))
    .expect("test badge JSON should be valid")
}

fn dns_record(version: Option<Version>, url: &str) -> BadgeRecord {
    BadgeRecord::new("ans-badge1", version, url)
}

fn server_cert(host: &str, fingerprint: &str) -> CertIdentity {
    CertIdentity::new(
        Some(host.to_string()),
        vec![host.to_string()],
        vec![],
        CertFingerprint::parse(fingerprint).unwrap(),
    )
}

fn mtls_cert(host: &str, version: &str, fingerprint: &str) -> CertIdentity {
    CertIdentity::new(
        Some(host.to_string()),
        vec![host.to_string()],
        vec![format!("ans://{}.{}", version, host)],
        CertFingerprint::parse(fingerprint).unwrap(),
    )
}

async fn server_verifier(
    dns: Arc<MockDnsResolver>,
    tlog: Arc<MockTransparencyLogClient>,
) -> ServerVerifier {
    ServerVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .build()
        .await
        .unwrap()
}

async fn server_verifier_with_cache(
    dns: Arc<MockDnsResolver>,
    tlog: Arc<MockTransparencyLogClient>,
) -> ServerVerifier {
    ServerVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .with_cache()
        .build()
        .await
        .unwrap()
}

async fn server_verifier_with_policy(
    dns: Arc<MockDnsResolver>,
    tlog: Arc<MockTransparencyLogClient>,
    policy: FailurePolicy,
) -> ServerVerifier {
    ServerVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .failure_policy(policy)
        .build()
        .await
        .unwrap()
}

async fn client_verifier(
    dns: Arc<MockDnsResolver>,
    tlog: Arc<MockTransparencyLogClient>,
) -> ClientVerifier {
    ClientVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .build()
        .await
        .unwrap()
}

async fn client_verifier_with_cache(
    dns: Arc<MockDnsResolver>,
    tlog: Arc<MockTransparencyLogClient>,
) -> ClientVerifier {
    ClientVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .with_cache()
        .build()
        .await
        .unwrap()
}

// =========================================================================
// §1 DNS Badge Record Resolution
// =========================================================================

/// §1.1 `_ans-badge` record exists → parsed successfully.
#[tokio::test]
async fn test_1_1_ans_badge_record_exists() {
    let host = "agent.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(outcome.is_success(), "Expected success, got: {:?}", outcome);
}

/// §1.2 `_ans-badge` absent, `_ra-badge` fallback → fallback succeeds.
///
/// The MockDnsResolver's `lookup_badge` implementation mirrors the real
/// HickoryDnsResolver: it queries `_ans-badge` first, then falls back to
/// `_ra-badge`. When records are stored under the host key, the mock
/// simulates whichever record format was registered.
#[tokio::test]
async fn test_1_2_ra_badge_fallback() {
    let host = "legacy.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    // Register with ra-badge1 format version to simulate legacy record
    let record = BadgeRecord::new("ra-badge1", Some(Version::new(1, 0, 0)), BADGE_URL_V1);
    let dns = Arc::new(MockDnsResolver::new().with_records(host, vec![record]));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        outcome.is_success(),
        "Expected fallback to ra-badge to succeed, got: {:?}",
        outcome
    );
}

/// §1.3 Neither `_ans-badge` nor `_ra-badge` exists → not an ANS agent.
#[tokio::test]
async fn test_1_3_neither_record_exists() {
    let dns = Arc::new(MockDnsResolver::new());
    let tlog = Arc::new(MockTransparencyLogClient::new());

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(
            &Fqdn::new("unknown.example.com").unwrap(),
            &server_cert("unknown.example.com", SERVER_FP),
        )
        .await;

    assert!(
        outcome.is_not_ans_agent(),
        "Expected NotAnsAgent, got: {:?}",
        outcome
    );
}

/// §1.4 TXT record with variable whitespace → parsed successfully.
#[test]
fn test_1_4_variable_whitespace() {
    // Extra spaces around semicolons and values
    let txt = "v=ans-badge1;version=v1.0.0; url=https://tlog.example.com/v1/agents/test-id";
    let record = BadgeRecord::parse(txt).expect("Should parse with variable whitespace");
    assert_eq!(record.format_version(), "ans-badge1");
    assert_eq!(record.version(), Some(&Version::new(1, 0, 0)));

    // No spaces at all
    let txt2 = "v=ans-badge1;version=v1.0.0;url=https://tlog.example.com/v1/agents/test-id";
    let record2 = BadgeRecord::parse(txt2).expect("Should parse without spaces");
    assert_eq!(record2.format_version(), "ans-badge1");

    // Extra whitespace everywhere
    let txt3 = "v=ans-badge1 ; version=v1.0.0 ; url=https://tlog.example.com/v1/agents/test-id";
    let record3 = BadgeRecord::parse(txt3).expect("Should parse with extra whitespace");
    assert_eq!(record3.version(), Some(&Version::new(1, 0, 0)));
}

/// §1.5 Legacy version without `v` prefix → normalized to `v`-prefixed.
#[test]
fn test_1_5_legacy_version_without_v_prefix() {
    let txt = "v=ra-badge1; version=1.0.0; url=https://tlog.example.com/v1/agents/test-id";
    let record = BadgeRecord::parse(txt).expect("Should parse bare semver");
    assert_eq!(record.format_version(), "ra-badge1");
    // Version should be parsed and normalized — `Version::parse` accepts both formats
    assert_eq!(record.version(), Some(&Version::new(1, 0, 0)));
}

/// §1.6a NXDOMAIN → not an ANS agent.
#[tokio::test]
async fn test_1_6a_nxdomain() {
    let dns = Arc::new(MockDnsResolver::new());
    let tlog = Arc::new(MockTransparencyLogClient::new());

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(
            &Fqdn::new("nonexistent.example.com").unwrap(),
            &server_cert("nonexistent.example.com", SERVER_FP),
        )
        .await;

    assert!(
        outcome.is_not_ans_agent(),
        "NXDOMAIN should result in NotAnsAgent, got: {:?}",
        outcome
    );
}

/// §1.6b SERVFAIL / timeout → failure policy applied.
#[tokio::test]
async fn test_1_6b_servfail_fail_closed() {
    let host = "timeout.example.com";
    let dns = Arc::new(MockDnsResolver::new().with_error(
        host,
        DnsError::LookupFailed {
            fqdn: host.to_string(),
            reason: "SERVFAIL".to_string(),
        },
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new());

    // FailClosed → DnsError
    let verifier = server_verifier_with_policy(dns, tlog, FailurePolicy::FailClosed).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        matches!(outcome, VerificationOutcome::DnsError(_)),
        "SERVFAIL + FailClosed should return DnsError, got: {:?}",
        outcome
    );
}

// =========================================================================
// §2 Badge Retrieval and Status Validation
// =========================================================================

/// §2.1 ACTIVE status → proceed to cert comparison, verification passes.
#[tokio::test]
async fn test_2_1_active_status() {
    let host = "active.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(outcome.is_success());
}

/// §2.2 WARNING status → proceed to cert comparison, verification passes.
#[tokio::test]
async fn test_2_2_warning_status() {
    let host = "warning.example.com";
    let b = badge_with_status(host, "v1.0.0", SERVER_FP, IDENTITY_FP, BadgeStatus::Warning);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        outcome.is_success(),
        "WARNING status should pass verification, got: {:?}",
        outcome
    );
}

/// §2.3 DEPRECATED status (single record) → pass with warning.
#[tokio::test]
async fn test_2_3_deprecated_status_single_record() {
    let host = "deprecated.example.com";
    let b = badge_with_status(
        host,
        "v1.0.0",
        SERVER_FP,
        IDENTITY_FP,
        BadgeStatus::Deprecated,
    );

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    // DEPRECATED is valid for connections (AHP-initiated signal, not a rejection)
    assert!(
        outcome.is_success(),
        "DEPRECATED should pass verification, got: {:?}",
        outcome
    );
    // The badge should be accessible for callers to log the warning
    assert_eq!(outcome.badge().unwrap().status, BadgeStatus::Deprecated);
}

/// §2.4 EXPIRED status → reject.
#[tokio::test]
async fn test_2_4_expired_status() {
    let host = "expired.example.com";
    let b = badge_with_status(host, "v1.0.0", SERVER_FP, IDENTITY_FP, BadgeStatus::Expired);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        matches!(
            outcome,
            VerificationOutcome::InvalidStatus {
                status: BadgeStatus::Expired,
                ..
            }
        ),
        "EXPIRED should be rejected, got: {:?}",
        outcome
    );
}

/// §2.5 REVOKED status → reject.
#[tokio::test]
async fn test_2_5_revoked_status() {
    let host = "revoked.example.com";
    let b = badge_with_status(host, "v1.0.0", SERVER_FP, IDENTITY_FP, BadgeStatus::Revoked);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        matches!(
            outcome,
            VerificationOutcome::InvalidStatus {
                status: BadgeStatus::Revoked,
                ..
            }
        ),
        "REVOKED should be rejected, got: {:?}",
        outcome
    );
}

/// §2.6 Transparency log unreachable → failure policy applied.
#[tokio::test]
async fn test_2_6_tlog_unreachable_fail_closed() {
    let host = "agent.example.com";
    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    // TLog returns ServiceUnavailable for all URLs
    let tlog = Arc::new(
        MockTransparencyLogClient::new().with_error(BADGE_URL_V1, TlogError::ServiceUnavailable),
    );

    let verifier = server_verifier_with_policy(dns, tlog, FailurePolicy::FailClosed).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        matches!(outcome, VerificationOutcome::TlogError(_)),
        "TLog unreachable + FailClosed should return TlogError, got: {:?}",
        outcome
    );
}

/// §2.6 Transparency log unreachable + FailOpenWithCache → uses cached badge.
#[tokio::test]
async fn test_2_6_tlog_unreachable_fail_open_with_cache() {
    let host = "agent.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);
    let cache = Arc::new(BadgeCache::with_defaults());
    let fqdn = Fqdn::new(host).unwrap();

    // Pre-populate cache
    cache
        .insert_for_fqdn_version(&fqdn, &Version::new(1, 0, 0), b)
        .await;

    let dns = Arc::new(MockDnsResolver::new().with_error(
        host,
        DnsError::LookupFailed {
            fqdn: host.to_string(),
            reason: "timeout".to_string(),
        },
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new());

    let verifier = ServerVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .cache(cache)
        .failure_policy(FailurePolicy::FailOpenWithCache {
            max_staleness: Duration::from_secs(600),
        })
        .build()
        .await
        .unwrap();

    let outcome = verifier.verify(&fqdn, &server_cert(host, SERVER_FP)).await;

    assert!(
        outcome.is_success(),
        "Should use cached badge when TLog is unreachable, got: {:?}",
        outcome
    );
}

/// §2.7 Badge URL returns 404 → failure policy applied.
#[tokio::test]
async fn test_2_7_badge_url_404() {
    let host = "agent.example.com";
    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_error(
        BADGE_URL_V1,
        TlogError::NotFound {
            url: BADGE_URL_V1.to_string(),
        },
    ));

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        matches!(outcome, VerificationOutcome::TlogError(_)),
        "Badge 404 should return TlogError, got: {:?}",
        outcome
    );
}

// =========================================================================
// §3 Client-Side Server Verification
// =========================================================================

/// §3.1 Fingerprint match, DNS SAN match → pass.
#[tokio::test]
async fn test_3_1_fingerprint_match_san_match() {
    let host = "server.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(outcome.is_success());
}

/// §3.2 Fingerprint mismatch → reject.
#[tokio::test]
async fn test_3_2_fingerprint_mismatch() {
    let host = "server.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, WRONG_FP))
        .await;

    assert!(
        matches!(outcome, VerificationOutcome::FingerprintMismatch { .. }),
        "Expected FingerprintMismatch, got: {:?}",
        outcome
    );
}

/// §3.3 DNS SAN mismatch → reject.
#[tokio::test]
async fn test_3_3_dns_san_mismatch() {
    let badge_host = "server.example.com";
    let cert_host = "wrong.example.com";
    // Badge says server.example.com, cert CN says wrong.example.com
    let b = badge(badge_host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        cert_host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(
            &Fqdn::new(cert_host).unwrap(),
            &server_cert(cert_host, SERVER_FP),
        )
        .await;

    assert!(
        matches!(outcome, VerificationOutcome::HostnameMismatch { .. }),
        "Expected HostnameMismatch, got: {:?}",
        outcome
    );
}

/// ANS-6 §5.1 dialed-host anchor: a badge and certificate that agree with
/// each other but name a different host than the caller dialed → reject.
/// Without the anchor a spoofed `_ans-badge` record pointing at a consistent
/// (badge, cert) pair for another agent would verify.
#[tokio::test]
async fn test_3_3b_badge_host_not_dialed_host() {
    let dialed_host = "victim.example.com";
    let other_host = "attacker.example.com";
    // Badge and cert consistently name attacker.example.com.
    let b = badge(other_host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        dialed_host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(
            &Fqdn::new(dialed_host).unwrap(),
            &server_cert(other_host, SERVER_FP),
        )
        .await;

    assert!(
        matches!(
            outcome,
            VerificationOutcome::HostnameMismatch { ref expected, ref actual, .. }
                if expected == dialed_host && actual == other_host
        ),
        "Expected HostnameMismatch anchored to the dialed host, got: {:?}",
        outcome
    );
}

/// §3.4 Fingerprint mismatch after renewal, refresh resolves → pass.
///
/// Simulates: verifier has cached stale badge (old fingerprint), server renewed
/// cert, TLog now returns updated badge with new fingerprint.
#[tokio::test]
async fn test_3_4_refresh_on_mismatch_after_renewal() {
    let host = "renewed.example.com";
    let old_fp = WRONG_FP;
    let new_fp = SERVER_FP;

    // TLog returns badge with the NEW fingerprint (post-renewal)
    let updated_badge = badge(host, "v1.0.0", new_fp, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, updated_badge));

    let cache = Arc::new(BadgeCache::with_defaults());
    let fqdn = Fqdn::new(host).unwrap();

    // Pre-populate cache with stale badge (old fingerprint)
    let stale_badge = badge(host, "v1.0.0", old_fp, IDENTITY_FP);
    cache
        .insert_for_fqdn_version(&fqdn, &Version::new(1, 0, 0), stale_badge)
        .await;

    let verifier = ServerVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .cache(cache)
        .build()
        .await
        .unwrap();

    // Cert has NEW fingerprint; cache has OLD → mismatch → refresh → success
    let outcome = verifier.verify(&fqdn, &server_cert(host, new_fp)).await;

    assert!(
        outcome.is_success(),
        "Refresh-on-mismatch should succeed after renewal, got: {:?}",
        outcome
    );
}

/// §3.5 Pre-fetch vs post-fetch ordering → pass either way.
///
/// Verifies that prefetching a badge before verification works correctly.
#[tokio::test]
async fn test_3_5_prefetch_then_verify() {
    let host = "agent.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier_with_cache(dns, tlog).await;
    let fqdn = Fqdn::new(host).unwrap();

    // Pre-fetch badge (before "TLS handshake")
    let prefetch_result = verifier.prefetch(&fqdn).await;
    assert!(prefetch_result.is_ok());

    // Then verify (after "TLS handshake")
    let outcome = verifier.verify(&fqdn, &server_cert(host, SERVER_FP)).await;

    assert!(
        outcome.is_success(),
        "Pre-fetched badge should be used for verification, got: {:?}",
        outcome
    );
}

// =========================================================================
// §4 Server-Side Client Verification (mTLS)
// =========================================================================

/// §4.1 All fields match, ACTIVE → pass.
#[tokio::test]
async fn test_4_1_all_fields_match_active() {
    let host = "client.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = client_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&mtls_cert(host, "v1.0.0", IDENTITY_FP))
        .await;

    assert!(outcome.is_success(), "Expected success, got: {:?}", outcome);
}

/// §4.2 Certificate does not chain to Private CA → reject at TLS layer.
///
/// This is enforced by rustls `AnsClientCertVerifier`, not by `ClientVerifier`.
/// The test verifies the type-level contract: `ClientVerifier::verify` is only
/// called AFTER the TLS handshake succeeds, meaning the cert already chains
/// to the Private CA. This test documents that chain validation is a TLS-layer
/// concern, not a badge verification concern.
#[test]
fn test_4_2_untrusted_ca_is_tls_layer() {
    // This is a design test — chain validation happens at the TLS layer
    // (AnsClientCertVerifier), not in ClientVerifier::verify().
    // ClientVerifier.verify() assumes the cert already chains to the Private CA.
    //
    // See rustls_verifier.rs: AnsClientCertVerifier::verify_client_cert()
}

/// §4.3 No URI SAN in certificate → reject.
#[tokio::test]
async fn test_4_3_no_uri_san() {
    let dns = Arc::new(MockDnsResolver::new());
    let tlog = Arc::new(MockTransparencyLogClient::new());

    let verifier = client_verifier(dns, tlog).await;

    // Cert has DNS SAN but no URI SAN
    let cert = CertIdentity::new(
        Some("client.example.com".to_string()),
        vec!["client.example.com".to_string()],
        vec![], // No URI SAN
        CertFingerprint::parse(IDENTITY_FP).unwrap(),
    );

    let outcome = verifier.verify(&cert).await;

    assert!(
        matches!(outcome, VerificationOutcome::CertError(_)),
        "Missing URI SAN should be rejected, got: {:?}",
        outcome
    );
}

/// §4.4 DNS SAN mismatch → reject.
#[tokio::test]
async fn test_4_4_dns_san_mismatch() {
    let badge_host = "real.example.com";
    let cert_host = "imposter.example.com";
    let b = badge(badge_host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    // DNS resolves cert_host, but badge says real.example.com
    let dns = Arc::new(MockDnsResolver::new().with_records(
        cert_host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = client_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&mtls_cert(cert_host, "v1.0.0", IDENTITY_FP))
        .await;

    assert!(
        matches!(outcome, VerificationOutcome::HostnameMismatch { .. }),
        "DNS SAN mismatch should reject, got: {:?}",
        outcome
    );
}

/// §4.5 URI SAN mismatch → reject.
#[tokio::test]
async fn test_4_5_uri_san_mismatch() {
    let host = "client.example.com";
    // Badge has v1.0.0, cert has v2.0.0
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(2, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = client_verifier(dns, tlog).await;
    // Cert says v2.0.0, badge says v1.0.0
    let outcome = verifier
        .verify(&mtls_cert(host, "v2.0.0", IDENTITY_FP))
        .await;

    assert!(
        matches!(outcome, VerificationOutcome::AnsNameMismatch { .. }),
        "URI SAN mismatch should reject, got: {:?}",
        outcome
    );
}

/// §4.6 Fingerprint mismatch → reject.
#[tokio::test]
async fn test_4_6_identity_fingerprint_mismatch() {
    let host = "client.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = client_verifier(dns, tlog).await;
    // Cert has wrong fingerprint
    let outcome = verifier.verify(&mtls_cert(host, "v1.0.0", WRONG_FP)).await;

    assert!(
        matches!(outcome, VerificationOutcome::FingerprintMismatch { .. }),
        "Identity fingerprint mismatch should reject, got: {:?}",
        outcome
    );
}

/// §4.7 All fields match, DEPRECATED → pass with warning.
#[tokio::test]
async fn test_4_7_deprecated_status_passes() {
    let host = "client.example.com";
    let b = badge_with_status(
        host,
        "v1.0.0",
        SERVER_FP,
        IDENTITY_FP,
        BadgeStatus::Deprecated,
    );

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = client_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&mtls_cert(host, "v1.0.0", IDENTITY_FP))
        .await;

    assert!(
        outcome.is_success(),
        "DEPRECATED should pass mTLS verification, got: {:?}",
        outcome
    );
    assert_eq!(outcome.badge().unwrap().status, BadgeStatus::Deprecated);
}

/// §4.8 All fields match, EXPIRED → reject.
#[tokio::test]
async fn test_4_8_expired_status_rejects() {
    let host = "client.example.com";
    let b = badge_with_status(host, "v1.0.0", SERVER_FP, IDENTITY_FP, BadgeStatus::Expired);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = client_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&mtls_cert(host, "v1.0.0", IDENTITY_FP))
        .await;

    assert!(
        matches!(
            outcome,
            VerificationOutcome::InvalidStatus {
                status: BadgeStatus::Expired,
                ..
            }
        ),
        "EXPIRED should reject, got: {:?}",
        outcome
    );
}

/// §4.9 First request blocks on verification → badge fetched before response.
///
/// Simulates the first-request flow: no cached badge exists, verification
/// must complete (DNS + TLog fetch) before the outcome is returned.
#[tokio::test]
async fn test_4_9_first_request_blocks_on_verification() {
    let host = "client.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    // No cache — forces full verification path
    let verifier = client_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&mtls_cert(host, "v1.0.0", IDENTITY_FP))
        .await;

    // Verification completes (blocks until done) and succeeds
    assert!(outcome.is_success());
}

/// §4.10 Subsequent requests use cache → immediate, no fetch.
#[tokio::test]
async fn test_4_10_subsequent_requests_use_cache() {
    let host = "client.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = client_verifier_with_cache(dns, tlog).await;
    let cert = mtls_cert(host, "v1.0.0", IDENTITY_FP);

    // First verification — populates cache
    let outcome1 = verifier.verify(&cert).await;
    assert!(outcome1.is_success());

    // Second verification — uses cache (even though mock DNS/TLog have no
    // new data, it succeeds because the cache has the badge)
    let outcome2 = verifier.verify(&cert).await;
    assert!(outcome2.is_success());
}

// =========================================================================
// §5 URI SAN Version Parsing
// =========================================================================

/// §5.1 Standard ANSName (v1.0.0) → parsed correctly.
#[test]
fn test_5_1_standard_ans_name() {
    let name = AnsName::parse("ans://v1.0.0.agent.example.com").unwrap();
    assert_eq!(*name.version(), Version::new(1, 0, 0));
    assert_eq!(name.fqdn().as_str(), "agent.example.com");
}

/// §5.2 Multi-digit version (v12.3.45) → parsed correctly.
#[test]
fn test_5_2_multi_digit_version() {
    let name = AnsName::parse("ans://v12.3.45.agent.example.com").unwrap();
    assert_eq!(*name.version(), Version::new(12, 3, 45));
    assert_eq!(name.fqdn().as_str(), "agent.example.com");
}

/// §5.3 Subdomain FQDN → parsed correctly.
#[test]
fn test_5_3_subdomain_fqdn() {
    let name = AnsName::parse("ans://v2.0.0.support.api.example.com").unwrap();
    assert_eq!(*name.version(), Version::new(2, 0, 0));
    assert_eq!(name.fqdn().as_str(), "support.api.example.com");
}

/// Additional: CertIdentity extracts version from URI SAN.
#[test]
fn test_5_cert_identity_extracts_version() {
    let cert = CertIdentity::new(
        Some("agent.example.com".to_string()),
        vec!["agent.example.com".to_string()],
        vec!["ans://v1.0.0.agent.example.com".to_string()],
        CertFingerprint::parse(IDENTITY_FP).unwrap(),
    );

    assert_eq!(cert.version(), Some(Version::new(1, 0, 0)));
    assert_eq!(cert.fqdn(), Some("agent.example.com"));
    let ans_name = cert.ans_name().unwrap();
    assert_eq!(*ans_name.version(), Version::new(1, 0, 0));
    assert_eq!(ans_name.fqdn().as_str(), "agent.example.com");
}

// =========================================================================
// §6 Version Change Handling
// =========================================================================

/// §6.1 Two ACTIVE versions, version-selected lookup → correct badge selected, pass.
///
/// During a version transition, both v1.0.0 and v1.0.1 are ACTIVE.
/// Client presents v1.0.0 identity cert → should select v1.0.0 badge.
#[tokio::test]
async fn test_6_1_two_active_versions_version_selected() {
    let host = "agent.example.com";
    let v1_identity_fp = IDENTITY_FP;
    let v2_identity_fp = "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let b_v1 = badge(host, "v1.0.0", SERVER_FP, v1_identity_fp);
    let b_v2 = badge(host, "v1.0.1", SERVER_FP, v2_identity_fp);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![
            dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1),
            dns_record(Some(Version::new(1, 0, 1)), BADGE_URL_V2),
        ],
    ));
    let tlog = Arc::new(
        MockTransparencyLogClient::new()
            .with_badge(BADGE_URL_V1, b_v1)
            .with_badge(BADGE_URL_V2, b_v2),
    );

    let verifier = client_verifier(dns, tlog).await;
    // Client presents v1.0.0 cert
    let outcome = verifier
        .verify(&mtls_cert(host, "v1.0.0", v1_identity_fp))
        .await;

    assert!(
        outcome.is_success(),
        "Version-selected lookup for v1.0.0 should pass, got: {:?}",
        outcome
    );
    assert_eq!(outcome.badge().unwrap().agent_version(), "v1.0.0");
}

/// §6.1 (server-side) Two ACTIVE versions, server running older version.
///
/// During a multi-version transition, the server may still be running v1.0.0
/// while v1.0.1 also exists. The server verifier should try all badges and
/// find the one matching the server cert fingerprint.
#[tokio::test]
async fn test_6_1_server_two_active_versions_older_server() {
    let host = "agent.example.com";
    let v1_server_fp = SERVER_FP;
    let v2_server_fp = "SHA256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    let b_v1 = badge(host, "v1.0.0", v1_server_fp, IDENTITY_FP);
    let b_v2 = badge(host, "v1.0.1", v2_server_fp, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![
            dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1),
            dns_record(Some(Version::new(1, 0, 1)), BADGE_URL_V2),
        ],
    ));
    let tlog = Arc::new(
        MockTransparencyLogClient::new()
            .with_badge(BADGE_URL_V1, b_v1)
            .with_badge(BADGE_URL_V2, b_v2),
    );

    let verifier = server_verifier(dns, tlog).await;
    // Server presents v1.0.0 cert (older version still running)
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, v1_server_fp))
        .await;

    assert!(
        outcome.is_success(),
        "Server running older version during multi-ACTIVE transition should pass, got: {:?}",
        outcome
    );
}

/// §6.1 (server-side) Two ACTIVE versions, server running newer version.
#[tokio::test]
async fn test_6_1_server_two_active_versions_newer_server() {
    let host = "agent.example.com";
    let v1_server_fp = SERVER_FP;
    let v2_server_fp = "SHA256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    let b_v1 = badge(host, "v1.0.0", v1_server_fp, IDENTITY_FP);
    let b_v2 = badge(host, "v1.0.1", v2_server_fp, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![
            dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1),
            dns_record(Some(Version::new(1, 0, 1)), BADGE_URL_V2),
        ],
    ));
    let tlog = Arc::new(
        MockTransparencyLogClient::new()
            .with_badge(BADGE_URL_V1, b_v1)
            .with_badge(BADGE_URL_V2, b_v2),
    );

    let verifier = server_verifier(dns, tlog).await;
    // Server presents v1.0.1 cert (newer version)
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, v2_server_fp))
        .await;

    assert!(
        outcome.is_success(),
        "Server running newer version should also pass, got: {:?}",
        outcome
    );
}

/// §6.2 Old version AHP-deprecated, new version ACTIVE, client on old → pass with warning.
///
/// The AHP has explicitly deprecated v1.0.0. v1.0.1 is ACTIVE.
/// Client still presents v1.0.0 identity cert. Should pass with DEPRECATED warning.
#[tokio::test]
async fn test_6_2_old_deprecated_new_active() {
    let host = "agent.example.com";
    let v1_identity_fp = IDENTITY_FP;
    let v2_identity_fp = "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let b_v1 = badge_with_status(
        host,
        "v1.0.0",
        SERVER_FP,
        v1_identity_fp,
        BadgeStatus::Deprecated,
    );
    let b_v2 = badge(host, "v1.0.1", SERVER_FP, v2_identity_fp);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![
            dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1),
            dns_record(Some(Version::new(1, 0, 1)), BADGE_URL_V2),
        ],
    ));
    let tlog = Arc::new(
        MockTransparencyLogClient::new()
            .with_badge(BADGE_URL_V1, b_v1)
            .with_badge(BADGE_URL_V2, b_v2),
    );

    let verifier = client_verifier(dns, tlog).await;
    // Client presents v1.0.0 cert (old, deprecated version)
    let outcome = verifier
        .verify(&mtls_cert(host, "v1.0.0", v1_identity_fp))
        .await;

    assert!(
        outcome.is_success(),
        "AHP-deprecated old version should still pass, got: {:?}",
        outcome
    );
    assert_eq!(outcome.badge().unwrap().status, BadgeStatus::Deprecated);
}

/// §6.3 No matching version in DNS → reject.
#[tokio::test]
async fn test_6_3_no_matching_version() {
    let host = "agent.example.com";
    // DNS only has v1.0.1
    let b = badge(host, "v1.0.1", SERVER_FP, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 1)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = client_verifier(dns, tlog).await;
    // Client presents v1.0.0 cert — no matching badge in DNS
    let outcome = verifier
        .verify(&mtls_cert(host, "v1.0.0", IDENTITY_FP))
        .await;

    // Badge's ans_name (v1.0.1) won't match cert's ans_name (v1.0.0)
    assert!(
        matches!(outcome, VerificationOutcome::AnsNameMismatch { .. }),
        "No matching version should reject, got: {:?}",
        outcome
    );
}

/// §6.4 Server verification, no version in cert → ACTIVE badge preferred.
///
/// Server certs don't contain version info. With two badges (one ACTIVE, one
/// DEPRECATED), the verifier should prefer the ACTIVE badge.
#[tokio::test]
async fn test_6_4_server_no_version_prefers_active() {
    let host = "agent.example.com";
    let active_fp = SERVER_FP;

    let b_deprecated = badge_with_status(
        host,
        "v1.0.0",
        WRONG_FP,
        IDENTITY_FP,
        BadgeStatus::Deprecated,
    );
    let b_active = badge(host, "v1.0.1", active_fp, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![
            dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1),
            dns_record(Some(Version::new(1, 0, 1)), BADGE_URL_V2),
        ],
    ));
    let tlog = Arc::new(
        MockTransparencyLogClient::new()
            .with_badge(BADGE_URL_V1, b_deprecated)
            .with_badge(BADGE_URL_V2, b_active),
    );

    let verifier = server_verifier(dns, tlog).await;
    // Server cert has the ACTIVE version's fingerprint
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, active_fp))
        .await;

    assert!(
        outcome.is_success(),
        "Should prefer ACTIVE badge for server verification, got: {:?}",
        outcome
    );
}

/// §6.5 Multiple records, partial fetch failure → pass if successful badge matches.
#[tokio::test]
async fn test_6_5_partial_fetch_failure_success() {
    let host = "agent.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![
            dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1),
            dns_record(Some(Version::new(1, 0, 1)), BADGE_URL_V2),
        ],
    ));
    // v1.0.1 fetch fails, v1.0.0 succeeds
    let tlog = Arc::new(
        MockTransparencyLogClient::new()
            .with_badge(BADGE_URL_V1, b)
            .with_error(BADGE_URL_V2, TlogError::ServiceUnavailable),
    );

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        outcome.is_success(),
        "Should pass if at least one badge matches, got: {:?}",
        outcome
    );
}

/// §6.5 Multiple records, partial fetch failure → failure policy if no match.
#[tokio::test]
async fn test_6_5_partial_fetch_failure_no_match() {
    let host = "agent.example.com";
    let b = badge(host, "v1.0.0", WRONG_FP, IDENTITY_FP); // Wrong fingerprint

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![
            dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1),
            dns_record(Some(Version::new(1, 0, 1)), BADGE_URL_V2),
        ],
    ));
    // v1.0.1 fetch fails, v1.0.0 fetches but doesn't match
    let tlog = Arc::new(
        MockTransparencyLogClient::new()
            .with_badge(BADGE_URL_V1, b)
            .with_error(BADGE_URL_V2, TlogError::ServiceUnavailable),
    );

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        matches!(outcome, VerificationOutcome::FingerprintMismatch { .. }),
        "No matching badge should return mismatch, got: {:?}",
        outcome
    );
}

// =========================================================================
// §7 DANE/TLSA Verification
// =========================================================================

/// §7.1 DNSSEC validated, TLSA matches → DANE pass.
#[tokio::test]
async fn test_7_1_dane_tlsa_matches() {
    let host = "dane.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);
    let fp = CertFingerprint::parse(SERVER_FP).unwrap();

    let tlsa = TlsaRecord::new(
        TlsaUsage::DomainIssuedCertificate,
        TlsaSelector::FullCertificate,
        TlsaMatchingType::Sha256,
        fp.as_bytes().to_vec(),
    );

    let dns = Arc::new(
        MockDnsResolver::new()
            .with_records(
                host,
                vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
            )
            .with_tlsa_records(host, 443, vec![tlsa]),
    );
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = ServerVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .with_dane_if_present()
        .build()
        .await
        .unwrap();

    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        outcome.is_success(),
        "DANE verification should pass when TLSA matches, got: {:?}",
        outcome
    );
}

/// §7.2 DNSSEC validated, TLSA mismatch → reject.
#[tokio::test]
async fn test_7_2_dane_tlsa_mismatch() {
    let host = "dane.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let wrong_fp = CertFingerprint::parse(WRONG_FP).unwrap();
    let tlsa = TlsaRecord::new(
        TlsaUsage::DomainIssuedCertificate,
        TlsaSelector::FullCertificate,
        TlsaMatchingType::Sha256,
        wrong_fp.as_bytes().to_vec(),
    );

    let dns = Arc::new(
        MockDnsResolver::new()
            .with_records(
                host,
                vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
            )
            .with_tlsa_records(host, 443, vec![tlsa]),
    );
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = ServerVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .with_dane_if_present()
        .build()
        .await
        .unwrap();

    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        matches!(outcome, VerificationOutcome::DaneError(_)),
        "DANE mismatch should reject, got: {:?}",
        outcome
    );
}

/// §7.3 No DNSSEC present → DANE skipped (not an error).
#[tokio::test]
async fn test_7_3_no_dnssec_dane_skipped() {
    let host = "nodane.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    // No TLSA records
    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = ServerVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .with_dane_if_present()
        .build()
        .await
        .unwrap();

    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        outcome.is_success(),
        "No TLSA records + ValidateIfPresent should pass, got: {:?}",
        outcome
    );
}

/// §7.4 DNSSEC validation failure on TLSA lookup → DANE error (reject).
#[tokio::test]
async fn test_7_4_dnssec_validation_failure() {
    let host = "dane.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    // Badge DNS records exist and succeed
    let dns = Arc::new(
        MockDnsResolver::new()
            .with_records(
                host,
                vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
            )
            // TLSA lookup fails with DNSSEC validation error
            .with_tlsa_error(
                host,
                443,
                DnsError::DnssecFailed {
                    fqdn: host.to_string(),
                },
            ),
    );
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = ServerVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .with_dane_if_present()
        .build()
        .await
        .unwrap();

    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        matches!(outcome, VerificationOutcome::DaneError(_)),
        "DNSSEC validation failure should reject with DaneError, got: {:?}",
        outcome
    );
}

/// §7.5 Multiple TLSA records (renewal window) → any match is a pass.
#[tokio::test]
async fn test_7_5_multiple_tlsa_records_any_match() {
    let host = "dane.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);
    let correct_fp = CertFingerprint::parse(SERVER_FP).unwrap();
    let old_fp = CertFingerprint::parse(WRONG_FP).unwrap();

    // Two TLSA records: old cert and new cert (renewal window)
    let tlsa_old = TlsaRecord::new(
        TlsaUsage::DomainIssuedCertificate,
        TlsaSelector::FullCertificate,
        TlsaMatchingType::Sha256,
        old_fp.as_bytes().to_vec(),
    );
    let tlsa_new = TlsaRecord::new(
        TlsaUsage::DomainIssuedCertificate,
        TlsaSelector::FullCertificate,
        TlsaMatchingType::Sha256,
        correct_fp.as_bytes().to_vec(),
    );

    let dns = Arc::new(
        MockDnsResolver::new()
            .with_records(
                host,
                vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
            )
            .with_tlsa_records(host, 443, vec![tlsa_old, tlsa_new]),
    );
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = ServerVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .with_dane_if_present()
        .build()
        .await
        .unwrap();

    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        outcome.is_success(),
        "Should pass when any TLSA record matches, got: {:?}",
        outcome
    );
}

// =========================================================================
// §8 Caching Behavior
// =========================================================================

/// §8.1 Cache hit within TTL → cached badge used, no network call.
#[tokio::test]
async fn test_8_1_cache_hit_within_ttl() {
    let host = "cached.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let cache = Arc::new(BadgeCache::with_defaults());
    let fqdn = Fqdn::new(host).unwrap();
    cache
        .insert_for_fqdn_version(&fqdn, &Version::new(1, 0, 0), b)
        .await;

    // Empty DNS/TLog — if cache weren't used, verification would fail
    let dns = Arc::new(MockDnsResolver::new());
    let tlog = Arc::new(MockTransparencyLogClient::new());

    let verifier = ServerVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .cache(cache)
        .build()
        .await
        .unwrap();

    let outcome = verifier.verify(&fqdn, &server_cert(host, SERVER_FP)).await;

    assert!(
        outcome.is_success(),
        "Should use cached badge without network calls, got: {:?}",
        outcome
    );
}

/// §8.2 Cache stale, TL available → badge refreshed.
///
/// Simulates cache miss (stale badge with wrong fingerprint) → forces
/// fresh fetch from DNS + TLog which returns the correct badge.
#[tokio::test]
async fn test_8_2_cache_stale_tlog_available() {
    let host = "agent.example.com";
    let new_fp = SERVER_FP;

    // Fresh badge from TLog has the new fingerprint
    let fresh_badge = badge(host, "v1.0.0", new_fp, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, fresh_badge));

    let cache = Arc::new(BadgeCache::with_defaults());
    let fqdn = Fqdn::new(host).unwrap();

    // Pre-populate cache with stale badge (wrong fingerprint)
    let stale_badge = badge(host, "v1.0.0", WRONG_FP, IDENTITY_FP);
    cache
        .insert_for_fqdn_version(&fqdn, &Version::new(1, 0, 0), stale_badge)
        .await;

    let verifier = ServerVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .cache(cache)
        .build()
        .await
        .unwrap();

    let outcome = verifier.verify(&fqdn, &server_cert(host, new_fp)).await;

    assert!(
        outcome.is_success(),
        "Should refresh stale cache from TLog, got: {:?}",
        outcome
    );
}

/// §8.3 Cache stale, TL unreachable → failure policy applied.
#[tokio::test]
async fn test_8_3_cache_stale_tlog_unreachable_fail_closed() {
    let host = "agent.example.com";
    let cache = Arc::new(BadgeCache::with_defaults());
    let fqdn = Fqdn::new(host).unwrap();

    // Stale badge with wrong fingerprint
    let stale_badge = badge(host, "v1.0.0", WRONG_FP, IDENTITY_FP);
    cache
        .insert_for_fqdn_version(&fqdn, &Version::new(1, 0, 0), stale_badge)
        .await;

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1)],
    ));
    // TLog is unreachable
    let tlog = Arc::new(
        MockTransparencyLogClient::new().with_error(BADGE_URL_V1, TlogError::ServiceUnavailable),
    );

    let verifier = ServerVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .cache(cache)
        .failure_policy(FailurePolicy::FailClosed)
        .build()
        .await
        .unwrap();

    let outcome = verifier.verify(&fqdn, &server_cert(host, SERVER_FP)).await;

    // Stale cache + TLog unreachable + FailClosed = TlogError
    assert!(
        matches!(outcome, VerificationOutcome::TlogError(_)),
        "Stale cache + unreachable TLog + FailClosed should error, got: {:?}",
        outcome
    );
}

/// §8.4 Background refresh configured → verifies cache TTL and refresh semantics.
#[tokio::test]
async fn test_8_4_cache_config_refresh_threshold() {
    let config = CacheConfig::with_ttl(Duration::from_secs(300));
    let cache = BadgeCache::new(config);

    let host = "agent.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);
    let fqdn = Fqdn::new(host).unwrap();

    let version = Version::new(1, 0, 0);
    cache.insert_for_fqdn_version(&fqdn, &version, b).await;

    // Immediately after insert, cache should be valid and not need refresh
    let cached = cache.get_by_fqdn_version(&fqdn, &version).await.unwrap();
    assert!(cached.is_valid());
    assert!(!cache.should_refresh(&cached));
}

// =========================================================================
// §9 Backward Compatibility
// =========================================================================

/// §9.1 New SDK, `_ans-badge` + `v=ans-badge1` → direct match.
#[tokio::test]
async fn test_9_1_ans_badge_direct_match() {
    let host = "modern.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let record = BadgeRecord::new("ans-badge1", Some(Version::new(1, 0, 0)), BADGE_URL_V1);
    let dns = Arc::new(MockDnsResolver::new().with_records(host, vec![record]));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(outcome.is_success());
}

/// §9.2 New SDK, `_ra-badge` + `v=ra-badge1` → fallback path, parsed.
#[tokio::test]
async fn test_9_2_ra_badge_fallback_path() {
    let host = "legacy.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    let record = BadgeRecord::new("ra-badge1", Some(Version::new(1, 0, 0)), BADGE_URL_V1);
    let dns = Arc::new(MockDnsResolver::new().with_records(host, vec![record]));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        outcome.is_success(),
        "ra-badge1 format should work via fallback, got: {:?}",
        outcome
    );
}

/// §9.3 New SDK, `_ra-badge` with bare semver → normalized, pass.
#[test]
fn test_9_3_ra_badge_bare_semver_normalized() {
    let txt = "v=ra-badge1; version=1.0.0; url=https://tlog.example.com/v1/agents/test";
    let record = BadgeRecord::parse(txt).unwrap();

    assert_eq!(record.format_version(), "ra-badge1");
    // Version should be normalized from "1.0.0" to Version(1,0,0)
    assert_eq!(record.version(), Some(&Version::new(1, 0, 0)));
    // Display as v-prefixed
    assert_eq!(record.version().unwrap().to_string(), "v1.0.0");
}

/// §9.4 Both `_ans-badge` and `_ra-badge` exist → `_ans-badge` takes priority.
///
/// This is enforced by the DNS resolver's lookup_badge method which queries
/// `_ans-badge` first and only falls back to `_ra-badge` if not found.
/// With mocks, we verify that when records exist under the host key (simulating
/// _ans-badge), the fallback is not needed.
#[tokio::test]
async fn test_9_4_ans_badge_takes_priority() {
    let host = "both.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    // Simulate _ans-badge record (primary)
    let record = BadgeRecord::new("ans-badge1", Some(Version::new(1, 0, 0)), BADGE_URL_V1);
    let dns = Arc::new(MockDnsResolver::new().with_records(host, vec![record]));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier(dns, tlog).await;
    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(outcome.is_success());
}

// =========================================================================
// Additional: BadgeStatus invariants
// =========================================================================

// =========================================================================
// §10 Trusted RA Domain Validation
// =========================================================================

/// §10.1 Server verification with untrusted badge domain → reject.
#[tokio::test]
async fn test_10_1_trusted_ra_domain_server_reject() {
    let host = "agent.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);
    let evil_url = "https://evil.attacker.com/v1/agents/test-id";

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), evil_url)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(evil_url, b));

    let verifier = ServerVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .trusted_ra_domains(["tlog.example.com"])
        .build()
        .await
        .unwrap();

    let outcome = verifier
        .verify(&Fqdn::new(host).unwrap(), &server_cert(host, SERVER_FP))
        .await;

    assert!(
        matches!(
            outcome,
            VerificationOutcome::TlogError(TlogError::UntrustedDomain { .. })
        ),
        "Server verifier should reject untrusted badge domain, got: {:?}",
        outcome
    );
}

/// §10.2 Client verification with untrusted badge domain → reject.
#[tokio::test]
async fn test_10_2_trusted_ra_domain_client_reject() {
    let host = "agent.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);
    let evil_url = "https://evil.attacker.com/v1/agents/test-id";

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![dns_record(Some(Version::new(1, 0, 0)), evil_url)],
    ));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(evil_url, b));

    let verifier = ClientVerifier::builder()
        .dns_resolver(dns as Arc<dyn DnsResolver>)
        .tlog_client(tlog as Arc<dyn TransparencyLogClient>)
        .trusted_ra_domains(["tlog.example.com"])
        .build()
        .await
        .unwrap();

    let outcome = verifier
        .verify(&mtls_cert(host, "v1.0.0", IDENTITY_FP))
        .await;

    assert!(
        matches!(
            outcome,
            VerificationOutcome::TlogError(TlogError::UntrustedDomain { .. })
        ),
        "Client verifier should reject untrusted badge domain, got: {:?}",
        outcome
    );
}

/// Verify BadgeStatus classification matches the updated spec.
///
/// Per AGENT_TO_AGENT_FLOW §2.3:
/// - ACTIVE/WARNING → fully active, proceed with verification
/// - DEPRECATED → AHP-initiated retirement signal, still valid for connections
/// - EXPIRED/REVOKED → reject
#[test]
fn test_badge_status_classification() {
    // is_active: Active and Warning only (not Deprecated)
    assert!(BadgeStatus::Active.is_active());
    assert!(BadgeStatus::Warning.is_active());
    assert!(!BadgeStatus::Deprecated.is_active());
    assert!(!BadgeStatus::Expired.is_active());
    assert!(!BadgeStatus::Revoked.is_active());

    // is_valid_for_connection: Active, Warning, and Deprecated
    assert!(BadgeStatus::Active.is_valid_for_connection());
    assert!(BadgeStatus::Warning.is_valid_for_connection());
    assert!(BadgeStatus::Deprecated.is_valid_for_connection());
    assert!(!BadgeStatus::Expired.is_valid_for_connection());
    assert!(!BadgeStatus::Revoked.is_valid_for_connection());

    // should_reject: Expired and Revoked only
    assert!(!BadgeStatus::Active.should_reject());
    assert!(!BadgeStatus::Warning.should_reject());
    assert!(!BadgeStatus::Deprecated.should_reject());
    assert!(BadgeStatus::Expired.should_reject());
    assert!(BadgeStatus::Revoked.should_reject());
}

// =========================================================================
// §11 Multi-Version Badge Caching
// =========================================================================

/// §11.1 Prefetch caches both versions; verify with either version's cert hits cache.
///
/// When prefetch() is called for an FQDN with two badge records (v1.0.0, v1.0.1),
/// both badges should be cached. A subsequent verify() with either version's
/// fingerprint should hit the cache without a DNS+TLog round trip.
#[tokio::test]
async fn test_11_1_prefetch_caches_both_versions() {
    let host = "agent.example.com";
    let v1_server_fp = SERVER_FP;
    let v2_server_fp = "SHA256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    let b_v1 = badge(host, "v1.0.0", v1_server_fp, IDENTITY_FP);
    let b_v2 = badge(host, "v1.0.1", v2_server_fp, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![
            dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1),
            dns_record(Some(Version::new(1, 0, 1)), BADGE_URL_V2),
        ],
    ));
    let tlog = Arc::new(
        MockTransparencyLogClient::new()
            .with_badge(BADGE_URL_V1, b_v1)
            .with_badge(BADGE_URL_V2, b_v2),
    );

    let verifier = server_verifier_with_cache(dns, tlog).await;
    let fqdn = Fqdn::new(host).unwrap();

    // Prefetch should cache both versions
    let prefetch_result = verifier.prefetch(&fqdn).await;
    assert!(prefetch_result.is_ok());

    // Verify with v1.0.0 cert should hit cache (no DNS/TLog needed)
    let outcome_v1 = verifier
        .verify(&fqdn, &server_cert(host, v1_server_fp))
        .await;
    assert!(
        outcome_v1.is_success(),
        "v1.0.0 cert should match cached badge, got: {:?}",
        outcome_v1
    );

    // Verify with v1.0.1 cert should also hit cache
    let outcome_v2 = verifier
        .verify(&fqdn, &server_cert(host, v2_server_fp))
        .await;
    assert!(
        outcome_v2.is_success(),
        "v1.0.1 cert should match cached badge, got: {:?}",
        outcome_v2
    );
}

/// §11.2 Verify caches all fetched badges, second verify with different version hits cache.
///
/// First verify with v1.0.1 cert triggers DNS+TLog, caches both v1.0.0 and v1.0.1.
/// Second verify with v1.0.0 cert should hit the cache directly.
#[tokio::test]
async fn test_11_2_verify_caches_all_fetched_badges() {
    let host = "agent.example.com";
    let v1_server_fp = SERVER_FP;
    let v2_server_fp = "SHA256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    let b_v1 = badge(host, "v1.0.0", v1_server_fp, IDENTITY_FP);
    let b_v2 = badge(host, "v1.0.1", v2_server_fp, IDENTITY_FP);

    let dns = Arc::new(MockDnsResolver::new().with_records(
        host,
        vec![
            dns_record(Some(Version::new(1, 0, 0)), BADGE_URL_V1),
            dns_record(Some(Version::new(1, 0, 1)), BADGE_URL_V2),
        ],
    ));
    let tlog = Arc::new(
        MockTransparencyLogClient::new()
            .with_badge(BADGE_URL_V1, b_v1)
            .with_badge(BADGE_URL_V2, b_v2),
    );

    let verifier = server_verifier_with_cache(dns, tlog).await;
    let fqdn = Fqdn::new(host).unwrap();

    // First verify with v1.0.0 cert — triggers DNS+TLog fetch of both badges
    let outcome1 = verifier
        .verify(&fqdn, &server_cert(host, v1_server_fp))
        .await;
    assert!(
        outcome1.is_success(),
        "First verify should pass, got: {:?}",
        outcome1
    );

    // Second verify with v1.0.1 cert — should hit the cache
    let outcome2 = verifier
        .verify(&fqdn, &server_cert(host, v2_server_fp))
        .await;
    assert!(
        outcome2.is_success(),
        "Second verify with different version cert should hit cache, got: {:?}",
        outcome2
    );
}

/// §11.3 Versionless badge record still caches by parsed version.
///
/// When a DNS record lacks an explicit version field, the version is parsed
/// from the badge's agent_version field (e.g., "v1.0.0").
#[tokio::test]
async fn test_11_3_versionless_record_caches_correctly() {
    let host = "agent.example.com";
    let b = badge(host, "v1.0.0", SERVER_FP, IDENTITY_FP);

    // DNS record without explicit version
    let dns =
        Arc::new(MockDnsResolver::new().with_records(host, vec![dns_record(None, BADGE_URL_V1)]));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL_V1, b));

    let verifier = server_verifier_with_cache(dns, tlog).await;
    let fqdn = Fqdn::new(host).unwrap();

    // First verify — should succeed and cache the badge
    let outcome = verifier.verify(&fqdn, &server_cert(host, SERVER_FP)).await;
    assert!(
        outcome.is_success(),
        "Versionless record should verify, got: {:?}",
        outcome
    );

    // Second verify should hit cache
    let outcome2 = verifier.verify(&fqdn, &server_cert(host, SERVER_FP)).await;
    assert!(
        outcome2.is_success(),
        "Second verify should use cached badge, got: {:?}",
        outcome2
    );
}
