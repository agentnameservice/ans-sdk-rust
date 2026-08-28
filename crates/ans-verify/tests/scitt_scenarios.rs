#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! SCITT integration test scenarios from SCITT_IMPLEMENTATION_PLAN.md §10.4.
//!
//! Each test maps to a scenario ID (e.g., `test_s1_1_*` → S1.1).
//! All external dependencies (DNS, Transparency Log) are mocked.
//! COSE_Sign1 artifacts are built in-process with a test P-256 key pair.

use std::sync::Arc;
use std::time::Duration;

use ans_types::*;
use ans_verify::*;
use base64::prelude::{BASE64_STANDARD, Engine as _};
use chrono::Utc;
use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner as _};
use p256::pkcs8::EncodePublicKey as _;
use sha2::{Digest, Sha256};
use uuid::Uuid;

// =========================================================================
// Constants
// =========================================================================

const HOST: &str = "agent.example.com";
const SERVER_FP: &str = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904";
const IDENTITY_FP: &str = "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496";
const WRONG_FP: &str = "SHA256:0000000000000000000000000000000000000000000000000000000000000000";
const BADGE_URL: &str = "https://tlog.example.com/v1/agents/test-uuid";

// =========================================================================
// Test Helpers — Badge / DNS / Cert
// =========================================================================

fn make_badge(host: &str, version: &str, server_fp: &str, identity_fp: &str) -> Badge {
    make_badge_with_status(host, version, server_fp, identity_fp, BadgeStatus::Active)
}

fn make_badge_with_status(
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
        vec![format!("ans://{version}.{host}")],
        CertFingerprint::parse(fingerprint).unwrap(),
    )
}

// =========================================================================
// Test Helpers — COSE_Sign1 / SCITT
// =========================================================================

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
    exp: i64,
    ans_name: &str,
    identity_certs: &[(String, String)],
    server_certs: &[(String, String)],
) -> Vec<u8> {
    let now = Utc::now().timestamp();
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
        ciborium::Value::Integer(now.into()),
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

fn sign_cose(signing_key: &SigningKey, payload: &[u8]) -> Vec<u8> {
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
    4_102_444_800 // 2100-01-01
}

fn past_exp() -> i64 {
    946_684_800 // 2000-01-01
}

fn nil_uuid() -> String {
    Uuid::nil().to_string()
}

// =========================================================================
// Composite helpers — build a complete SCITT-enabled verifier
// =========================================================================

async fn make_scitt_verifier(
    host: &str,
    server_fp: &str,
    identity_fp: &str,
    key_store: Arc<ScittKeyStore>,
    policy: ScittTierPolicy,
) -> AnsVerifier {
    let badge = make_badge(host, "v1.0.0", server_fp, identity_fp);
    let record = dns_record(Some(Version::new(1, 0, 0)), BADGE_URL);

    let dns = Arc::new(MockDnsResolver::new().with_records(host, vec![record]));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL, badge));

    AnsVerifier::builder()
        .dns_resolver(dns)
        .tlog_client(tlog)
        .scitt_config(ScittConfig::new().with_tier_policy(policy))
        .scitt_key_store(key_store)
        .build()
        .await
        .expect("test verifier build should succeed")
}

fn make_server_token(signing_key: &SigningKey, server_fp: &str) -> Vec<u8> {
    let payload = build_cbor_payload(
        &nil_uuid(),
        "ACTIVE",
        future_exp(),
        &format!("ans://v1.0.0.{HOST}"),
        &[],
        &[(server_fp.to_string(), "X509-DV-SERVER".to_string())],
    );
    sign_cose(signing_key, &payload)
}

fn make_identity_token(signing_key: &SigningKey, identity_fp: &str) -> Vec<u8> {
    let payload = build_cbor_payload(
        &nil_uuid(),
        "ACTIVE",
        future_exp(),
        &format!("ans://v1.0.0.{HOST}"),
        &[(identity_fp.to_string(), "X509-OV-CLIENT".to_string())],
        &[],
    );
    sign_cose(signing_key, &payload)
}

fn make_server_token_with_status(
    signing_key: &SigningKey,
    server_fp: &str,
    status: &str,
) -> Vec<u8> {
    let payload = build_cbor_payload(
        &nil_uuid(),
        status,
        future_exp(),
        &format!("ans://v1.0.0.{HOST}"),
        &[],
        &[(server_fp.to_string(), "X509-DV-SERVER".to_string())],
    );
    sign_cose(signing_key, &payload)
}

fn make_expired_token(signing_key: &SigningKey, server_fp: &str) -> Vec<u8> {
    let payload = build_cbor_payload(
        &nil_uuid(),
        "ACTIVE",
        past_exp(),
        &format!("ans://v1.0.0.{HOST}"),
        &[],
        &[(server_fp.to_string(), "X509-DV-SERVER".to_string())],
    );
    sign_cose(signing_key, &payload)
}

fn build_receipt_protected_bytes(signing_key: &SigningKey) -> Vec<u8> {
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
        // vds=1 (label 395) → RFC9162_SHA256
        (
            ciborium::Value::Integer(395.into()),
            ciborium::Value::Integer(1.into()),
        ),
    ];
    let map = ciborium::Value::Map(pairs);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf).unwrap();
    buf
}

/// Build a valid receipt COSE_Sign1 with a trivial Merkle tree (tree_size=1, leaf_index=0).
///
/// A tree of size 1 has an empty inclusion path — the leaf hash IS the root hash.
fn build_receipt(signing_key: &SigningKey, event_payload: &[u8]) -> Vec<u8> {
    let protected_bytes = build_receipt_protected_bytes(signing_key);
    let digest = compute_sig_structure_digest(&protected_bytes, event_payload).unwrap();
    let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
    let sig_bytes = sig.to_bytes().to_vec();

    // VDP at label 396: tree_size=1, leaf_index=0, empty inclusion_path
    let vdp = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer((-1_i64).into()),
            ciborium::Value::Integer(1.into()), // tree_size
        ),
        (
            ciborium::Value::Integer((-2_i64).into()),
            ciborium::Value::Integer(0.into()), // leaf_index
        ),
        (
            ciborium::Value::Integer((-3_i64).into()),
            ciborium::Value::Array(vec![]), // empty inclusion_path
        ),
    ]);
    let unprotected = ciborium::Value::Map(vec![(ciborium::Value::Integer(396.into()), vdp)]);

    let array = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(protected_bytes),
        unprotected,
        ciborium::Value::Bytes(event_payload.to_vec()),
        ciborium::Value::Bytes(sig_bytes),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&array, &mut buf).unwrap();
    buf
}

fn encode_b64(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

// =========================================================================
// S1: Valid SCITT verification
// =========================================================================

/// S1.1: Valid status token, server verify → ScittVerified (StatusTokenVerified)
#[tokio::test]
async fn test_s1_1_valid_token_server_verify() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token(&signing_key, SERVER_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome.is_success());
    match outcome {
        VerificationOutcome::ScittVerified { tier, .. } => {
            assert_eq!(tier, VerificationTier::StatusTokenVerified);
        }
        other => panic!("Expected ScittVerified, got: {other:?}"),
    }
}

/// ANS-6 §5.2 dialed-host anchor: a valid status token whose `ansName` names
/// a different host than the one the caller dialed → reject, even though the
/// certificate fingerprint is in `validServerCerts`.
#[tokio::test]
async fn test_s1_1b_token_host_not_dialed_host() {
    let dialed_host = "other.example.com";
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    // Token names HOST (agent.example.com), caller dials other.example.com.
    let token = make_server_token(&signing_key, SERVER_FP);

    let verifier = make_scitt_verifier(
        dialed_host,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(dialed_host, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(dialed_host, &cert, &headers)
        .await;
    assert!(
        matches!(
            outcome,
            VerificationOutcome::ScittError(ScittError::HostMismatch { ref expected, ref actual })
                if expected == dialed_host && actual == HOST
        ),
        "Expected HostMismatch anchored to the dialed host, got: {outcome:?}"
    );
}

/// S1.2: Valid status token, mTLS verify → ScittVerified
#[tokio::test]
async fn test_s1_2_valid_token_mtls_verify() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_identity_token(&signing_key, IDENTITY_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = mtls_cert(HOST, "v1.0.0", IDENTITY_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier.verify_client_with_scitt(&cert, &headers).await;
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
}

// =========================================================================
// S2: Missing headers → badge fallback
// =========================================================================

/// S2.1: Missing receipt header only → ScittVerified (token alone is sufficient)
#[tokio::test]
async fn test_s2_1_missing_receipt_header() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token(&signing_key, SERVER_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    // Token present, receipt absent
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome.is_success());
    match outcome {
        VerificationOutcome::ScittVerified { tier, .. } => {
            assert_eq!(tier, VerificationTier::StatusTokenVerified);
        }
        other => panic!("Expected ScittVerified with StatusTokenVerified tier, got: {other:?}"),
    }
}

/// S2.2: Receipt present but no status token → reject (headers present = SCITT final)
#[tokio::test]
async fn test_s2_2_missing_token_header() {
    let (_, store) = make_key_and_store(1);
    let store = Arc::new(store);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    // Receipt present but no token — headers are present so SCITT result is final
    let headers = ScittHeaders::from_base64(Some("aGVsbG8="), None).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    // Headers present without token = hard reject, no badge fallback
    assert!(
        !outcome.is_success(),
        "Expected failure when receipt present but token missing"
    );
    assert!(
        matches!(outcome, VerificationOutcome::ScittError(_)),
        "Expected ScittError, got: {outcome:?}"
    );
}

/// S2.3: Both headers absent → badge verification
#[tokio::test]
async fn test_s2_3_both_headers_absent() {
    let (_, store) = make_key_and_store(1);
    let store = Arc::new(store);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::new(None, None);

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::Verified { .. }));
}

// =========================================================================
// S3: Present-but-corrupt headers → REJECT (not fallback)
// =========================================================================

/// S3.1: Receipt header present but not valid Base64 → Reject at header decode
#[test]
fn test_s3_1_receipt_invalid_base64() {
    let result = ScittHeaders::from_base64(Some("not!valid!base64!"), None);
    assert!(result.is_err());
    match result.unwrap_err() {
        ScittError::Base64Decode(msg) => assert!(msg.contains("receipt")),
        other => panic!("Expected Base64Decode, got: {other}"),
    }
}

/// S3.2: Receipt header present but not valid COSE → Reject at verification
#[tokio::test]
async fn test_s3_2_receipt_invalid_cose() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    // Valid token but garbage receipt
    let token = make_server_token(&signing_key, SERVER_FP);
    let garbage_receipt = BASE64_STANDARD.encode(b"not-a-cose-structure");

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers =
        ScittHeaders::from_base64(Some(&garbage_receipt), Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    // Token verifies, receipt fails → still ScittVerified but StatusTokenVerified tier
    // (bad receipt degrades tier, doesn't reject)
    assert!(outcome.is_success());
    match outcome {
        VerificationOutcome::ScittVerified { tier, .. } => {
            assert_eq!(tier, VerificationTier::StatusTokenVerified);
        }
        other => panic!("Expected ScittVerified with degraded tier, got: {other:?}"),
    }
}

/// S3.5: Token signature invalid → Reject (not fallback)
#[tokio::test]
async fn test_s3_5_token_signature_invalid() {
    let (signing_key, _) = make_key_and_store(1);
    let (_, wrong_store) = make_key_and_store(2); // Different key
    let wrong_store = Arc::new(wrong_store);
    let token = make_server_token(&signing_key, SERVER_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        wrong_store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    // Crypto failure → hard reject (not badge fallback)
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

// =========================================================================
// S4: Expired token behavior
// =========================================================================

/// S4.1: Expired token with headers present → hard reject (no badge fallback)
#[tokio::test]
async fn test_s4_1_expired_token_with_headers_rejects() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_expired_token(&signing_key, SERVER_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    // Headers present + expired token = hard reject (no badge fallback)
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

/// S4.2: Expired token with RequireScitt → also rejects
#[tokio::test]
async fn test_s4_2_expired_token_require_scitt_rejects() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_expired_token(&signing_key, SERVER_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::RequireScitt,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

// =========================================================================
// S5: Fingerprint matching
// =========================================================================

/// S5.1: Fingerprint matches 2nd array element → ScittVerified
#[tokio::test]
async fn test_s5_1_fingerprint_matches_second_element() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let other_fp = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // Token with two server certs: first=other_fp, second=SERVER_FP
    let payload = build_cbor_payload(
        &nil_uuid(),
        "ACTIVE",
        future_exp(),
        &format!("ans://v1.0.0.{HOST}"),
        &[],
        &[
            (other_fp.to_string(), "X509-DV-SERVER".to_string()),
            (SERVER_FP.to_string(), "X509-DV-SERVER".to_string()),
        ],
    );
    let token = sign_cose(&signing_key, &payload);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
}

/// S5.2: Fingerprint not in any element → Reject
#[tokio::test]
async fn test_s5_2_fingerprint_not_in_array() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    // Token lists WRONG_FP, cert has SERVER_FP
    let token = make_server_token(&signing_key, WRONG_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

/// S5.3: Renewal overlap — both old+new cert fingerprints in token
#[tokio::test]
async fn test_s5_3_renewal_overlap_both_certs_accepted() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let new_fp = "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    // Token lists both old (SERVER_FP) and new (new_fp) certs
    let payload = build_cbor_payload(
        &nil_uuid(),
        "ACTIVE",
        future_exp(),
        &format!("ans://v1.0.0.{HOST}"),
        &[],
        &[
            (SERVER_FP.to_string(), "X509-DV-SERVER".to_string()),
            (new_fp.to_string(), "X509-DV-SERVER".to_string()),
        ],
    );
    let token = sign_cose(&signing_key, &payload);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store.clone(),
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;

    // Old cert still works
    let old_cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();
    let outcome = verifier
        .verify_server_with_scitt(HOST, &old_cert, &headers)
        .await;
    assert!(outcome.is_success());

    // New cert also works
    let new_cert = server_cert(HOST, new_fp);
    let verifier2 = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let headers2 = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();
    let outcome2 = verifier2
        .verify_server_with_scitt(HOST, &new_cert, &headers2)
        .await;
    assert!(outcome2.is_success());
}

// =========================================================================
// S7: Mixed SCITT/badge peers
// =========================================================================

/// S7.1: Server has SCITT, client badge-only → badge verification
#[tokio::test]
async fn test_s7_1_server_scitt_client_badge_only() {
    let (_, store) = make_key_and_store(1);
    let store = Arc::new(store);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    // No SCITT headers (badge-only client)
    let headers = ScittHeaders::new(None, None);

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::Verified { .. }));
}

// =========================================================================
// S8: mTLS SCITT scenarios
// =========================================================================

/// S8.1: mTLS all checks pass, ACTIVE → ScittVerified
#[tokio::test]
async fn test_s8_1_mtls_active_all_pass() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_identity_token(&signing_key, IDENTITY_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = mtls_cert(HOST, "v1.0.0", IDENTITY_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier.verify_client_with_scitt(&cert, &headers).await;
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
}

/// S8.2: mTLS fingerprint not in identity array → Reject
#[tokio::test]
async fn test_s8_2_mtls_fingerprint_not_in_identity_array() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    // Token lists WRONG_FP as identity cert
    let token = make_identity_token(&signing_key, WRONG_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = mtls_cert(HOST, "v1.0.0", IDENTITY_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier.verify_client_with_scitt(&cert, &headers).await;
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

/// S8.4: mTLS DEPRECATED status → ScittVerified (deprecated is not terminal)
#[tokio::test]
async fn test_s8_4_mtls_deprecated_status() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);

    let payload = build_cbor_payload(
        &nil_uuid(),
        "DEPRECATED",
        future_exp(),
        &format!("ans://v1.0.0.{HOST}"),
        &[(IDENTITY_FP.to_string(), "X509-OV-CLIENT".to_string())],
        &[],
    );
    let token = sign_cose(&signing_key, &payload);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = mtls_cert(HOST, "v1.0.0", IDENTITY_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier.verify_client_with_scitt(&cert, &headers).await;
    // DEPRECATED is allowed (not terminal) → ScittVerified
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
}

// =========================================================================
// Policy-specific tests
// =========================================================================

/// RequireScitt with empty headers → fail
#[tokio::test]
async fn test_require_scitt_empty_headers_fails() {
    let (_, store) = make_key_and_store(1);
    let store = Arc::new(store);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::RequireScitt,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::new(None, None);

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

/// RequireScitt with expired token → fail (no badge fallback)
#[tokio::test]
async fn test_require_scitt_expired_token_fails() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_expired_token(&signing_key, SERVER_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::RequireScitt,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

/// BadgeWithScittEnhancement: both succeed → ScittVerified
#[tokio::test]
async fn test_badge_enhancement_both_succeed() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token(&signing_key, SERVER_FP);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::BadgeWithScittEnhancement,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
}

/// BadgeWithScittEnhancement: no headers → badge only
#[tokio::test]
async fn test_badge_enhancement_no_headers() {
    let (_, store) = make_key_and_store(1);
    let store = Arc::new(store);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::BadgeWithScittEnhancement,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::new(None, None);

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::Verified { .. }));
}

/// Terminal status (REVOKED) in token → hard reject regardless of policy
#[tokio::test]
async fn test_terminal_status_revoked_hard_reject() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token_with_status(&signing_key, SERVER_FP, "REVOKED");

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(!outcome.is_success());
    assert!(
        matches!(outcome, VerificationOutcome::ScittError(_)),
        "Expected ScittError for REVOKED status"
    );
}

/// Terminal status (EXPIRED) in token → hard reject regardless of policy
#[tokio::test]
async fn test_terminal_status_expired_hard_reject() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token_with_status(&signing_key, SERVER_FP, "EXPIRED");

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

// =========================================================================
// S9 — On-demand key refresh scenarios
// =========================================================================

/// Helper: build a C2SP key string from a seed byte.
fn make_c2sp_key_string(seed: u8) -> String {
    let signing_key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let verifying_key = signing_key.verifying_key();
    let spki_doc = verifying_key.to_public_key_der().unwrap();
    let spki_der = spki_doc.as_bytes();
    let digest = Sha256::digest(spki_der);
    let kid: [u8; 4] = [digest[0], digest[1], digest[2], digest[3]];
    let key_hash_hex = hex::encode(kid);
    let spki_b64 = BASE64_STANDARD.encode(spki_der);
    format!("tl.example.com+{key_hash_hex}+{spki_b64}")
}

/// S9.1: Unknown key ID triggers on-demand refresh and verification succeeds.
///
/// The initial key store has key A (seed=1). A status token is signed with
/// key B (seed=2). The mock client returns key B from `fetch_root_keys()`.
/// The verifier should detect `UnknownKeyId`, refresh, and succeed.
#[tokio::test]
async fn test_s9_1_unknown_key_triggers_refresh_and_succeeds() {
    // Key A (seed=1) is in the initial store
    let key_a_string = make_c2sp_key_string(1);
    let initial_store = ScittKeyStore::from_c2sp_keys(&[key_a_string]).unwrap();

    // Key B (seed=2) is NOT in the initial store — will be returned by mock
    let (signing_key_b, _) = make_key_and_store(2);
    let key_b_string = make_c2sp_key_string(2);

    // Mock client returns key B on root_keys fetch
    let mock_scitt_client = MockScittClient::new().with_root_keys(vec![key_b_string]);

    // Build a RefreshableKeyStore with the mock client
    let refreshable = Arc::new(RefreshableKeyStore::new(
        initial_store,
        Arc::new(mock_scitt_client),
    ));

    // Build verifier using the refreshable store
    let badge = make_badge(HOST, "v1.0.0", SERVER_FP, IDENTITY_FP);
    let record = dns_record(Some(Version::new(1, 0, 0)), BADGE_URL);
    let dns = Arc::new(MockDnsResolver::new().with_records(HOST, vec![record]));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL, badge));

    let verifier = AnsVerifier::builder()
        .dns_resolver(dns)
        .tlog_client(tlog)
        .scitt_config(ScittConfig::new().with_tier_policy(ScittTierPolicy::ScittWithBadgeFallback))
        .scitt_refreshable_key_store(refreshable)
        .build()
        .await
        .expect("build should succeed");

    // Sign token with key B (not in initial store)
    let token = make_server_token(&signing_key_b, SERVER_FP);
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;

    // Should succeed — on-demand refresh fetched key B
    assert!(
        outcome.is_success(),
        "Expected success after on-demand key refresh, got: {outcome:?}"
    );
    assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
}

/// Helper: build a SCITT-enabled verifier with `with_caching()` (enables both
/// badge caching and SCITT verification caching).
async fn make_cached_scitt_verifier(
    host: &str,
    server_fp: &str,
    identity_fp: &str,
    key_store: Arc<ScittKeyStore>,
    policy: ScittTierPolicy,
) -> AnsVerifier {
    let badge = make_badge(host, "v1.0.0", server_fp, identity_fp);
    let record = dns_record(Some(Version::new(1, 0, 0)), BADGE_URL);

    let dns = Arc::new(MockDnsResolver::new().with_records(host, vec![record]));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL, badge));

    AnsVerifier::builder()
        .dns_resolver(dns)
        .tlog_client(tlog)
        .scitt_config(ScittConfig::new().with_tier_policy(policy))
        .scitt_key_store(key_store)
        .with_caching()
        .build()
        .await
        .expect("test verifier build should succeed")
}

/// S9.2: Unknown key ID within cooldown returns error immediately.
///
/// The refreshable store was just refreshed (within cooldown). The verifier
/// should NOT make another network call and should return the original
/// UnknownKeyId as a ScittError.
#[tokio::test]
async fn test_s9_2_unknown_key_within_cooldown_returns_error() {
    // Key A (seed=1) is in the initial store
    let key_a_string = make_c2sp_key_string(1);
    let initial_store = ScittKeyStore::from_c2sp_keys(&[key_a_string.clone()]).unwrap();

    // Key B (seed=3) — token will be signed with this, but mock only returns key A
    let (signing_key_b, _) = make_key_and_store(3);

    // Mock client returns only key A (not key B) — refresh won't help
    let mock_scitt_client = MockScittClient::new().with_root_keys(vec![key_a_string]);

    // Use a very long cooldown (1 hour) so we're always within it
    let refreshable = Arc::new(RefreshableKeyStore::with_cooldown(
        initial_store,
        Arc::new(mock_scitt_client),
        Duration::from_secs(3600),
    ));

    // Force an initial refresh so last_refreshed is set (within cooldown)
    refreshable.do_refresh().await.unwrap();

    // Build verifier
    let badge = make_badge(HOST, "v1.0.0", SERVER_FP, IDENTITY_FP);
    let record = dns_record(Some(Version::new(1, 0, 0)), BADGE_URL);
    let dns = Arc::new(MockDnsResolver::new().with_records(HOST, vec![record]));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL, badge));

    let verifier = AnsVerifier::builder()
        .dns_resolver(dns)
        .tlog_client(tlog)
        .scitt_config(ScittConfig::new().with_tier_policy(ScittTierPolicy::RequireScitt))
        .scitt_refreshable_key_store(refreshable)
        .build()
        .await
        .expect("build should succeed");

    // Sign token with key B (not in store, won't be found even after refresh)
    let token = make_server_token(&signing_key_b, SERVER_FP);
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;

    // Within cooldown — should fail with ScittError (no second network call)
    assert!(
        !outcome.is_success(),
        "Expected failure within cooldown, got: {outcome:?}"
    );
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

// =========================================================================
// S10: Verification cache integration tests
// =========================================================================

/// S10.1: Repeated identical calls return consistent ScittVerified results.
///
/// After the first call does full ECDSA + fingerprint verification, the
/// second call hits the Layer 2 outcome cache and returns the same result
/// without re-doing any cryptographic work.
#[tokio::test]
async fn test_s10_1_repeated_calls_return_consistent_results() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token(&signing_key, SERVER_FP);

    let verifier = make_cached_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    // First call: full verification
    let outcome1 = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome1.is_success());
    let tier1 = match &outcome1 {
        VerificationOutcome::ScittVerified { tier, .. } => *tier,
        other => panic!("Expected ScittVerified, got: {other:?}"),
    };

    // Second call: should hit cache and return identical result
    let outcome2 = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome2.is_success());
    match &outcome2 {
        VerificationOutcome::ScittVerified { tier, .. } => {
            assert_eq!(*tier, tier1, "Cached result should have same tier");
        }
        other => panic!("Expected ScittVerified on second call, got: {other:?}"),
    }
}

/// S10.2: Same token with different cert fingerprint — Layer 1 token
/// cache hit but fingerprint comparison still runs and rejects.
///
/// The token lists SERVER_FP. The first call verifies with SERVER_FP cert
/// (success). The second call uses WRONG_FP cert — the Layer 2 outcome
/// cache misses (different cert), the Layer 1 token cache hits (same token
/// bytes), but the fingerprint comparison correctly rejects.
#[tokio::test]
async fn test_s10_2_cached_token_different_cert_rejects() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token(&signing_key, SERVER_FP);

    let verifier = make_cached_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    // First call with correct cert → success (populates Layer 1 + Layer 2)
    let cert_ok = server_cert(HOST, SERVER_FP);
    let outcome1 = verifier
        .verify_server_with_scitt(HOST, &cert_ok, &headers)
        .await;
    assert!(outcome1.is_success());

    // Second call with wrong cert → Layer 2 misses, Layer 1 token hits,
    // fingerprint comparison fails → ScittError
    let cert_wrong = server_cert(HOST, WRONG_FP);
    let outcome2 = verifier
        .verify_server_with_scitt(HOST, &cert_wrong, &headers)
        .await;
    assert!(
        !outcome2.is_success(),
        "Wrong cert should still be rejected even with cached token"
    );
    assert!(matches!(outcome2, VerificationOutcome::ScittError(_)));
}

/// S10.3: Same token with two valid certs (renewal overlap) — both succeed.
///
/// Token lists both OLD_FP and NEW_FP. First call with OLD_FP populates
/// caches. Second call with NEW_FP misses Layer 2 (different cert) but
/// hits Layer 1 token cache and fingerprint match succeeds for NEW_FP too.
#[tokio::test]
async fn test_s10_3_cached_token_renewal_overlap_both_succeed() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let new_fp = "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    // Token lists both SERVER_FP and new_fp
    let payload = build_cbor_payload(
        &nil_uuid(),
        "ACTIVE",
        future_exp(),
        &format!("ans://v1.0.0.{HOST}"),
        &[],
        &[
            (SERVER_FP.to_string(), "X509-DV-SERVER".to_string()),
            (new_fp.to_string(), "X509-DV-SERVER".to_string()),
        ],
    );
    let token = sign_cose(&signing_key, &payload);

    let verifier = make_cached_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    // First call with old cert → populates caches
    let cert_old = server_cert(HOST, SERVER_FP);
    let outcome1 = verifier
        .verify_server_with_scitt(HOST, &cert_old, &headers)
        .await;
    assert!(outcome1.is_success());

    // Second call with new cert → Layer 1 token cache hit, fingerprint ok
    let cert_new = server_cert(HOST, new_fp);
    let outcome2 = verifier
        .verify_server_with_scitt(HOST, &cert_new, &headers)
        .await;
    assert!(
        outcome2.is_success(),
        "New cert should succeed via cached token + fingerprint match"
    );
    assert!(matches!(
        outcome2,
        VerificationOutcome::ScittVerified { .. }
    ));
}

/// S10.4: Errors are not cached — bad signature fails on every call.
///
/// A token signed with key B but verified against key A's store fails.
/// Repeating the call should fail again (errors must not be cached).
#[tokio::test]
async fn test_s10_4_errors_not_cached() {
    let (signing_key, _) = make_key_and_store(1);
    let (_, wrong_store) = make_key_and_store(2);
    let wrong_store = Arc::new(wrong_store);
    let token = make_server_token(&signing_key, SERVER_FP);

    let verifier = make_cached_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        wrong_store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    // First call: signature mismatch → ScittError
    let outcome1 = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(!outcome1.is_success());
    assert!(matches!(outcome1, VerificationOutcome::ScittError(_)));

    // Second call: should fail again (error was not cached)
    let outcome2 = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(!outcome2.is_success());
    assert!(matches!(outcome2, VerificationOutcome::ScittError(_)));
}

/// S10.5: `with_caching()` enables SCITT verification cache automatically.
///
/// Verifies the builder's `with_caching()` method produces a working
/// verifier with both badge and SCITT verification caching active.
#[tokio::test]
async fn test_s10_5_with_caching_enables_scitt_cache() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token(&signing_key, SERVER_FP);

    let badge = make_badge(HOST, "v1.0.0", SERVER_FP, IDENTITY_FP);
    let record = dns_record(Some(Version::new(1, 0, 0)), BADGE_URL);
    let dns = Arc::new(MockDnsResolver::new().with_records(HOST, vec![record]));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL, badge));

    let verifier = AnsVerifier::builder()
        .dns_resolver(dns)
        .tlog_client(tlog)
        .scitt_config(ScittConfig::new().with_tier_policy(ScittTierPolicy::ScittWithBadgeFallback))
        .scitt_key_store(store)
        .with_caching()
        .build()
        .await
        .expect("build should succeed");

    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    // Verify twice — should succeed both times (second hits cache)
    for i in 0..2 {
        let outcome = verifier
            .verify_server_with_scitt(HOST, &cert, &headers)
            .await;
        assert!(
            outcome.is_success(),
            "Call {i} should succeed with caching enabled"
        );
        assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
    }
}

/// S10.6: `with_scitt_verification_cache()` explicit cache builder method.
///
/// Tests the explicit cache builder method with custom max entries.
#[tokio::test]
async fn test_s10_6_explicit_cache_builder_method() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token(&signing_key, SERVER_FP);

    let badge = make_badge(HOST, "v1.0.0", SERVER_FP, IDENTITY_FP);
    let record = dns_record(Some(Version::new(1, 0, 0)), BADGE_URL);
    let dns = Arc::new(MockDnsResolver::new().with_records(HOST, vec![record]));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(BADGE_URL, badge));

    let custom_cache = ScittVerificationCache::new(50);
    let verifier = AnsVerifier::builder()
        .dns_resolver(dns)
        .tlog_client(tlog)
        .scitt_config(ScittConfig::new().with_tier_policy(ScittTierPolicy::ScittWithBadgeFallback))
        .scitt_key_store(store)
        .with_scitt_verification_cache(custom_cache)
        .build()
        .await
        .expect("build should succeed");

    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
}

/// S10.7: mTLS cached verification — same token verified for client identity.
///
/// Tests that the verification cache works correctly for the client
/// (mTLS) path in addition to the server path.
#[tokio::test]
async fn test_s10_7_mtls_cached_verification() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_identity_token(&signing_key, IDENTITY_FP);

    let verifier = make_cached_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = mtls_cert(HOST, "v1.0.0", IDENTITY_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    // First call: full verification
    let outcome1 = verifier.verify_client_with_scitt(&cert, &headers).await;
    assert!(outcome1.is_success());
    assert!(matches!(
        outcome1,
        VerificationOutcome::ScittVerified { .. }
    ));

    // Second call: cache hit
    let outcome2 = verifier.verify_client_with_scitt(&cert, &headers).await;
    assert!(outcome2.is_success());
    assert!(matches!(
        outcome2,
        VerificationOutcome::ScittVerified { .. }
    ));
}

/// S10.8: Terminal status is not cached — REVOKED always rejects.
///
/// Ensures that terminal-status errors (REVOKED, EXPIRED) from the token
/// are never stored in the cache. Each call should independently reject.
#[tokio::test]
async fn test_s10_8_terminal_status_not_cached() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token_with_status(&signing_key, SERVER_FP, "REVOKED");

    let verifier = make_cached_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    // Both calls should reject — REVOKED must never be cached
    for i in 0..2 {
        let outcome = verifier
            .verify_server_with_scitt(HOST, &cert, &headers)
            .await;
        assert!(
            !outcome.is_success(),
            "Call {i}: REVOKED should always reject"
        );
        assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
    }
}

/// S10.9: BadgeWithScittEnhancement policy caches ScittVerified outcomes.
///
/// Tests that the cache works correctly with the badge-first policy.
#[tokio::test]
async fn test_s10_9_badge_enhancement_cached() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token(&signing_key, SERVER_FP);

    let verifier = make_cached_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::BadgeWithScittEnhancement,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers = ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap();

    // First call: badge then SCITT enhancement
    let outcome1 = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome1.is_success());
    assert!(matches!(
        outcome1,
        VerificationOutcome::ScittVerified { .. }
    ));

    // Second call: SCITT part hits cache
    let outcome2 = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(outcome2.is_success());
    assert!(matches!(
        outcome2,
        VerificationOutcome::ScittVerified { .. }
    ));
}

/// S10.10: Many concurrent verifications of the same token.
///
/// Stresses the cache with concurrent calls to verify the same token,
/// ensuring no panics, data races, or inconsistent results.
#[tokio::test]
async fn test_s10_10_concurrent_cached_verifications() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token(&signing_key, SERVER_FP);

    let verifier = Arc::new(
        make_cached_scitt_verifier(
            HOST,
            SERVER_FP,
            IDENTITY_FP,
            store,
            ScittTierPolicy::ScittWithBadgeFallback,
        )
        .await,
    );
    let cert = Arc::new(server_cert(HOST, SERVER_FP));
    let headers = Arc::new(ScittHeaders::from_base64(None, Some(&encode_b64(&token))).unwrap());

    // Spawn 20 concurrent verifications
    let mut handles = Vec::new();
    for _ in 0..20 {
        let v = verifier.clone();
        let c = cert.clone();
        let h = headers.clone();
        handles.push(tokio::spawn(async move {
            let outcome = v.verify_server_with_scitt(HOST, &c, &h).await;
            assert!(outcome.is_success());
            assert!(matches!(outcome, VerificationOutcome::ScittVerified { .. }));
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

// =========================================================================
// Wave 1 regression tests — SCITT review findings
// =========================================================================

/// RequireScitt + invalid receipt → hard reject (not tier degradation).
///
/// Regression test for finding #2: receipt verification failure was silently
/// degraded to StatusTokenVerified tier instead of rejecting.
#[tokio::test]
async fn test_require_scitt_bad_receipt_rejects() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token(&signing_key, SERVER_FP);
    let garbage_receipt = BASE64_STANDARD.encode(b"not-a-cose-structure");

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::RequireScitt,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers =
        ScittHeaders::from_base64(Some(&garbage_receipt), Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    // Under RequireScitt, a present-but-invalid receipt must hard reject
    assert!(!outcome.is_success());
    assert!(matches!(outcome, VerificationOutcome::ScittError(_)));
}

/// ScittWithBadgeFallback + invalid receipt → still degrades tier (existing behavior preserved).
///
/// Companion to the RequireScitt test above — ensures the fix only changes
/// behavior for RequireScitt, not for lenient policies.
#[tokio::test]
async fn test_fallback_policy_bad_receipt_degrades_tier() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token(&signing_key, SERVER_FP);
    let garbage_receipt = BASE64_STANDARD.encode(b"not-a-cose-structure");

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers =
        ScittHeaders::from_base64(Some(&garbage_receipt), Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    // Under lenient policy, bad receipt degrades tier but still succeeds
    assert!(outcome.is_success());
    match outcome {
        VerificationOutcome::ScittVerified { tier, .. } => {
            assert_eq!(tier, VerificationTier::StatusTokenVerified);
        }
        other => panic!("Expected ScittVerified with degraded tier, got: {other:?}"),
    }
}

/// Builder rejects scitt_config without key store.
///
/// Regression test for finding #6: scitt_config without scitt_key_store
/// was silently accepted and fell back to badge at call time.
#[tokio::test]
async fn test_builder_rejects_config_without_key_store() {
    let result = AnsVerifier::builder()
        .scitt_config(ScittConfig::new())
        .build()
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("key store"),
        "Error should mention key store: {err}"
    );
}

// =========================================================================
// S-Full: FullScitt tier (token + receipt both valid)
// =========================================================================

/// Valid status token + valid receipt → ScittVerified with FullScitt tier.
///
/// This is the highest verification tier: COSE signature + Merkle inclusion proof.
/// The receipt is built with tree_size=1, leaf_index=0 (trivial single-leaf tree).
#[tokio::test]
async fn test_full_scitt_tier_with_token_and_receipt() {
    let (signing_key, store) = make_key_and_store(1);
    let store = Arc::new(store);
    let token = make_server_token(&signing_key, SERVER_FP);

    // Build a receipt: the payload can be any bytes — the receipt just proves
    // inclusion in the TL's Merkle tree. Use a simple event payload.
    let event_payload = b"test-event-payload";
    let receipt = build_receipt(&signing_key, event_payload);

    let verifier = make_scitt_verifier(
        HOST,
        SERVER_FP,
        IDENTITY_FP,
        store,
        ScittTierPolicy::ScittWithBadgeFallback,
    )
    .await;
    let cert = server_cert(HOST, SERVER_FP);
    let headers =
        ScittHeaders::from_base64(Some(&encode_b64(&receipt)), Some(&encode_b64(&token))).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;
    assert!(
        outcome.is_success(),
        "FullScitt should succeed: {outcome:?}"
    );
    match outcome {
        VerificationOutcome::ScittVerified { tier, .. } => {
            assert_eq!(
                tier,
                VerificationTier::FullScitt,
                "Expected FullScitt tier when both token and receipt are valid"
            );
        }
        other => panic!("Expected ScittVerified with FullScitt tier, got: {other:?}"),
    }
}
