//! Tests for the `DPoP` (`pop`) module.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use ans_types::CertFingerprint;
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner as _};
use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, SanType};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::*;
use crate::scitt::{ScittHeaders, ScittKeyStore, compute_sig_structure_digest};

const ANS_NAME: &str = "ans://v1.0.0.caller.example.com";
const METHOD: &str = "POST";
const URL: &str = "https://payments.example.com/api/task";
const NOW: i64 = 1_787_529_605;

fn make_tl_key(seed: u8) -> (SigningKey, ScittKeyStore) {
    let signing_key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let verifying_key = signing_key.verifying_key();
    let spki_doc = verifying_key.to_public_key_der().unwrap();
    let spki_der = spki_doc.as_bytes();
    let digest = Sha256::digest(spki_der);
    let kid = [digest[0], digest[1], digest[2], digest[3]];
    let key_string = format!(
        "tl.example.com+{}+{}",
        hex::encode(kid),
        BASE64_STANDARD.encode(spki_der)
    );
    let store = ScittKeyStore::from_c2sp_keys(&[key_string]).unwrap();
    (signing_key, store)
}

fn identity_material(seed: u8, ans_name: &str) -> (SigningKey, Vec<u8>, CertFingerprint) {
    identity_material_with_validity(seed, ans_name, None)
}

fn identity_material_with_validity(
    seed: u8,
    ans_name: &str,
    validity: Option<((i32, u8, u8), (i32, u8, u8))>,
) -> (SigningKey, Vec<u8>, CertFingerprint) {
    let signing_key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let pkcs8 = signing_key.to_pkcs8_der().unwrap();
    let key_pair = KeyPair::try_from(pkcs8.as_bytes()).unwrap();
    let host = ans_types::AnsName::parse(ans_name)
        .unwrap()
        .fqdn()
        .as_str()
        .to_string();
    let mut params = CertificateParams::default();
    if let Some((nb, na)) = validity {
        params.not_before = rcgen::date_time_ymd(nb.0, nb.1, nb.2);
        params.not_after = rcgen::date_time_ymd(na.0, na.1, na.2);
    }
    params
        .distinguished_name
        .push(DnType::CommonName, host.clone());
    params
        .subject_alt_names
        .push(SanType::DnsName(host.try_into().unwrap()));
    params
        .subject_alt_names
        .push(SanType::URI(ans_name.try_into().unwrap()));
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.self_signed(&key_pair).unwrap();
    let der = cert.der().to_vec();
    let fp = CertFingerprint::from_der(&der);
    (signing_key, der, fp)
}

fn build_protected_bytes(signing_key: &SigningKey, vds: bool) -> Vec<u8> {
    let spki_doc = signing_key.verifying_key().to_public_key_der().unwrap();
    let digest = Sha256::digest(spki_doc.as_bytes());
    let kid = vec![digest[0], digest[1], digest[2], digest[3]];
    let mut pairs = vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer((-7_i64).into()),
        ),
        (
            ciborium::Value::Integer(4.into()),
            ciborium::Value::Bytes(kid),
        ),
    ];
    if vds {
        pairs.push((
            ciborium::Value::Integer(395.into()),
            ciborium::Value::Integer(1.into()),
        ));
    }
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(pairs), &mut buf).unwrap();
    buf
}

fn sign_cose(
    signing_key: &SigningKey,
    protected: Vec<u8>,
    unprotected: ciborium::Value,
    payload: &[u8],
) -> Vec<u8> {
    let digest = compute_sig_structure_digest(&protected, payload).unwrap();
    let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
    let array = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(protected),
        unprotected,
        ciborium::Value::Bytes(payload.to_vec()),
        ciborium::Value::Bytes(sig.to_bytes().to_vec()),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&array, &mut buf).unwrap();
    buf
}

fn add_signed_issuer(tl_key: &SigningKey, artifact: &[u8], issuer: &str) -> Vec<u8> {
    let ciborium::Value::Array(parts) = ciborium::de::from_reader(artifact).unwrap() else {
        panic!("fixture must be COSE_Sign1");
    };
    let ciborium::Value::Map(mut protected) =
        ciborium::de::from_reader(parts[0].as_bytes().unwrap().as_slice()).unwrap()
    else {
        panic!("fixture protected headers must be a map");
    };
    protected.push((
        ciborium::Value::Integer(15.into()),
        ciborium::Value::Map(vec![(
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text(issuer.into()),
        )]),
    ));
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(protected), &mut encoded).unwrap();
    sign_cose(
        tl_key,
        encoded,
        parts[1].clone(),
        parts[2].as_bytes().unwrap(),
    )
}

fn make_status_token(
    tl_key: &SigningKey,
    agent_id: Uuid,
    ans_name: &str,
    identity_fp: &CertFingerprint,
) -> Vec<u8> {
    let fp_bytes = identity_fp.as_bytes().to_vec();
    let cert_entry = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Bytes(fp_bytes),
        ),
        (
            ciborium::Value::Integer(2.into()),
            ciborium::Value::Text("X509-OV-CLIENT".to_string()),
        ),
    ]);
    make_status_token_with_identity_entry(tl_key, agent_id, ans_name, Some(cert_entry))
}

/// Status token for an agent registered without Identity Certificates:
/// `validIdentityCerts` (key 6) is absent entirely, not present-but-empty.
fn make_status_token_without_identity_certs(
    tl_key: &SigningKey,
    agent_id: Uuid,
    ans_name: &str,
) -> Vec<u8> {
    make_status_token_with_identity_entry(tl_key, agent_id, ans_name, None)
}

fn make_status_token_with_identity_entry(
    tl_key: &SigningKey,
    agent_id: Uuid,
    ans_name: &str,
    identity_entry: Option<ciborium::Value>,
) -> Vec<u8> {
    let mut pairs = vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text(agent_id.to_string()),
        ),
        (
            ciborium::Value::Integer(2.into()),
            ciborium::Value::Text("ACTIVE".to_string()),
        ),
        (
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Integer(NOW.into()),
        ),
        (
            ciborium::Value::Integer(4.into()),
            ciborium::Value::Integer((NOW + 3600).into()),
        ),
        (
            ciborium::Value::Integer(5.into()),
            ciborium::Value::Text(ans_name.to_string()),
        ),
    ];
    if let Some(entry) = identity_entry {
        pairs.push((
            ciborium::Value::Integer(6.into()),
            ciborium::Value::Array(vec![entry]),
        ));
    }
    pairs.push((
        ciborium::Value::Integer(7.into()),
        ciborium::Value::Array(vec![]),
    ));
    pairs.push((
        ciborium::Value::Integer(8.into()),
        ciborium::Value::Map(vec![]),
    ));
    let payload = ciborium::Value::Map(pairs);
    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(&payload, &mut payload_bytes).unwrap();
    sign_cose(
        tl_key,
        build_protected_bytes(tl_key, false),
        ciborium::Value::Map(vec![]),
        &payload_bytes,
    )
}

fn make_receipt(tl_key: &SigningKey, agent_id: Uuid, ans_name: &str) -> Vec<u8> {
    let leaf = serde_json::json!({
        "payload": {
            "logId": "550e8400-e29b-41d4-a716-446655440000",
            "producer": {
                "event": {
                    "ansId": agent_id.to_string(),
                    "ansName": ans_name,
                    "eventType": "AGENT_REGISTERED",
                    "agent": { "host": "caller.example.com", "name": "caller", "version": "1.0.0" }
                },
                "keyId": "id-B",
                "signature": "eyJhbGciOiJFUzI1NiJ9"
            }
        },
        "schemaVersion": "V2",
        "signature": "eyJhbGciOiJFUzI1NiJ9",
        "status": "SEALED"
    });
    let event_bytes = serde_json::to_vec(&leaf).unwrap();
    let vdp = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer((-1_i64).into()),
            ciborium::Value::Integer(1.into()),
        ),
        (
            ciborium::Value::Integer((-2_i64).into()),
            ciborium::Value::Integer(0.into()),
        ),
        (
            ciborium::Value::Integer((-3_i64).into()),
            ciborium::Value::Array(vec![]),
        ),
    ]);
    let unprotected = ciborium::Value::Map(vec![(ciborium::Value::Integer(396.into()), vdp)]);
    sign_cose(
        tl_key,
        build_protected_bytes(tl_key, true),
        unprotected,
        &event_bytes,
    )
}

fn frozen_now() -> i64 {
    NOW
}

fn signer_at_now(key: SigningKey, cert: Vec<u8>) -> Signer {
    Signer::new(key, cert).unwrap().with_clock(frozen_now)
}

fn replay() -> MemoryReplayCache {
    MemoryReplayCache::new(16).with_clock(frozen_now)
}

fn headers(receipt: &[u8], token: &[u8]) -> ScittHeaders {
    ScittHeaders::new(Some(receipt.to_vec()), Some(token.to_vec()))
}

fn rewrite_payload(
    proof: &str,
    key: &SigningKey,
    edit: impl FnOnce(&mut serde_json::Value),
) -> String {
    let (header, payload, _) = super::jws::split_compact_jws(proof).unwrap();
    let mut payload: serde_json::Value =
        serde_json::from_slice(&super::jws::b64url_decode(payload).unwrap()).unwrap();
    edit(&mut payload);
    let payload = super::jws::b64url_encode(&serde_json::to_vec(&payload).unwrap());
    let input = format!("{header}.{payload}");
    let signature = super::jws::sign_es256(key, input.as_bytes()).unwrap();
    format!("{input}.{signature}")
}

#[test]
fn normalize_htu_preserves_path_octets() {
    for path in [
        "/a/../task",
        "/a/./task",
        "/%2e%2e/task",
        "/%2fTask",
        "//task",
    ] {
        let url = format!("https://Payments.Example.com:443{path}?q=1#fragment");
        assert_eq!(
            normalize_htu(&url).unwrap(),
            format!("https://payments.example.com{path}")
        );
    }
}

#[tokio::test]
async fn content_digest_is_required_even_for_empty_requests() {
    let (key, cert, _) = identity_material(33, ANS_NAME);
    let signer = signer_at_now(key.clone(), cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let missing = rewrite_payload(&proof, &key, |payload| {
        payload
            .as_object_mut()
            .unwrap()
            .remove("ans_content_digest");
    });
    let err = verify_proof(
        &missing,
        METHOD,
        URL,
        &replay(),
        VerifyProofOptions {
            now: Some(NOW),
            ..VerifyProofOptions::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::MalformedProof);
}

#[tokio::test]
async fn null_profile_revision_is_malformed() {
    let (key, cert, _) = identity_material(34, ANS_NAME);
    let signer = signer_at_now(key.clone(), cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let malformed = rewrite_payload(&proof, &key, |payload| {
        payload["ans_profile"] = serde_json::Value::Null;
    });
    let err = verify_proof(
        &malformed,
        METHOD,
        URL,
        &replay(),
        VerifyProofOptions {
            now: Some(NOW),
            ..VerifyProofOptions::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::MalformedProof);
}

#[tokio::test]
async fn optional_receipt_is_still_verified_when_present() {
    let (key, cert, fp) = identity_material(35, ANS_NAME);
    let signer = signer_at_now(key, cert);
    let (tl_key, store) = make_tl_key(14);
    let token = make_status_token(&tl_key, Uuid::nil(), ANS_NAME, &fp);
    let wrong_receipt = make_receipt(&tl_key, Uuid::nil(), "ans://v2.0.0.caller.example.com");
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let replay = replay();
    let opts = VerifyCallerOptions {
        now: Some(NOW),
        require_receipt: false,
        ..VerifyCallerOptions::default()
    };

    let err = verify_caller(
        &proof,
        &headers(&wrong_receipt, &token),
        METHOD,
        URL,
        &store,
        &replay,
        opts.clone(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::BindingFailed);

    // Rejection must not consume the proof's replay slot. The reduced mode
    // permits an absent receipt, but cannot ignore adverse supplied evidence.
    verify_caller(
        &proof,
        &ScittHeaders::new(None, Some(token)),
        METHOD,
        URL,
        &store,
        &replay,
        opts,
    )
    .await
    .unwrap();
}

#[test]
fn normalize_htu_drops_default_port_and_query() {
    assert_eq!(
        normalize_htu("https://Payments.Example.com:443/api/task?x=1#frag").unwrap(),
        "https://payments.example.com/api/task"
    );
    assert_eq!(
        normalize_htu("https://payments.example.com").unwrap(),
        "https://payments.example.com/"
    );
    assert_eq!(
        normalize_htu("http://h.example:80/p").unwrap(),
        "http://h.example/p"
    );
    assert_eq!(
        normalize_htu("https://h.example:8443/p").unwrap(),
        "https://h.example:8443/p"
    );
}

#[test]
fn access_token_from_authorization_dpop_scheme() {
    assert_eq!(access_token_from_authorization("DPoP abc"), Some("abc"));
    assert_eq!(access_token_from_authorization("dpop  tok  "), Some("tok"));
    assert!(access_token_from_authorization("Bearer abc").is_none());
    assert!(access_token_from_authorization("DPoP").is_none());
}

#[test]
fn reject_duplicate_header_counts() {
    assert!(reject_duplicate_header("DPoP", 1).is_ok());
    assert_eq!(
        reject_duplicate_header("DPoP", 2).unwrap_err().kind,
        PopErrorKind::MalformedProof
    );
}

#[tokio::test]
async fn sign_and_verify_proof_roundtrip() {
    let (key, cert, _) = identity_material(7, ANS_NAME);
    let signer = signer_at_now(key, cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let cache = replay();
    let result = verify_proof(
        &proof,
        METHOD,
        URL,
        &cache,
        VerifyProofOptions {
            now: Some(NOW),
            ..VerifyProofOptions::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(result.htu, "https://payments.example.com/api/task");
    assert_eq!(result.issued_at, NOW);
}

#[tokio::test]
async fn replay_is_rejected() {
    let (key, cert, _) = identity_material(8, ANS_NAME);
    let signer = signer_at_now(key, cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let cache = replay();
    let opts = VerifyProofOptions {
        now: Some(NOW),
        ..VerifyProofOptions::default()
    };
    verify_proof(&proof, METHOD, URL, &cache, opts.clone())
        .await
        .unwrap();
    let err = verify_proof(&proof, METHOD, URL, &cache, opts)
        .await
        .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::Replay);
}

#[tokio::test]
async fn wrong_method_or_url_rejected() {
    let (key, cert, _) = identity_material(9, ANS_NAME);
    let signer = signer_at_now(key, cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let cache = replay();
    let opts = VerifyProofOptions {
        now: Some(NOW),
        ..VerifyProofOptions::default()
    };
    let err = verify_proof(&proof, "GET", URL, &cache, opts.clone())
        .await
        .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::HttpBindingMismatch);
    let err = verify_proof(
        &proof,
        METHOD,
        "https://other.example.com/api/task",
        &cache,
        opts,
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::HttpBindingMismatch);
}

#[tokio::test]
async fn extra_header_field_rejected() {
    let (key, cert, _) = identity_material(10, ANS_NAME);
    let signer = signer_at_now(key, cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let (h, p, s) = {
        let mut it = proof.split('.');
        (it.next().unwrap(), it.next().unwrap(), it.next().unwrap())
    };
    let mut header: serde_json::Value =
        serde_json::from_slice(&base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(h).unwrap())
            .unwrap();
    header["kid"] = serde_json::json!("smuggled");
    let h2 = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let tampered = format!("{h2}.{p}.{s}");
    let err = verify_proof(
        &tampered,
        METHOD,
        URL,
        &replay(),
        VerifyProofOptions {
            now: Some(NOW),
            ..VerifyProofOptions::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::MalformedProof);
}

#[tokio::test]
async fn jose_conformance_rejects_certificate_chains_and_jwk_extensions() {
    let (key, cert, _) = identity_material(39, ANS_NAME);
    let signer = signer_at_now(key.clone(), cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let (header, payload, _) = super::jws::split_compact_jws(&proof).unwrap();
    let header: serde_json::Value =
        serde_json::from_slice(&super::jws::b64url_decode(header).unwrap()).unwrap();

    for parameter in ["x5c", "alg", "use", "kid", "d"] {
        let mut modified = header.clone();
        let expected = if parameter == "x5c" {
            let leaf = modified["x5c"][0].clone();
            modified["x5c"].as_array_mut().unwrap().push(leaf);
            PopErrorKind::CertInvalid
        } else {
            modified["jwk"][parameter] = serde_json::json!("unexpected");
            PopErrorKind::MalformedProof
        };
        let encoded = super::jws::b64url_encode(&serde_json::to_vec(&modified).unwrap());
        let input = format!("{encoded}.{payload}");
        let signature = super::jws::sign_es256(&key, input.as_bytes()).unwrap();
        let proof = format!("{input}.{signature}");
        let err = verify_proof(
            &proof,
            METHOD,
            URL,
            &replay(),
            VerifyProofOptions {
                now: Some(NOW),
                ..VerifyProofOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind, expected, "accepted nonconformant {parameter}");
    }
}

#[tokio::test]
async fn ath_both_directions() {
    let (key, cert, _) = identity_material(11, ANS_NAME);
    let signer = signer_at_now(key, cert);
    let token = "access-token-bytes";
    let with_ath = signer.sign(METHOD, URL, Some(token)).unwrap();
    let without = signer.sign(METHOD, URL, None).unwrap();
    let opts_tok = VerifyProofOptions {
        access_token: Some(token.to_string()),
        now: Some(NOW),
        ..VerifyProofOptions::default()
    };
    let opts_none = VerifyProofOptions {
        now: Some(NOW),
        ..VerifyProofOptions::default()
    };
    verify_proof(&with_ath, METHOD, URL, &replay(), opts_tok.clone())
        .await
        .unwrap();
    assert_eq!(
        verify_proof(&with_ath, METHOD, URL, &replay(), opts_none.clone())
            .await
            .unwrap_err()
            .kind,
        PopErrorKind::TokenBindingMismatch
    );
    assert_eq!(
        verify_proof(&without, METHOD, URL, &replay(), opts_tok)
            .await
            .unwrap_err()
            .kind,
        PopErrorKind::TokenBindingMismatch
    );
}

#[tokio::test]
async fn stale_proof_rejected() {
    let (key, cert, _) = identity_material(12, ANS_NAME);
    let signer = signer_at_now(key, cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let err = verify_proof(
        &proof,
        METHOD,
        URL,
        &replay(),
        VerifyProofOptions {
            now: Some(NOW + 121),
            skew: Some(Duration::from_secs(120)),
            ..VerifyProofOptions::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::ProofStale);
}

#[tokio::test]
async fn cert_outside_validity_window_rejected() {
    // NOW is in 2026 — a 2020–2021 certificate is expired and a 2030–2031
    // certificate is not yet valid (ANS-6 §7.4 step 3 / §7.5).
    for validity in [((2020, 1, 1), (2021, 1, 1)), ((2030, 1, 1), (2031, 1, 1))] {
        let (key, cert, _) = identity_material_with_validity(26, ANS_NAME, Some(validity));
        let signer = signer_at_now(key, cert);
        let proof = signer.sign(METHOD, URL, None).unwrap();
        let err = verify_proof(
            &proof,
            METHOD,
            URL,
            &replay(),
            VerifyProofOptions {
                now: Some(NOW),
                ..VerifyProofOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind, PopErrorKind::CertInvalid);
    }
}

#[tokio::test]
async fn cached_cert_still_enforces_validity() {
    // ~30 days after NOW — past the cert's 2026-09-01 notAfter.
    const LATER: i64 = NOW + 2_592_000;
    fn frozen_much_later() -> i64 {
        LATER
    }

    let (id_key, cert, fp) =
        identity_material_with_validity(27, ANS_NAME, Some(((2020, 1, 1), (2026, 9, 1))));
    let (tl_key, store) = make_tl_key(12);
    let agent_id = Uuid::nil();
    let token = make_status_token(&tl_key, agent_id, ANS_NAME, &fp);
    let receipt = make_receipt(&tl_key, agent_id, ANS_NAME);
    let cache = VerifiedArtifactCache::new(8);
    let signer = Signer::new(id_key, cert).unwrap();

    let proof = signer
        .clone()
        .with_clock(frozen_now)
        .sign(METHOD, URL, None)
        .unwrap();
    verify_caller(
        &proof,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &store,
        &replay(),
        VerifyCallerOptions {
            now: Some(NOW),
            ..VerifyCallerOptions::default()
        }
        .with_artifact_cache(cache.clone()),
    )
    .await
    .unwrap();

    // The parsed cert is cached now; a request after notAfter must still
    // reject — validity is time-dependent and never cached.
    let proof2 = signer
        .with_clock(frozen_much_later)
        .sign(METHOD, URL, None)
        .unwrap();
    let err = verify_caller(
        &proof2,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &store,
        &MemoryReplayCache::new(16).with_clock(frozen_much_later),
        VerifyCallerOptions {
            now: Some(LATER),
            ..VerifyCallerOptions::default()
        }
        .with_artifact_cache(cache),
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::CertInvalid);
}

#[tokio::test]
async fn verify_caller_binds_three_proofs() {
    let (id_key, cert, fp) = identity_material(13, ANS_NAME);
    let (tl_key, store) = make_tl_key(1);
    let agent_id = Uuid::parse_str("7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07").unwrap();
    let token = make_status_token(&tl_key, agent_id, ANS_NAME, &fp);
    let receipt = make_receipt(&tl_key, agent_id, ANS_NAME);
    let signer = signer_at_now(id_key, cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let id = verify_caller(
        &proof,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &store,
        &replay(),
        VerifyCallerOptions {
            now: Some(NOW),
            ..VerifyCallerOptions::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(id.ans_name.to_string(), ANS_NAME);
    assert_eq!(id.agent_id, agent_id);
    assert_eq!(id.fingerprint, fp);
}

#[tokio::test]
async fn missing_status_token_is_hard_reject() {
    let (id_key, cert, _) = identity_material(14, ANS_NAME);
    let (tl_key, store) = make_tl_key(2);
    let signer = signer_at_now(id_key, cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let err = verify_caller(
        &proof,
        &ScittHeaders::new(Some(b"unused".to_vec()), None),
        METHOD,
        URL,
        &store,
        &replay(),
        VerifyCallerOptions {
            now: Some(NOW),
            require_receipt: false,
            ..VerifyCallerOptions::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::MissingHeaders);
    let _ = tl_key;
}

#[tokio::test]
async fn fingerprint_mismatch_rejected() {
    let (id_key, cert, _) = identity_material(15, ANS_NAME);
    let (_other_key, _other_cert, other_fp) = identity_material(16, ANS_NAME);
    let (tl_key, store) = make_tl_key(3);
    let agent_id = Uuid::nil();
    let token = make_status_token(&tl_key, agent_id, ANS_NAME, &other_fp);
    let receipt = make_receipt(&tl_key, agent_id, ANS_NAME);
    let signer = signer_at_now(id_key, cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let err = verify_caller(
        &proof,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &store,
        &replay(),
        VerifyCallerOptions {
            now: Some(NOW),
            ..VerifyCallerOptions::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::BindingFailed);
}

#[tokio::test]
async fn receipt_for_different_agent_rejected() {
    let (id_key, cert, fp) = identity_material(17, ANS_NAME);
    let (tl_key, store) = make_tl_key(4);
    let agent_id = Uuid::nil();
    let other_id = Uuid::parse_str("019be7f3-5720-77c9-9672-adae3394502f").unwrap();
    let token = make_status_token(&tl_key, agent_id, ANS_NAME, &fp);
    let receipt = make_receipt(&tl_key, other_id, ANS_NAME);
    let signer = signer_at_now(id_key, cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let err = verify_caller(
        &proof,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &store,
        &replay(),
        VerifyCallerOptions {
            now: Some(NOW),
            ..VerifyCallerOptions::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::BindingFailed);
}

#[tokio::test]
async fn untrusted_proof_does_not_consume_replay_slot() {
    let (id_key, cert, _) = identity_material(18, ANS_NAME);
    let (tl_key, store) = make_tl_key(5);
    let signer = signer_at_now(id_key, cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let cache = Arc::new(MemoryReplayCache::new(1).with_clock(frozen_now));
    let err = verify_caller(
        &proof,
        &ScittHeaders::new(None, None),
        METHOD,
        URL,
        &store,
        cache.as_ref(),
        VerifyCallerOptions {
            now: Some(NOW),
            require_receipt: false,
            ..VerifyCallerOptions::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::MissingHeaders);
    assert!(cache.is_empty());
    let _ = tl_key;
}

#[tokio::test]
async fn replay_cache_fails_closed_at_capacity() {
    let cache = MemoryReplayCache::new(1).with_clock(frozen_now);
    assert!(!cache.check_and_store("aaa", NOW + 120).await.unwrap());
    let err = cache.check_and_store("bbb", NOW + 120).await.unwrap_err();
    assert_eq!(err.kind, PopErrorKind::ReplayCacheFull);
}

#[tokio::test]
async fn replay_cache_rejects_expired_reservations() {
    let cache = replay();
    // A slow body read or shared-store round trip can outlive the proof's
    // retention window. Storing an already-expired key would admit reuse.
    for expiry in [NOW - 1, NOW] {
        let err = cache.check_and_store("expired", expiry).await.unwrap_err();
        assert_eq!(err.kind, PopErrorKind::ProofStale);
    }
    assert!(cache.is_empty());
    assert!(!cache.check_and_store("fresh", NOW + 120).await.unwrap());
    assert!(cache.check_and_store("fresh", NOW + 120).await.unwrap());
}

#[tokio::test]
async fn attach_identity_binds_dpop_authorization() {
    let (key, cert, _) = identity_material(19, ANS_NAME);
    let signer = signer_at_now(key, cert);
    let proof = attach_identity(&signer, METHOD, URL, Some("DPoP tok")).unwrap();
    verify_proof(
        &proof,
        METHOD,
        URL,
        &replay(),
        VerifyProofOptions {
            access_token: Some("tok".to_string()),
            now: Some(NOW),
            ..VerifyProofOptions::default()
        },
    )
    .await
    .unwrap();
}

#[test]
fn signer_rejects_mismatched_cert() {
    let (key, _, _) = identity_material(20, ANS_NAME);
    let (_, cert, _) = identity_material(21, ANS_NAME);
    assert_eq!(
        Signer::new(key, cert).unwrap_err().kind,
        PopErrorKind::CertInvalid
    );
}

#[tokio::test]
async fn trusted_authority_preflight_accepts_and_rejects() {
    let (id_key, cert, fp) = identity_material(22, ANS_NAME);
    let (tl_key, store) = make_tl_key(6);
    let agent_id = Uuid::nil();
    let token = make_status_token(&tl_key, agent_id, ANS_NAME, &fp);
    let receipt = make_receipt(&tl_key, agent_id, ANS_NAME);
    let signer = signer_at_now(id_key, cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();

    // Case- and default-port-insensitive match passes the full pipeline.
    let ok = VerifyCallerOptions {
        now: Some(NOW),
        ..VerifyCallerOptions::default()
    }
    .with_trusted_authority("Payments.Example.com:443");
    verify_caller(
        &proof,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &store,
        &replay(),
        ok,
    )
    .await
    .unwrap();

    // A foreign authority rejects before any proof work — even an empty
    // proof reports the authority failure, not the missing proof.
    let foreign = VerifyCallerOptions {
        now: Some(NOW),
        ..VerifyCallerOptions::default()
    }
    .with_trusted_authority("api.other.example");
    let err = verify_caller(
        "",
        &headers(&receipt, &token),
        METHOD,
        URL,
        &store,
        &replay(),
        foreign,
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::UntrustedAuthority);
}

#[tokio::test]
async fn artifact_cache_is_scoped_to_trusted_keys() {
    let (id_key, cert, fp) = identity_material(23, ANS_NAME);
    let (tl_key, store) = make_tl_key(7);
    let agent_id = Uuid::nil();
    let token = make_status_token(&tl_key, agent_id, ANS_NAME, &fp);
    let receipt = make_receipt(&tl_key, agent_id, ANS_NAME);
    let signer = signer_at_now(id_key, cert);
    let cache = VerifiedArtifactCache::new(8);

    let opts = |cache: &VerifiedArtifactCache| {
        VerifyCallerOptions {
            now: Some(NOW),
            ..VerifyCallerOptions::default()
        }
        .with_artifact_cache(cache.clone())
    };

    // Warm the cache against the store that trusts the TL key.
    let proof = signer.sign(METHOD, URL, None).unwrap();
    verify_caller(
        &proof,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &store,
        &replay(),
        opts(&cache),
    )
    .await
    .unwrap();

    // Identical bytes still work under an equivalent cloned trust store.
    let proof2 = signer.sign(METHOD, URL, None).unwrap();
    verify_caller(
        &proof2,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &store.clone(),
        &replay(),
        opts(&cache),
    )
    .await
    .unwrap();

    // A different trust store must not inherit the previous verification.
    let (_, wrong_store) = make_tl_key(8);
    let proof3 = signer.sign(METHOD, URL, None).unwrap();
    let error = verify_caller(
        &proof3,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &wrong_store,
        &replay(),
        opts(&cache),
    )
    .await
    .unwrap_err();
    assert!(error.is_unknown_key_id());
}

#[tokio::test]
async fn artifact_cache_scope_includes_issuer_name_for_tokens_and_receipts() {
    use crate::scitt::ScittError;
    use std::error::Error as _;

    let (id_key, cert, fp) = identity_material(23, ANS_NAME);
    let signer = signer_at_now(id_key, cert);
    let (tl_key, trusted) = make_tl_key(7);
    let spki = tl_key.verifying_key().to_public_key_der().unwrap();
    let renamed = ScittKeyStore::from_c2sp_keys(&[format!(
        "different-tl.example.com+{}+{}",
        hex::encode(&Sha256::digest(spki.as_bytes())[..4]),
        BASE64_STANDARD.encode(spki.as_bytes()),
    )])
    .unwrap();

    for token_issuer in [true, false] {
        let cache = VerifiedArtifactCache::new(8);
        let mut token = make_status_token(&tl_key, Uuid::nil(), ANS_NAME, &fp);
        let mut receipt = make_receipt(&tl_key, Uuid::nil(), ANS_NAME);
        if token_issuer {
            token = add_signed_issuer(&tl_key, &token, "tl.example.com");
        } else {
            receipt = add_signed_issuer(&tl_key, &receipt, "tl.example.com");
        }
        let options = || VerifyCallerOptions {
            now: Some(NOW),
            artifact_cache: Some(cache.clone()),
            ..Default::default()
        };
        verify_caller(
            &signer.sign(METHOD, URL, None).unwrap(),
            &headers(&receipt, &token),
            METHOD,
            URL,
            &trusted,
            &replay(),
            options(),
        )
        .await
        .unwrap();
        let replay_cache = replay();
        let error = verify_caller(
            &signer.sign(METHOD, URL, None).unwrap(),
            &headers(&receipt, &token),
            METHOD,
            URL,
            &renamed,
            &replay_cache,
            options(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.kind,
            if token_issuer {
                PopErrorKind::StatusInvalid
            } else {
                PopErrorKind::ReceiptInvalid
            }
        );
        assert!(matches!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<ScittError>()),
            Some(ScittError::IssuerMismatch { .. })
        ));
        assert!(replay_cache.is_empty());
    }
}

#[tokio::test]
async fn unavailable_shared_replay_backend_rejects_authenticated_callers() {
    struct Unavailable;
    #[async_trait::async_trait]
    impl ReplayCache for Unavailable {
        async fn check_and_store(&self, _key: &str, _exp: i64) -> Result<bool, PopError> {
            Err(PopError::with_source(
                PopErrorKind::ReplayCacheUnavailable,
                "replay backend timed out",
                std::io::Error::from(std::io::ErrorKind::TimedOut),
            ))
        }
    }
    let (key, cert, fp) = identity_material(23, ANS_NAME);
    let (tl_key, store) = make_tl_key(7);
    let token = make_status_token(&tl_key, Uuid::nil(), ANS_NAME, &fp);
    let receipt = make_receipt(&tl_key, Uuid::nil(), ANS_NAME);
    let signer = signer_at_now(key, cert);
    let error = verify_caller(
        &signer.sign(METHOD, URL, None).unwrap(),
        &headers(&receipt, &token),
        METHOD,
        URL,
        &store,
        &Unavailable,
        VerifyCallerOptions {
            now: Some(NOW),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind, PopErrorKind::ReplayCacheUnavailable);
}

#[tokio::test]
async fn artifact_cache_still_enforces_exp() {
    // Past exp (NOW + 3600) + status skew (60): the cached entry must not
    // shadow expiry; the bytes re-verify fresh and fail.
    const LATER: i64 = NOW + 3_661;
    fn frozen_later() -> i64 {
        LATER
    }

    let (id_key, cert, fp) = identity_material(24, ANS_NAME);
    let (tl_key, store) = make_tl_key(9);
    let agent_id = Uuid::nil();
    let token = make_status_token(&tl_key, agent_id, ANS_NAME, &fp);
    let receipt = make_receipt(&tl_key, agent_id, ANS_NAME);
    let cache = VerifiedArtifactCache::new(8);

    let signer = Signer::new(id_key, cert).unwrap();
    let proof = signer
        .clone()
        .with_clock(frozen_now)
        .sign(METHOD, URL, None)
        .unwrap();
    verify_caller(
        &proof,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &store,
        &replay(),
        VerifyCallerOptions {
            now: Some(NOW),
            ..VerifyCallerOptions::default()
        }
        .with_artifact_cache(cache.clone()),
    )
    .await
    .unwrap();

    let proof2 = signer
        .with_clock(frozen_later)
        .sign(METHOD, URL, None)
        .unwrap();
    let err = verify_caller(
        &proof2,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &store,
        &MemoryReplayCache::new(16).with_clock(frozen_later),
        VerifyCallerOptions {
            now: Some(LATER),
            ..VerifyCallerOptions::default()
        }
        .with_artifact_cache(cache),
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::StatusInvalid);
    assert!(!err.is_unknown_key_id());
}

#[tokio::test]
async fn unknown_key_id_is_detectable_for_retry() {
    let (id_key, cert, fp) = identity_material(25, ANS_NAME);
    let (tl_key, _) = make_tl_key(10);
    let (_, other_store) = make_tl_key(11);
    let agent_id = Uuid::nil();
    let token = make_status_token(&tl_key, agent_id, ANS_NAME, &fp);
    let receipt = make_receipt(&tl_key, agent_id, ANS_NAME);
    let signer = signer_at_now(id_key, cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();

    let err = verify_caller(
        &proof,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &other_store,
        &replay(),
        VerifyCallerOptions {
            now: Some(NOW),
            ..VerifyCallerOptions::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::StatusInvalid);
    assert!(err.is_unknown_key_id());

    let missing = verify_caller(
        "",
        &headers(&receipt, &token),
        METHOD,
        URL,
        &other_store,
        &replay(),
        VerifyCallerOptions {
            now: Some(NOW),
            ..VerifyCallerOptions::default()
        },
    )
    .await
    .unwrap_err();
    assert!(!missing.is_unknown_key_id());
}

#[test]
fn request_authority_normalizes() {
    assert_eq!(
        request_authority("https://API.Example.com:443/x?q=1").unwrap(),
        "api.example.com"
    );
    assert_eq!(
        request_authority("https://api.example.com:8443/x").unwrap(),
        "api.example.com:8443"
    );
    assert!(request_authority("/relative/path").is_err());
}

#[tokio::test]
async fn content_binding_both_directions() {
    let (key, cert, _) = identity_material(28, ANS_NAME);
    let signer = signer_at_now(key, cert);
    let body = br#"{"amount": 100}"#;
    let digest: [u8; 32] = Sha256::digest(body).into();
    let opts = |content: Option<[u8; 32]>| VerifyProofOptions {
        content_sha256: content,
        now: Some(NOW),
        ..VerifyProofOptions::default()
    };

    // Bound content, matching digest → ok.
    let bound = signer.sign_with_content(METHOD, URL, None, body).unwrap();
    verify_proof(&bound, METHOD, URL, &replay(), opts(Some(digest)))
        .await
        .unwrap();

    // Bound content, tampered body → reject.
    let tampered: [u8; 32] = Sha256::digest(br#"{"amount": 9999}"#).into();
    let err = verify_proof(&bound, METHOD, URL, &replay(), opts(Some(tampered)))
        .await
        .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::ContentBindingMismatch);

    // Claim present but request carries no content → reject.
    let bound2 = signer.sign_with_content(METHOD, URL, None, body).unwrap();
    let err = verify_proof(&bound2, METHOD, URL, &replay(), opts(None))
        .await
        .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::ContentBindingMismatch);

    // Adding content to an empty request breaks its signed empty digest.
    let empty_request = signer.sign(METHOD, URL, None).unwrap();
    let err = verify_proof(&empty_request, METHOD, URL, &replay(), opts(Some(digest)))
        .await
        .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::ContentBindingMismatch);

    // Empty content is explicitly bound, with either representation of the
    // received digest accepted by the low-level options.
    let empty = signer.sign_with_content(METHOD, URL, None, b"").unwrap();
    verify_proof(&empty, METHOD, URL, &replay(), opts(None))
        .await
        .unwrap();
    let empty_digest: [u8; 32] = Sha256::digest(b"").into();
    verify_proof(&empty, METHOD, URL, &replay(), opts(Some(empty_digest)))
        .await
        .unwrap();
}

#[test]
fn minted_proofs_carry_profile_revision() {
    let (key, cert, _) = identity_material(29, ANS_NAME);
    let signer = signer_at_now(key, cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let payload_b64 = proof.split('.').nth(1).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(
        &base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(payload_b64)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        payload["ans_profile"],
        serde_json::json!(ANS_PROFILE_REVISION)
    );
    assert_eq!(
        payload["ans_content_digest"],
        "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
    );
}

#[tokio::test]
async fn malformed_content_digests_reject_before_certificate_work() {
    let (key, cert, _) = identity_material(36, ANS_NAME);
    let signer = signer_at_now(key.clone(), cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    for value in [
        serde_json::Value::Null,
        serde_json::json!(1),
        serde_json::json!(""),
        serde_json::json!("not+a/base64url=digest"),
        serde_json::json!("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU="),
        serde_json::json!(super::jws::b64url_encode(&[0u8; 31])),
        serde_json::json!(super::jws::b64url_encode(&[0u8; 33])),
    ] {
        let malformed = rewrite_payload(&proof, &key, |payload| {
            payload["ans_content_digest"] = value.clone();
        });
        let (header, payload, signature) = super::jws::split_compact_jws(&malformed).unwrap();
        let mut header: serde_json::Value =
            serde_json::from_slice(&super::jws::b64url_decode(header).unwrap()).unwrap();
        header["x5c"] = serde_json::json!(["not-a-certificate"]);
        let header = super::jws::b64url_encode(&serde_json::to_vec(&header).unwrap());
        let malformed = format!("{header}.{payload}.{signature}");
        let err = verify_proof(
            &malformed,
            METHOD,
            URL,
            &replay(),
            VerifyProofOptions {
                now: Some(NOW),
                ..VerifyProofOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind, PopErrorKind::MalformedProof, "digest: {value}");
    }
}

#[tokio::test]
async fn absent_profile_is_revision_one_but_malformed_profiles_reject() {
    let (key, cert, _) = identity_material(37, ANS_NAME);
    let signer = signer_at_now(key.clone(), cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();
    let opts = VerifyProofOptions {
        now: Some(NOW),
        ..VerifyProofOptions::default()
    };
    let absent = rewrite_payload(&proof, &key, |payload| {
        payload.as_object_mut().unwrap().remove("ans_profile");
    });
    verify_proof(&absent, METHOD, URL, &replay(), opts.clone())
        .await
        .unwrap();
    for value in [
        serde_json::Value::Null,
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!("1"),
        serde_json::json!(true),
    ] {
        let malformed = rewrite_payload(&proof, &key, |payload| {
            payload["ans_profile"] = value.clone();
        });
        assert!(
            verify_proof(&malformed, METHOD, URL, &replay(), opts.clone())
                .await
                .is_err(),
            "accepted profile: {value}"
        );
    }
}

#[tokio::test]
async fn content_hashing_follows_identity_binding_and_precedes_replay() {
    let (key, cert, fp) = identity_material(38, ANS_NAME);
    let signer = signer_at_now(key, cert);
    let (tl_key, store) = make_tl_key(15);
    let token = make_status_token(&tl_key, Uuid::nil(), ANS_NAME, &fp);
    let receipt = make_receipt(&tl_key, Uuid::nil(), ANS_NAME);
    let body = br#"{"task":"reconcile-ledger","amount":"1000.00"}"#;
    let proof = signer.sign_with_content(METHOD, URL, None, body).unwrap();
    let opts = VerifyCallerOptions {
        now: Some(NOW),
        ..VerifyCallerOptions::default()
    };
    let replay = replay();

    let wrong_token = make_status_token(
        &tl_key,
        Uuid::nil(),
        ANS_NAME,
        &CertFingerprint::from_der(b"other"),
    );
    let hashed = std::cell::Cell::new(false);
    let err = verify_caller_with_content(
        &proof,
        &headers(&receipt, &wrong_token),
        METHOD,
        URL,
        &store,
        &replay,
        opts.clone(),
        || async {
            hashed.set(true);
            Ok(Sha256::digest(body).into())
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::BindingFailed);
    assert!(!hashed.get(), "untrusted caller bought content hashing");

    // A body read/size-limit error and a mismatch both leave the jti unused.
    for result in [
        Err(PopError::new(
            PopErrorKind::ContentBindingMismatch,
            "body too large",
        )),
        Ok(Sha256::digest(b"modified").into()),
    ] {
        let err = verify_caller_with_content(
            &proof,
            &headers(&receipt, &token),
            METHOD,
            URL,
            &store,
            &replay,
            opts.clone(),
            || async { result },
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind, PopErrorKind::ContentBindingMismatch);
    }

    let identity = verify_caller_with_content(
        &proof,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &store,
        &replay,
        opts.clone(),
        || async {
            // Transfer framing has been removed; splitting the same content
            // into different chunks does not change its digest.
            let mut hash = Sha256::new();
            for chunk in body.chunks(7) {
                hash.update(chunk);
            }
            let digest: [u8; 32] = hash.finalize().into();
            assert_eq!(
                super::jws::b64url_encode(&digest),
                "wT8MhptL9zBd-WXZkYTjY7AHo1vNNfPYZzVifJEzPJc"
            );
            Ok(digest)
        },
    )
    .await
    .unwrap();
    assert_eq!(identity.ans_name.to_string(), ANS_NAME);

    let err = verify_caller_with_content(
        &proof,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &store,
        &replay,
        opts,
        || async { Ok(Sha256::digest(body).into()) },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::Replay);
}

#[tokio::test]
async fn content_coding_remains_applied_when_hashing() {
    let plain = br#"{"task":"reconcile-ledger","amount":"1000.00"}"#;
    // gzip(plain), generated with mtime=0. These transmitted octets are the
    // bound content, even when the application subsequently decodes JSON.
    let gzip: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 171, 86, 42, 73, 44, 206, 86, 178, 82, 42, 74, 77, 206,
        207, 75, 206, 204, 73, 213, 205, 73, 77, 73, 79, 45, 82, 210, 81, 74, 204, 205, 47, 205,
        43, 1, 202, 25, 26, 24, 24, 232, 25, 24, 40, 213, 2, 0, 130, 136, 183, 214, 46, 0, 0, 0,
    ];
    let (key, cert, _) = identity_material(40, ANS_NAME);
    let proof = signer_at_now(key, cert)
        .sign_with_content(METHOD, URL, None, gzip)
        .unwrap();
    let replay = replay();
    for digest in [Sha256::digest(plain).into(), Sha256::digest(b"").into()] {
        let err = verify_proof(
            &proof,
            METHOD,
            URL,
            &replay,
            VerifyProofOptions {
                now: Some(NOW),
                content_sha256: Some(digest),
                ..VerifyProofOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind, PopErrorKind::ContentBindingMismatch);
    }
    verify_proof(
        &proof,
        METHOD,
        URL,
        &replay,
        VerifyProofOptions {
            now: Some(NOW),
            content_sha256: Some(Sha256::digest(gzip).into()),
            ..VerifyProofOptions::default()
        },
    )
    .await
    .unwrap();
}

/// ANS-6 §7.12 / §10 tolerance case: a proof carrying an unknown payload
/// claim verifies — the payload is the open extension lane.
#[tokio::test]
async fn unknown_payload_claim_is_tolerated() {
    let (key, cert, _) = identity_material(30, ANS_NAME);
    let signing_key = key.clone();
    let signer = signer_at_now(key, cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();

    let (h, p, _) = {
        let mut it = proof.split('.');
        (
            it.next().unwrap().to_string(),
            it.next().unwrap().to_string(),
            it.next().unwrap(),
        )
    };
    let mut payload: serde_json::Value =
        serde_json::from_slice(&base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(&p).unwrap())
            .unwrap();
    payload["future_extension"] = serde_json::json!({"nested": true});
    let p2 = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{h}.{p2}");
    let sig = super::jws::sign_es256(&signing_key, signing_input.as_bytes()).unwrap();
    let extended = format!("{h}.{p2}.{sig}");

    verify_proof(
        &extended,
        METHOD,
        URL,
        &replay(),
        VerifyProofOptions {
            now: Some(NOW),
            ..VerifyProofOptions::default()
        },
    )
    .await
    .unwrap();
}

/// ANS-6 §7.12: a revision is a change a verifier cannot safely ignore, so a
/// proof minted under a revision this implementation does not know rejects
/// (contrast with the unknown-*claim* tolerance above).
#[tokio::test]
async fn unknown_profile_revision_rejected() {
    let (key, cert, _) = identity_material(31, ANS_NAME);
    let signing_key = key.clone();
    let signer = signer_at_now(key, cert);
    let proof = signer.sign(METHOD, URL, None).unwrap();

    let (h, p, _) = {
        let mut it = proof.split('.');
        (
            it.next().unwrap().to_string(),
            it.next().unwrap().to_string(),
            it.next().unwrap(),
        )
    };
    let mut payload: serde_json::Value =
        serde_json::from_slice(&base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(&p).unwrap())
            .unwrap();
    payload["ans_profile"] = serde_json::json!(ANS_PROFILE_REVISION + 1);
    let p2 = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{h}.{p2}");
    let sig = super::jws::sign_es256(&signing_key, signing_input.as_bytes()).unwrap();
    let future_revision = format!("{h}.{p2}.{sig}");

    let err = verify_proof(
        &future_revision,
        METHOD,
        URL,
        &replay(),
        VerifyProofOptions {
            now: Some(NOW),
            ..VerifyProofOptions::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::UnsupportedProfile);
}

/// Identity Certificates are optional at registration (ANS-1 §6.1), so a
/// status token can carry no `validIdentityCerts` at all. Such an agent
/// cannot authenticate as a Method B caller: possession verifies, but the
/// §7.5 binding rejects cleanly — no panic, no fallback.
#[tokio::test]
async fn caller_rejected_when_token_has_no_identity_certs() {
    let (key, cert, _) = identity_material(32, ANS_NAME);
    let signer = signer_at_now(key, cert);
    let (tl_key, store) = make_tl_key(13);
    let agent_id = Uuid::nil();
    let token = make_status_token_without_identity_certs(&tl_key, agent_id, ANS_NAME);
    let receipt = make_receipt(&tl_key, agent_id, ANS_NAME);

    let proof = signer.sign(METHOD, URL, None).unwrap();
    let err = verify_caller(
        &proof,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &store,
        &replay(),
        VerifyCallerOptions {
            now: Some(NOW),
            ..VerifyCallerOptions::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::BindingFailed);
}

#[test]
fn error_echo_truncates_on_char_boundary() {
    // 63 ASCII bytes then a 2-byte char straddling the 64-byte cutoff.
    let s = format!("{}é tail", "a".repeat(63));
    let msg = PopError::echo(&s);
    assert_eq!(msg, format!("{}…", "a".repeat(63)));
}

#[test]
fn access_token_from_authorization_multibyte_prefix() {
    // Byte 4 falls inside a multi-byte char; must not panic.
    assert!(access_token_from_authorization("abcé longer").is_none());
    assert!(access_token_from_authorization("é").is_none());
}

#[test]
fn normalize_authority_drops_default_ports() {
    assert_eq!(
        normalize_authority("API.Example.com:443"),
        "api.example.com"
    );
    assert_eq!(
        normalize_authority(" api.example.com:80 "),
        "api.example.com"
    );
}
