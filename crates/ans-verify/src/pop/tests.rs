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
    let payload = ciborium::Value::Map(vec![
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
        (
            ciborium::Value::Integer(6.into()),
            ciborium::Value::Array(vec![cert_entry]),
        ),
        (
            ciborium::Value::Integer(7.into()),
            ciborium::Value::Array(vec![]),
        ),
        (
            ciborium::Value::Integer(8.into()),
            ciborium::Value::Map(vec![]),
        ),
    ]);
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
async fn artifact_cache_reuses_verified_artifacts() {
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

    // Same bytes against a store that does NOT trust the TL key: only a
    // cache hit (skipped crypto) can make this succeed.
    let (_, wrong_store) = make_tl_key(8);
    let proof2 = signer.sign(METHOD, URL, None).unwrap();
    let id = verify_caller(
        &proof2,
        &headers(&receipt, &token),
        METHOD,
        URL,
        &wrong_store,
        &replay(),
        opts(&cache),
    )
    .await
    .unwrap();
    assert_eq!(id.ans_name.to_string(), ANS_NAME);
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
    let opts = |content: Option<[u8; 32]>, require: bool| VerifyProofOptions {
        content_sha256: content,
        require_content_binding: require,
        now: Some(NOW),
        ..VerifyProofOptions::default()
    };

    // Bound content, matching digest → ok.
    let bound = signer.sign_with_content(METHOD, URL, None, body).unwrap();
    verify_proof(&bound, METHOD, URL, &replay(), opts(Some(digest), false))
        .await
        .unwrap();

    // Bound content, tampered body → reject.
    let tampered: [u8; 32] = Sha256::digest(br#"{"amount": 9999}"#).into();
    let err = verify_proof(&bound, METHOD, URL, &replay(), opts(Some(tampered), false))
        .await
        .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::ContentBindingMismatch);

    // Claim present but request carries no content → reject.
    let bound2 = signer.sign_with_content(METHOD, URL, None, body).unwrap();
    let err = verify_proof(&bound2, METHOD, URL, &replay(), opts(None, false))
        .await
        .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::ContentBindingMismatch);

    // Unbound content: accepted at revision 1, rejected under policy.
    let unbound = signer.sign(METHOD, URL, None).unwrap();
    verify_proof(&unbound, METHOD, URL, &replay(), opts(Some(digest), false))
        .await
        .unwrap();
    let unbound2 = signer.sign(METHOD, URL, None).unwrap();
    let err = verify_proof(&unbound2, METHOD, URL, &replay(), opts(Some(digest), true))
        .await
        .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::ContentBindingMismatch);

    // Empty content mints no claim (a zero-length body carries none).
    let empty = signer.sign_with_content(METHOD, URL, None, b"").unwrap();
    verify_proof(&empty, METHOD, URL, &replay(), opts(None, false))
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
