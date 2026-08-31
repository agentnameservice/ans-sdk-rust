#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Benchmarks for offline SCITT verification and the ANS-6 Method B `DPoP` flow.
//!
//! Everything measured here runs in-process with no network I/O — the point
//! of the SCITT tier. The dominant cost of each verification is one or more
//! ECDSA P-256 operations; the Merkle inclusion walk adds one SHA-256 per
//! tree level, so receipt verification scales logarithmically with log size.
//!
//! ```bash
//! cargo bench -p ans-verify --features scitt,test-support
//! # ring-backed ECDSA verification (~3x faster verifies):
//! cargo bench -p ans-verify --features scitt,test-support,fast-verify
//! # squeeze the pure-Rust backend further:
//! RUSTFLAGS="-C target-cpu=native" cargo bench -p ans-verify --features scitt,test-support
//! ```

use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ans_verify::{
    CertFingerprint, MemoryReplayCache, ReplayCache as _, ScittHeaders, ScittKeyStore, Signer,
    VerifiedArtifactCache, VerifyCallerOptions, VerifyProofOptions, attach_identity,
    compute_sig_structure_digest, verify_caller, verify_proof, verify_receipt,
    verify_status_token_at,
};
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner as _};
use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, SanType};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const ANS_NAME: &str = "ans://v1.0.0.caller.example.com";
const METHOD: &str = "POST";
const URL: &str = "https://payments.example.com/api/task";

// ── Fixtures (mirror examples/local_dpop.rs) ───────────────────────────────

fn caller_identity() -> (SigningKey, Vec<u8>, CertFingerprint) {
    let signing_key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let pkcs8 = signing_key.to_pkcs8_der().unwrap();
    let key_pair = KeyPair::try_from(pkcs8.as_bytes()).unwrap();
    let host = "caller.example.com".to_string();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, host.clone());
    params
        .subject_alt_names
        .push(SanType::DnsName(host.try_into().unwrap()));
    params
        .subject_alt_names
        .push(SanType::URI(ANS_NAME.try_into().unwrap()));
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.self_signed(&key_pair).unwrap();
    let der = cert.der().to_vec();
    let fingerprint = CertFingerprint::from_der(&der);
    (signing_key, der, fingerprint)
}

fn tl_key() -> (SigningKey, ScittKeyStore) {
    let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();
    let spki = signing_key.verifying_key().to_public_key_der().unwrap();
    let digest = Sha256::digest(spki.as_bytes());
    let line = format!(
        "tl.example.com+{}+{}",
        hex::encode(&digest[..4]),
        BASE64_STANDARD.encode(spki.as_bytes())
    );
    let store = ScittKeyStore::from_c2sp_keys(&[line]).unwrap();
    (signing_key, store)
}

fn protected_header(signing_key: &SigningKey, with_vds: bool) -> Vec<u8> {
    let spki = signing_key.verifying_key().to_public_key_der().unwrap();
    let kid = Sha256::digest(spki.as_bytes())[..4].to_vec();
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
    if with_vds {
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

fn mint_status_token(
    tl_key: &SigningKey,
    agent_id: Uuid,
    fingerprint: &CertFingerprint,
    now: i64,
) -> Vec<u8> {
    let cert_entry = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Bytes(fingerprint.as_bytes().to_vec()),
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
            ciborium::Value::Integer(now.into()),
        ),
        (
            ciborium::Value::Integer(4.into()),
            ciborium::Value::Integer((now + 86_400).into()),
        ),
        (
            ciborium::Value::Integer(5.into()),
            ciborium::Value::Text(ANS_NAME.to_string()),
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
        protected_header(tl_key, false),
        ciborium::Value::Map(vec![]),
        &payload_bytes,
    )
}

/// Receipt for leaf 0 of a tree with `2^depth` entries: the inclusion path
/// carries `depth` sibling hashes. `verify_receipt` walks the path to compute
/// the root, so path contents are arbitrary; the length is what costs.
fn mint_receipt(tl_key: &SigningKey, agent_id: Uuid, depth: u32) -> Vec<u8> {
    let leaf = serde_json::json!({
        "payload": {
            "logId": "550e8400-e29b-41d4-a716-446655440000",
            "producer": {
                "event": {
                    "ansId": agent_id.to_string(),
                    "ansName": ANS_NAME,
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
    let path: Vec<ciborium::Value> = (0..depth)
        .map(|i| ciborium::Value::Bytes(vec![u8::try_from(i % 251).unwrap(); 32]))
        .collect();
    let vdp = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer((-1_i64).into()),
            ciborium::Value::Integer(i64::from(1u32 << depth.min(31)).into()),
        ),
        (
            ciborium::Value::Integer((-2_i64).into()),
            ciborium::Value::Integer(0.into()),
        ),
        (
            ciborium::Value::Integer((-3_i64).into()),
            ciborium::Value::Array(path),
        ),
    ]);
    let unprotected = ciborium::Value::Map(vec![(ciborium::Value::Integer(396.into()), vdp)]);
    sign_cose(
        tl_key,
        protected_header(tl_key, true),
        unprotected,
        &event_bytes,
    )
}

// ── Benchmarks ──────────────────────────────────────────────────────────────

fn bench_status_token(c: &mut Criterion) {
    let (tl, store) = tl_key();
    let (_, _, fp) = caller_identity();
    let now = chrono::Utc::now().timestamp();
    let token = mint_status_token(&tl, Uuid::nil(), &fp, now);

    c.bench_function("status_token/verify", |b| {
        b.iter(|| {
            verify_status_token_at(black_box(&token), &store, Duration::from_secs(60), now).unwrap()
        });
    });
}

fn bench_receipt(c: &mut Criterion) {
    let (tl, store) = tl_key();
    let mut group = c.benchmark_group("receipt");
    // Tree depth k ⇒ 2^k log entries ⇒ k sibling hashes in the inclusion path.
    for depth in [0u32, 10, 20, 30] {
        let receipt = mint_receipt(&tl, Uuid::nil(), depth);
        group.bench_with_input(
            BenchmarkId::new("verify", format!("2pow{depth}_entries")),
            &receipt,
            |b, receipt| b.iter(|| verify_receipt(black_box(receipt), &store).unwrap()),
        );
    }
    group.finish();
}

#[allow(clippy::too_many_lines)] // the three cache tiers read best side by side
fn bench_dpop(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (id_key, cert_der, fp) = caller_identity();
    let (tl, store) = tl_key();
    let now = chrono::Utc::now().timestamp();
    let agent_id = Uuid::nil();
    // A 2^20-entry log: the receipt carries a 20-node inclusion path.
    let token = mint_status_token(&tl, agent_id, &fp, now);
    let receipt = mint_receipt(&tl, agent_id, 20);
    let headers = ScittHeaders::new(Some(receipt.clone()), Some(token));
    let signer = Signer::new(id_key, cert_der).unwrap();

    let mut group = c.benchmark_group("dpop");
    group.throughput(criterion::Throughput::Elements(1));

    group.bench_function("sign", |b| {
        b.iter(|| attach_identity(black_box(&signer), METHOD, URL, None).unwrap());
    });

    // Each proof is single-use (fresh jti), so mint per iteration in setup;
    // only the verification is measured.
    let replay = MemoryReplayCache::new(2_000_000);
    group.bench_function("verify_proof", |b| {
        b.to_async(&rt).iter_batched(
            || signer.sign(METHOD, URL, None).unwrap(),
            |proof| {
                let replay = &replay;
                async move {
                    verify_proof(
                        &proof,
                        METHOD,
                        URL,
                        replay,
                        VerifyProofOptions {
                            now: Some(now),
                            ..VerifyProofOptions::default()
                        },
                    )
                    .await
                    .unwrap()
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });

    let opts = |cache: Option<VerifiedArtifactCache>| {
        let mut o = VerifyCallerOptions {
            now: Some(now),
            ..VerifyCallerOptions::default()
        }
        .with_trusted_authority("payments.example.com");
        o.artifact_cache = cache;
        o
    };

    // Cold — first contact: nothing cached, every request re-verifies proof
    // + status token + receipt (3 ECDSA verifies + the Merkle walk).
    let replay_cold = MemoryReplayCache::new(2_000_000);
    group.bench_function("verify_caller_cold", |b| {
        b.to_async(&rt).iter_batched(
            || signer.sign(METHOD, URL, None).unwrap(),
            |proof| {
                let (headers, store, replay) = (&headers, &store, &replay_cold);
                let opts = opts(None);
                async move {
                    verify_caller(&proof, headers, METHOD, URL, store, replay, opts)
                        .await
                        .unwrap()
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Warm — known agent: the receipt is cached from an earlier request, but
    // the status token has rotated (fresh bytes each iteration, varying iat),
    // so it re-verifies (2 ECDSA verifies per request).
    let replay_warm = MemoryReplayCache::new(2_000_000);
    let cache_warm = VerifiedArtifactCache::default();
    rt.block_on(async {
        let proof = signer.sign(METHOD, URL, None).unwrap();
        verify_caller(
            &proof,
            &headers,
            METHOD,
            URL,
            &store,
            &replay_warm,
            opts(Some(cache_warm.clone())),
        )
        .await
        .unwrap();
    });
    let iat_counter = AtomicU64::new(1);
    group.bench_function("verify_caller_warm", |b| {
        b.to_async(&rt).iter_batched(
            || {
                let iat = now + i64::try_from(iat_counter.fetch_add(1, Ordering::Relaxed)).unwrap();
                let rotated = mint_status_token(&tl, agent_id, &fp, iat);
                let headers = ScittHeaders::new(Some(receipt.clone()), Some(rotated));
                (signer.sign(METHOD, URL, None).unwrap(), headers)
            },
            |(proof, headers)| {
                let (store, replay) = (&store, &replay_warm);
                let opts = opts(Some(cache_warm.clone()));
                async move {
                    verify_caller(&proof, &headers, METHOD, URL, store, replay, opts)
                        .await
                        .unwrap()
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Hot — steady state: receipt and status-token bytes are unchanged
    // between requests, so both verify from the artifact cache (ANS-6 §4.6)
    // and the per-request crypto collapses to the single proof verification.
    let replay_hot = MemoryReplayCache::new(2_000_000);
    let cache_hot = VerifiedArtifactCache::default();
    rt.block_on(async {
        let proof = signer.sign(METHOD, URL, None).unwrap();
        verify_caller(
            &proof,
            &headers,
            METHOD,
            URL,
            &store,
            &replay_hot,
            opts(Some(cache_hot.clone())),
        )
        .await
        .unwrap();
    });
    group.bench_function("verify_caller_hot", |b| {
        b.to_async(&rt).iter_batched(
            || signer.sign(METHOD, URL, None).unwrap(),
            |proof| {
                let (headers, store, replay) = (&headers, &store, &replay_hot);
                let opts = opts(Some(cache_hot.clone()));
                async move {
                    verify_caller(&proof, headers, METHOD, URL, store, replay, opts)
                        .await
                        .unwrap()
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// The primitive that dominates every tier: one ECDSA P-256 operation.
/// `verify` measures the selected backend — pure-Rust `p256` by default,
/// ring under `fast-verify`. Signing is always `p256`.
fn bench_ecdsa(c: &mut Criterion) {
    let key = SigningKey::from_slice(&[5u8; 32]).unwrap();
    let message = b"bench payload";
    let digest: [u8; 32] = Sha256::digest(message).into();
    let (sig, _): (p256::ecdsa::Signature, _) = key.sign_prehash(&digest).unwrap();
    let verifying_key = key.verifying_key();

    let mut group = c.benchmark_group("ecdsa_p256");
    group.bench_function("sign_prehash", |b| {
        b.iter(|| {
            let (sig, _): (p256::ecdsa::Signature, _) =
                key.sign_prehash(black_box(&digest)).unwrap();
            sig
        });
    });
    group.bench_function("verify", |b| {
        b.iter(|| {
            assert!(ans_verify::verify_p256_sha256(
                verifying_key,
                black_box(message.as_slice()),
                &sig
            ));
        });
    });
    group.finish();
}

fn bench_replay_cache(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let now = chrono::Utc::now().timestamp();
    let far_future = now + 86_400;
    // Criterion drives tens of millions of iterations through this path, so
    // measured inserts use an already-expired exp: each entry is evicted by
    // the next call's housekeeping and occupancy stays flat at the prefill.
    let already_expired = now - 60;

    // Steady-state occupancy: 100k live entries, matching the §7.6 sizing
    // for ~800 req/s at the default window.
    let cache = MemoryReplayCache::new(2_000_000);
    rt.block_on(async {
        for i in 0..100_000u64 {
            cache
                .check_and_store(&format!("prefill-{i}"), far_future)
                .await
                .unwrap();
        }
    });

    let counter = AtomicU64::new(0);
    c.bench_function("replay_cache/check_and_store_at_100k", |b| {
        b.to_async(&rt).iter_batched(
            || format!("bench-{}", counter.fetch_add(1, Ordering::Relaxed)),
            |key| {
                let cache = &cache;
                async move {
                    black_box(cache.check_and_store(&key, already_expired).await.unwrap());
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_status_token,
    bench_receipt,
    bench_dpop,
    bench_replay_cache,
    bench_ecdsa
);
criterion_main!(benches);
