#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Example: ANS-6 Method B — `DPoP` caller authentication without mTLS
//!
//! Self-contained example that generates an identity certificate, a
//! transparency-log key, and SCITT artifacts in-memory, then runs both sides
//! of the application-layer proof-of-possession flow:
//!
//! - **Caller**: mints an RFC 9449 `DPoP` proof bound to its Identity
//!   Certificate (`Signer` / `attach_identity`)
//! - **Callee**: composes possession (proof), liveness (status token), and
//!   identity (receipt) onto one certificate (`verify_caller`), with the
//!   trusted-authority allowlist, replay rejection, verified-artifact cache,
//!   and unknown-key retry signal demonstrated along the way
//!
//! ```bash
//! cargo run -p ans-verify --features scitt,test-support --example local_dpop
//! ```

use ans_verify::{
    AnsName, CertFingerprint, MemoryReplayCache, PopErrorKind, ScittHeaders, ScittKeyStore, Signer,
    VerifiedArtifactCache, VerifyCallerOptions, attach_identity, attach_identity_with_content,
    compute_sig_structure_digest, verify_caller,
};
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner as _};
use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, SanType};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const CALLER_ANS_NAME: &str = "ans://v1.0.0.caller.example.com";
const METHOD: &str = "POST";
const URL: &str = "https://payments.example.com/api/task";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "local_dpop=info,ans_verify=debug".into()),
        )
        .init();

    // --- In-memory setup: identity certificate, TL key, SCITT artifacts ---

    println!("Generating caller identity and transparency-log material...");
    let (identity_key, identity_cert_der, fingerprint) = caller_identity(CALLER_ANS_NAME)?;
    let (tl_key, key_store) = transparency_log_key();
    let agent_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();
    let status_token = mint_status_token(&tl_key, agent_id, CALLER_ANS_NAME, &fingerprint, now);
    let receipt = mint_receipt(&tl_key, agent_id, CALLER_ANS_NAME);
    println!("  Identity fingerprint: {fingerprint}");
    println!("  Agent id: {agent_id}");

    // --- Caller side: mint the DPoP proof for an outbound request ---
    //
    // In a real agent the SCITT headers come from `ScittHeaderSupplier`;
    // here we attach the artifacts minted above.

    let signer = Signer::new(identity_key, identity_cert_der)?;
    let proof = attach_identity(&signer, METHOD, URL, None)?;
    let headers = ScittHeaders::new(Some(receipt.clone()), Some(status_token.clone()));
    println!("\nCaller minted DPoP proof ({} bytes)", proof.len());

    // --- Callee side: verify possession + liveness + identity ---
    //
    // The callee owns the comparison URL (ANS-6 §7.7): reconstruct it from
    // configuration or a proxy-set header, never from the client's `Host`.
    // The allowlist rejects foreign authorities before any proof work, and
    // the artifact cache skips re-verifying re-presented artifacts (§4.6).

    let replay = MemoryReplayCache::new(0);
    let artifact_cache = VerifiedArtifactCache::default();
    let opts = || {
        VerifyCallerOptions::default()
            .with_trusted_authority("payments.example.com")
            .with_artifact_cache(artifact_cache.clone())
    };

    let identity =
        verify_caller(&proof, &headers, METHOD, URL, &key_store, &replay, opts()).await?;
    println!("\nRequest 1 authenticated:");
    println!("  ans_name: {}", identity.ans_name);
    println!("  agent_id: {}", identity.agent_id);
    println!("  jkt:      {}", identity.jkt);

    // Replaying the same proof is rejected — each proof is single-use.
    let err = verify_caller(&proof, &headers, METHOD, URL, &key_store, &replay, opts())
        .await
        .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::Replay);
    println!("\nReplayed proof rejected: {err}");

    // A fresh proof succeeds; the status token and receipt bytes are
    // unchanged, so they verify from the cache without re-running crypto.
    let proof2 = attach_identity(&signer, METHOD, URL, None)?;
    verify_caller(&proof2, &headers, METHOD, URL, &key_store, &replay, opts()).await?;
    println!("Request 2 authenticated (artifacts served from cache)");

    // Content-bearing requests bind the body into the proof (§7.13): the
    // callee hashes the content it received, so a TLS-terminating hop that
    // rewrites the body breaks the binding — even on a first, in-flight
    // request that no replay check would catch.
    let body: &[u8] = br#"{"amount":100}"#;
    let bound = attach_identity_with_content(&signer, METHOD, URL, None, body)?;
    let digest: [u8; 32] = Sha256::digest(body).into();
    verify_caller(
        &bound,
        &headers,
        METHOD,
        URL,
        &key_store,
        &replay,
        opts().with_content_sha256(digest),
    )
    .await?;
    println!("Content-bound request authenticated");

    let bound2 = attach_identity_with_content(&signer, METHOD, URL, None, body)?;
    let rewritten: [u8; 32] = Sha256::digest(br#"{"amount":9999}"#).into();
    let err = verify_caller(
        &bound2,
        &headers,
        METHOD,
        URL,
        &key_store,
        &replay,
        opts().with_content_sha256(rewritten),
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::ContentBindingMismatch);
    println!("Rewritten body rejected: {err}");

    // A request for an authority this callee does not answer as is rejected
    // before any proof verification — the §7.7 defense against spoofed-Host
    // replays (ans-6-examples.md A.6).
    let proof3 = attach_identity(&signer, METHOD, "https://evil.example.com/api/task", None)?;
    let err = verify_caller(
        &proof3,
        &headers,
        METHOD,
        "https://evil.example.com/api/task",
        &key_store,
        &replay,
        opts(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, PopErrorKind::UntrustedAuthority);
    println!("Foreign authority rejected: {err}");

    // An artifact signed by a key the callee does not know yields the §9.5
    // retry signal: refresh the root keys once (cooldown-gated via
    // `RefreshableKeyStore`), retry, then reject.
    let other_store = ScittKeyStore::from_c2sp_keys(&[unrelated_key_line()])?;
    let proof4 = attach_identity(&signer, METHOD, URL, None)?;
    let err = verify_caller(
        &proof4,
        &headers,
        METHOD,
        URL,
        &other_store,
        &MemoryReplayCache::new(0),
        VerifyCallerOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(err.is_unknown_key_id());
    println!("Unknown signing key detected — refresh root keys and retry: {err}");

    println!("\nDone.");
    Ok(())
}

/// Generate a P-256 identity key and a self-signed certificate carrying the
/// `ans://` URI SAN, as the ANS Private CA would issue.
fn caller_identity(
    ans_name: &str,
) -> Result<(SigningKey, Vec<u8>, CertFingerprint), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_slice(&[7u8; 32])?;
    let pkcs8 = signing_key.to_pkcs8_der()?;
    let key_pair = KeyPair::try_from(pkcs8.as_bytes())?;
    let host = AnsName::parse(ans_name)?.fqdn().as_str().to_string();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, host.clone());
    params
        .subject_alt_names
        .push(SanType::DnsName(host.try_into()?));
    params
        .subject_alt_names
        .push(SanType::URI(ans_name.try_into()?));
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.self_signed(&key_pair)?;
    let der = cert.der().to_vec();
    let fingerprint = CertFingerprint::from_der(&der);
    Ok((signing_key, der, fingerprint))
}

/// Generate a transparency-log signing key and a key store trusting it, the
/// way a callee would load `/root-keys` C2SP lines at bootstrap.
fn transparency_log_key() -> (SigningKey, ScittKeyStore) {
    let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();
    let store = ScittKeyStore::from_c2sp_keys(&[c2sp_line(&signing_key)]).unwrap();
    (signing_key, store)
}

/// A valid C2SP line for a key no artifact in this example is signed with.
fn unrelated_key_line() -> String {
    c2sp_line(&SigningKey::from_slice(&[9u8; 32]).unwrap())
}

fn c2sp_line(signing_key: &SigningKey) -> String {
    let spki = signing_key.verifying_key().to_public_key_der().unwrap();
    let digest = Sha256::digest(spki.as_bytes());
    format!(
        "tl.example.com+{}+{}",
        hex::encode(&digest[..4]),
        BASE64_STANDARD.encode(spki.as_bytes())
    )
}

fn cose_kid(signing_key: &SigningKey) -> Vec<u8> {
    let spki = signing_key.verifying_key().to_public_key_der().unwrap();
    Sha256::digest(spki.as_bytes())[..4].to_vec()
}

fn protected_header(signing_key: &SigningKey, with_vds: bool) -> Vec<u8> {
    let mut pairs = vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer((-7_i64).into()),
        ),
        (
            ciborium::Value::Integer(4.into()),
            ciborium::Value::Bytes(cose_kid(signing_key)),
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

/// Mint a status token as the TL would: integer-keyed CBOR payload with the
/// identity certificate's raw-byte fingerprint in `validIdentityCerts`.
fn mint_status_token(
    tl_key: &SigningKey,
    agent_id: Uuid,
    ans_name: &str,
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
            ciborium::Value::Integer((now + 3600).into()),
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
        protected_header(tl_key, false),
        ciborium::Value::Map(vec![]),
        &payload_bytes,
    )
}

/// Mint a receipt whose leaf event (V2 envelope) names the agent, with a
/// single-leaf inclusion proof.
fn mint_receipt(tl_key: &SigningKey, agent_id: Uuid, ans_name: &str) -> Vec<u8> {
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
        protected_header(tl_key, true),
        unprotected,
        &event_bytes,
    )
}
