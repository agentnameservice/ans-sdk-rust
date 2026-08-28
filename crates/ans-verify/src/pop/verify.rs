//! Cryptographic verification of a `DPoP` proof (possession only).

use std::sync::Arc;
use std::time::Duration;

use ans_types::{AnsName, CertFingerprint};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

use super::cache::VerifiedArtifactCache;
use super::error::{PopError, PopErrorKind};
use super::jws::{b64url_encode, jws_signing_input, split_compact_jws, verify_es256};
use super::proof::{
    accept_es256_dpop, access_token_hash, check_cert_validity, decode_proof_header,
    decode_proof_payload, match_jwk_to_cert, normalize_htu, parse_leaf_cert,
};
use super::replay::ReplayCache;

/// Maximum compact `DPoP` proof length (8 KiB).
pub const MAX_PROOF_SIZE: usize = 8 * 1024;
/// Default freshness window for a proof's `iat` (±120 seconds).
pub const DEFAULT_POP_SKEW: Duration = Duration::from_secs(120);
/// Maximum accepted `jti` size in bytes.
pub const MAX_JTI_SIZE: usize = 128;
/// Extra retention past the freshness window so no boundary gap opens.
const REPLAY_GRACE_SECS: i64 = 5;

/// A cryptographically verified `DPoP` proof that is **not yet** bound to a
/// live ANS agent. Use [`super::verify_caller`] for the full three-proof check.
#[derive(Debug, Clone)]
pub struct ProofResult {
    /// DER of the `x5c[0]` identity certificate.
    pub cert_der: Vec<u8>,
    /// SHA-256 fingerprint of `cert_der`.
    pub fingerprint: CertFingerprint,
    /// RFC 7638 thumbprint of the proof key (`cnf.jkt`).
    pub jkt: String,
    /// Proof identifier (raw `jti` claim).
    pub jti: String,
    /// Normalized `htu` from the proof.
    pub htu: String,
    /// Proof `iat` as Unix seconds.
    pub issued_at: i64,
    pub(crate) replay_exp: i64,
    /// The certificate's `ans://` URI SAN, extracted during cert parsing so
    /// the binding step does not re-parse the DER.
    pub(crate) ans_name: Option<AnsName>,
}

/// Options for [`verify_proof`].
#[derive(Debug, Clone, Default)]
pub struct VerifyProofOptions {
    /// Access token presented as `Authorization: DPoP <token>`.
    ///
    /// When `Some`, the proof must carry a matching `ath`. When `None`, a
    /// proof that carries `ath` is rejected.
    pub access_token: Option<String>,
    /// Freshness window. `None` or zero uses [`DEFAULT_POP_SKEW`].
    pub skew: Option<Duration>,
    /// Unix timestamp used as `now`. `None` uses the system clock.
    pub now: Option<i64>,
}

/// Verify a compact `DPoP` proof against an HTTP method and URL.
///
/// Order: size cap, compact structure, pinned `typ`/`alg` plus required
/// `jwk`/`x5c`, P-256 leaf within its validity window, jwk↔x5c key equality,
/// signature, `htm`, normalized `htu`, `ath` ↔ presented token, `iat` window,
/// `jti` presence and size, then replay commit.
///
/// A proof verified here is well-formed but **not trusted**: nothing has
/// established that its certificate belongs to a live ANS agent. Prefer
/// [`super::verify_caller`], which records the `jti` only after status-token
/// binding succeeds.
///
/// # Errors
///
/// Returns a [`PopError`] for any failed check, including replay-cache errors
/// (fail closed).
pub async fn verify_proof(
    proof_jws: &str,
    method: &str,
    raw_url: &str,
    replay: &dyn ReplayCache,
    opts: VerifyProofOptions,
) -> Result<ProofResult, PopError> {
    let result = verify_proof_unrecorded(proof_jws, method, raw_url, &opts, None)?;
    commit_replay(&result, replay).await?;
    Ok(result)
}

/// `cert_cache`: when set, the parsed `x5c[0]` is reused for identical entry
/// bytes; the validity window still checks against `now` on every call.
pub fn verify_proof_unrecorded(
    proof_jws: &str,
    method: &str,
    raw_url: &str,
    opts: &VerifyProofOptions,
    cert_cache: Option<&VerifiedArtifactCache>,
) -> Result<ProofResult, PopError> {
    if proof_jws.len() > MAX_PROOF_SIZE {
        return Err(PopError::new(
            PopErrorKind::MalformedProof,
            "proof exceeds size limit",
        ));
    }
    let skew = opts
        .skew
        .filter(|d| *d > Duration::ZERO)
        .unwrap_or(DEFAULT_POP_SKEW);
    let skew_secs = i64::try_from(skew.as_secs()).unwrap_or(i64::MAX);
    let now = opts.now.unwrap_or_else(|| chrono::Utc::now().timestamp());

    let (header_b64, payload_b64, sig_b64) = split_compact_jws(proof_jws)?;
    let header = decode_proof_header(header_b64)?;
    accept_es256_dpop(&header)?;
    let leaf = match cert_cache {
        Some(cache) => {
            let key = VerifiedArtifactCache::key(header.x5c[0].as_bytes());
            if let Some(leaf) = cache.proof_cert(&key) {
                leaf
            } else {
                let leaf = Arc::new(parse_leaf_cert(&header.x5c[0])?);
                cache.store_proof_cert(key, leaf.clone());
                leaf
            }
        }
        None => Arc::new(parse_leaf_cert(&header.x5c[0])?),
    };
    check_cert_validity(&leaf, now, skew_secs)?;
    match_jwk_to_cert(&header.jwk, &leaf.key)?;
    let signing_input = jws_signing_input(header_b64, payload_b64);
    verify_es256(&leaf.key, signing_input.as_bytes(), sig_b64)?;
    let payload = decode_proof_payload(payload_b64)?;
    check_http_binding(&payload, method, raw_url)?;
    check_token_binding(&payload, opts.access_token.as_deref())?;
    check_freshness(&payload, now, skew)?;
    if payload.jti.is_empty() {
        return Err(PopError::new(
            PopErrorKind::MalformedProof,
            "proof missing jti",
        ));
    }
    if payload.jti.len() > MAX_JTI_SIZE {
        return Err(PopError::new(
            PopErrorKind::MalformedProof,
            "proof jti exceeds size limit",
        ));
    }

    Ok(ProofResult {
        fingerprint: leaf.fingerprint.clone(),
        jkt: leaf.jkt.clone(),
        ans_name: leaf.ans_name.clone(),
        jti: payload.jti,
        htu: payload.htu,
        issued_at: payload.iat,
        replay_exp: payload
            .iat
            .saturating_add(skew_secs)
            .saturating_add(REPLAY_GRACE_SECS),
        cert_der: leaf.der.clone(),
    })
}

fn check_http_binding(
    payload: &super::proof::ProofPayload,
    method: &str,
    raw_url: &str,
) -> Result<(), PopError> {
    if payload.htm != method {
        return Err(PopError::new(
            PopErrorKind::HttpBindingMismatch,
            "htm does not match request method",
        ));
    }
    let want = normalize_htu(raw_url)?;
    if payload.htu != want {
        return Err(PopError::new(
            PopErrorKind::HttpBindingMismatch,
            "htu does not match request URL",
        ));
    }
    Ok(())
}

fn check_token_binding(
    payload: &super::proof::ProofPayload,
    access_token: Option<&str>,
) -> Result<(), PopError> {
    match (access_token, payload.ath.as_deref()) {
        (None, Some(_)) => Err(PopError::new(
            PopErrorKind::TokenBindingMismatch,
            "proof carries ath but no access token was presented",
        )),
        (Some(_), None) => Err(PopError::new(
            PopErrorKind::TokenBindingMismatch,
            "access token presented but proof carries no ath",
        )),
        (None, None) => Ok(()),
        (Some(token), Some(ath)) => {
            let want = access_token_hash(token);
            if ath.as_bytes().ct_eq(want.as_bytes()).unwrap_u8() != 1 {
                return Err(PopError::new(
                    PopErrorKind::TokenBindingMismatch,
                    "ath does not match the presented access token",
                ));
            }
            Ok(())
        }
    }
}

fn check_freshness(
    payload: &super::proof::ProofPayload,
    now: i64,
    skew: Duration,
) -> Result<(), PopError> {
    if payload.iat == 0 {
        return Err(PopError::new(
            PopErrorKind::MalformedProof,
            "proof missing iat",
        ));
    }
    let skew_secs = i64::try_from(skew.as_secs()).unwrap_or(i64::MAX);
    let delta = now.saturating_sub(payload.iat);
    if delta > skew_secs {
        return Err(PopError::new(
            PopErrorKind::ProofStale,
            "proof iat is too old",
        ));
    }
    if delta < -skew_secs {
        return Err(PopError::new(
            PopErrorKind::ProofStale,
            "proof iat is too far in the future",
        ));
    }
    Ok(())
}

pub async fn commit_replay(result: &ProofResult, replay: &dyn ReplayCache) -> Result<(), PopError> {
    let digest = Sha256::digest(result.jti.as_bytes());
    let key = b64url_encode(&digest);
    let seen = replay.check_and_store(&key, result.replay_exp).await?;
    if seen {
        return Err(PopError::new(
            PopErrorKind::Replay,
            "jti already seen within the freshness window",
        ));
    }
    Ok(())
}
