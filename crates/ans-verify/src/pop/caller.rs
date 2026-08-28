//! Three-proof caller authentication: `DPoP` + status token + receipt.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use ans_types::{AnsName, CertFingerprint, StatusTokenPayload};
use serde::Deserialize;
use uuid::Uuid;

use super::cache::VerifiedArtifactCache;
use super::error::{PopError, PopErrorKind};
use super::proof::{normalize_authority, request_authority};
use super::replay::ReplayCache;
use super::verify::{ProofResult, VerifyProofOptions, commit_replay, verify_proof_unrecorded};
use crate::scitt::{
    MAX_CLOCK_SKEW_TOLERANCE_SECS, ScittHeaders, ScittKeyStore, VerifiedReceipt,
    matches_identity_cert, verify_receipt, verify_status_token_at,
};

/// Default status-token clock-skew tolerance (matches [`crate::ScittConfig`]).
const DEFAULT_STATUS_SKEW: Duration = Duration::from_secs(60);

/// Authenticated identity of an A2A caller.
///
/// This is AUTHENTICATION, not authorization. A successful result means the
/// request provably came from this agent; the callee MUST still decide whether
/// this agent may perform the requested action.
#[derive(Debug, Clone)]
pub struct CallerIdentity {
    /// Caller's `ans://` name, from the verified status token.
    pub ans_name: AnsName,
    /// Caller's agent id, from the verified status token.
    pub agent_id: Uuid,
    /// SHA-256 of the identity certificate that signed the proof.
    pub fingerprint: CertFingerprint,
    /// RFC 7638 thumbprint of the key that signed the proof (`cnf.jkt`).
    pub jkt: String,
}

/// Options for [`verify_caller`].
#[derive(Debug, Clone)]
pub struct VerifyCallerOptions {
    /// Require a SCITT receipt (default `true`). When `false`, identity rests
    /// on the status token + possession proof only.
    pub require_receipt: bool,
    /// Restrict accepted callers to these `ans://` names (compared by FQDN
    /// host, case-insensitive). Empty means any proven agent authenticates.
    pub allowed_ans_names: Vec<String>,
    /// Trusted-authority allowlist (ANS-6 §7.7): the externally-visible
    /// authorities this callee answers as. When non-empty, a `raw_url` whose
    /// authority is outside the set (compared case-insensitively with default
    /// ports dropped) is rejected before any proof verification. Empty skips
    /// the check — valid only when `raw_url` is already externally configured.
    pub trusted_authorities: Vec<String>,
    /// `DPoP` freshness window. `None` uses [`DEFAULT_POP_SKEW`](crate::DEFAULT_POP_SKEW).
    pub pop_skew: Option<Duration>,
    /// Status-token clock skew. `None` uses 60 seconds.
    pub status_skew: Option<Duration>,
    /// Unix timestamp used as `now`. `None` uses the system clock.
    pub now: Option<i64>,
    /// Access token presented as `Authorization: DPoP <token>`.
    pub access_token: Option<String>,
    /// Cache of verified artifacts (ANS-6 §4.6). When set, a status token or
    /// receipt whose exact bytes verified before skips re-verification; the
    /// token's `exp` is still enforced and the possession proof is never
    /// cached. Cloning the cache is cheap — share one per key store.
    pub artifact_cache: Option<VerifiedArtifactCache>,
}

impl Default for VerifyCallerOptions {
    fn default() -> Self {
        Self {
            require_receipt: true,
            allowed_ans_names: Vec::new(),
            trusted_authorities: Vec::new(),
            pop_skew: None,
            status_skew: None,
            now: None,
            access_token: None,
            artifact_cache: None,
        }
    }
}

impl VerifyCallerOptions {
    /// Restrict accepted callers to this `ans://` name (host match).
    pub fn with_expected_ans_name(mut self, ans_name: impl Into<String>) -> Self {
        self.allowed_ans_names.push(ans_name.into());
        self
    }

    /// Add an externally-visible authority this callee answers as (§7.7).
    pub fn with_trusted_authority(mut self, authority: impl Into<String>) -> Self {
        self.trusted_authorities.push(authority.into());
        self
    }

    /// Reuse verified status tokens and receipts across requests (§4.6).
    pub fn with_artifact_cache(mut self, cache: VerifiedArtifactCache) -> Self {
        self.artifact_cache = Some(cache);
        self
    }
}

/// Authenticate an A2A caller from its `DPoP` proof and SCITT headers.
///
/// Composes possession ([`super::verify_proof`]), liveness (status token),
/// and identity (receipt) and binds them to one identity certificate.
/// Missing status token is a hard reject (Flavor B does not fall back to
/// the badge tier). The `jti` is recorded only after that binding succeeds.
///
/// # The `raw_url` authority (ANS-6 §7.7)
///
/// The `htu` check is only as trustworthy as `raw_url`. Its authority MUST
/// come from configuration or a header the fronting proxy sets and strips
/// from clients — deriving it from the request's own `Host` or a
/// client-supplied `X-Forwarded-*` is a MUST NOT — and it MUST be joined
/// with **this request's** path. A `Host`-derived URL lets a proof captured
/// for another origin replay here; a constant URL collapses `htu` to one
/// value across all paths. Setting
/// [`VerifyCallerOptions::trusted_authorities`] adds the allowlist half of
/// the §7.7 defense: a `raw_url` for a foreign authority is then rejected
/// before any proof verification. §7.7 requires deployments to fail startup
/// when neither an allowlist nor an externally-configured URL is wired —
/// this library cannot see your startup, so enforce that in the embedding
/// service.
///
/// Callers should also run the request-level preflight first: reject the
/// request via [`super::reject_duplicate_header`] when `DPoP`,
/// `Authorization`, `X-SCITT-Receipt`, or `X-ANS-Status-Token` appears
/// more than once.
///
/// # Errors
///
/// Returns a [`PopError`] for missing artifacts, cryptographic failure,
/// binding failure, or replay-cache errors.
pub async fn verify_caller(
    proof_jws: &str,
    headers: &ScittHeaders,
    method: &str,
    raw_url: &str,
    keys: &ScittKeyStore,
    replay: &dyn ReplayCache,
    opts: VerifyCallerOptions,
) -> Result<CallerIdentity, PopError> {
    // §7.4 preflight: reject a foreign authority before any proof work.
    if !opts.trusted_authorities.is_empty() {
        let authority = request_authority(raw_url)?;
        let allowed = opts
            .trusted_authorities
            .iter()
            .map(|a| normalize_authority(a))
            .any(|a| a == authority);
        if !allowed {
            return Err(PopError::new(
                PopErrorKind::UntrustedAuthority,
                "request authority is not in the trusted set",
            ));
        }
    }

    if proof_jws.is_empty() {
        return Err(PopError::new(
            PopErrorKind::MissingHeaders,
            "no DPoP proof on request",
        ));
    }
    let token_bytes = headers.status_token.as_deref().ok_or_else(|| {
        PopError::new(
            PopErrorKind::MissingHeaders,
            "no ANS status token on request",
        )
    })?;
    if opts.require_receipt && headers.receipt.is_none() {
        return Err(PopError::new(
            PopErrorKind::MissingHeaders,
            "no SCITT receipt on request",
        ));
    }

    let now = opts.now.unwrap_or_else(|| chrono::Utc::now().timestamp());
    let proof_opts = VerifyProofOptions {
        access_token: opts.access_token.clone(),
        skew: opts.pop_skew,
        now: Some(now),
    };
    let proof = verify_proof_unrecorded(
        proof_jws,
        method,
        raw_url,
        &proof_opts,
        opts.artifact_cache.as_ref(),
    )?;

    let status_skew = opts.status_skew.unwrap_or(DEFAULT_STATUS_SKEW);
    let status = verified_status_payload(
        token_bytes,
        keys,
        status_skew,
        now,
        opts.artifact_cache.as_ref(),
    )
    .await?;

    let receipt = if opts.require_receipt {
        let bytes = headers.receipt.as_deref().ok_or_else(|| {
            PopError::new(PopErrorKind::MissingHeaders, "no SCITT receipt on request")
        })?;
        Some(verified_receipt(bytes, keys, opts.artifact_cache.as_ref()).await?)
    } else {
        None
    };

    let identity = bind_caller(&proof, &status, receipt.as_deref(), &opts)?;
    commit_replay(&proof, replay).await?;
    Ok(identity)
}

/// Verify the status token, reusing a cached result for identical bytes.
///
/// ANS-6 §4.6: a cache hit skips the cryptographic re-verification but never
/// the time check — once the cached token's `exp` (plus skew, capped as in
/// [`verify_status_token_at`]) passes, the bytes re-verify fresh and fail
/// with the canonical expiry error.
async fn verified_status_payload(
    token_bytes: &[u8],
    keys: &ScittKeyStore,
    skew: Duration,
    now: i64,
    cache: Option<&VerifiedArtifactCache>,
) -> Result<Arc<StatusTokenPayload>, PopError> {
    let verify_fresh = || {
        verify_status_token_at(token_bytes, keys, skew, now)
            .map(|v| Arc::new(v.payload))
            .map_err(|e| {
                PopError::with_source(
                    PopErrorKind::StatusInvalid,
                    "status token verification failed",
                    e,
                )
            })
    };
    let Some(cache) = cache else {
        return verify_fresh();
    };
    let key = VerifiedArtifactCache::key(token_bytes);
    let tolerance =
        i64::try_from(skew.as_secs().min(MAX_CLOCK_SKEW_TOLERANCE_SECS)).unwrap_or(i64::MAX);
    if let Some(payload) = cache.status(&key).await
        && now <= payload.exp.saturating_add(tolerance)
    {
        return Ok(payload);
    }
    let payload = verify_fresh()?;
    cache.store_status(key, payload.clone()).await;
    Ok(payload)
}

/// Verify the receipt, reusing a cached result for identical bytes.
///
/// Receipts carry no expiry — an inclusion proof that verified once stays
/// valid for those bytes, so a hit is returned as-is.
async fn verified_receipt(
    receipt_bytes: &[u8],
    keys: &ScittKeyStore,
    cache: Option<&VerifiedArtifactCache>,
) -> Result<Arc<VerifiedReceipt>, PopError> {
    let verify_fresh = || {
        verify_receipt(receipt_bytes, keys)
            .map(Arc::new)
            .map_err(|e| {
                PopError::with_source(
                    PopErrorKind::ReceiptInvalid,
                    "receipt verification failed",
                    e,
                )
            })
    };
    let Some(cache) = cache else {
        return verify_fresh();
    };
    let key = VerifiedArtifactCache::key(receipt_bytes);
    if let Some(receipt) = cache.receipt(&key).await {
        return Ok(receipt);
    }
    let receipt = verify_fresh()?;
    cache.store_receipt(key, receipt.clone()).await;
    Ok(receipt)
}

fn bind_caller(
    proof: &ProofResult,
    status: &ans_types::StatusTokenPayload,
    receipt: Option<&VerifiedReceipt>,
    opts: &VerifyCallerOptions,
) -> Result<CallerIdentity, PopError> {
    if !matches_identity_cert(status, &proof.fingerprint) {
        return Err(PopError::new(
            PopErrorKind::BindingFailed,
            "proof certificate fingerprint is not in the status token's validIdentityCerts",
        ));
    }

    let cert_ans = proof.ans_name.as_ref().ok_or_else(|| {
        PopError::new(
            PopErrorKind::BindingFailed,
            "proof certificate has no ans:// URI SAN",
        )
    })?;
    if !cert_ans
        .fqdn()
        .as_str()
        .eq_ignore_ascii_case(status.ans_name.fqdn().as_str())
    {
        return Err(PopError::new(
            PopErrorKind::BindingFailed,
            "proof certificate ans:// SAN host does not match the status token AnsName",
        ));
    }

    if let Some(rcpt) = receipt {
        receipt_names_agent(rcpt, status)?;
    }

    if !opts.allowed_ans_names.is_empty() {
        let allowed = allowed_hosts(&opts.allowed_ans_names);
        if !allowed.contains(&status.ans_name.fqdn().as_str().to_ascii_lowercase()) {
            return Err(PopError::new(
                PopErrorKind::ExpectedPeerMismatch,
                "caller ans host is not in the accepted set",
            ));
        }
    }

    Ok(CallerIdentity {
        ans_name: status.ans_name.clone(),
        agent_id: status.agent_id,
        fingerprint: proof.fingerprint.clone(),
        jkt: proof.jkt.clone(),
    })
}

fn allowed_hosts(names: &[String]) -> HashSet<String> {
    names
        .iter()
        .map(|n| {
            AnsName::parse(n).map_or_else(
                |_| n.trim().to_ascii_lowercase(),
                |ans| ans.fqdn().as_str().to_ascii_lowercase(),
            )
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct Envelope {
    payload: Option<EnvelopePayload>,
    #[serde(rename = "ansId")]
    ans_id: Option<String>,
    #[serde(rename = "ansName")]
    ans_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EnvelopePayload {
    producer: Option<EnvelopeProducer>,
}

#[derive(Debug, Deserialize)]
struct EnvelopeProducer {
    event: Option<LeafEvent>,
}

#[derive(Debug, Deserialize)]
struct LeafEvent {
    #[serde(rename = "ansId")]
    ans_id: Option<String>,
    #[serde(rename = "ansName")]
    ans_name: Option<String>,
}

fn receipt_names_agent(
    receipt: &VerifiedReceipt,
    status: &ans_types::StatusTokenPayload,
) -> Result<(), PopError> {
    let (ans_id, ans_name) = leaf_identity(&receipt.event_bytes)?;
    if ans_id.is_none() && ans_name.is_none() {
        return Err(PopError::new(
            PopErrorKind::ReceiptInvalid,
            "receipt leaf event names no agent (ansId/ansName)",
        ));
    }
    if let Some(id) = ans_id.as_deref() {
        let parsed = Uuid::parse_str(id).map_err(|e| {
            PopError::with_source(
                PopErrorKind::ReceiptInvalid,
                "receipt leaf ansId is not a UUID",
                e,
            )
        })?;
        if parsed != status.agent_id {
            return Err(PopError::new(
                PopErrorKind::BindingFailed,
                "receipt leaf ansId does not match status token agentId",
            ));
        }
    }
    if let Some(name) = ans_name.as_deref()
        && !name.eq_ignore_ascii_case(&status.ans_name.to_string())
    {
        return Err(PopError::new(
            PopErrorKind::BindingFailed,
            "receipt leaf ansName does not match status token ansName",
        ));
    }
    Ok(())
}

fn leaf_identity(event_bytes: &[u8]) -> Result<(Option<String>, Option<String>), PopError> {
    let envelope: Envelope = serde_json::from_slice(event_bytes).map_err(|e| {
        PopError::with_source(
            PopErrorKind::ReceiptInvalid,
            "receipt leaf event is not decodable JSON",
            e,
        )
    })?;
    if let Some(event) = envelope
        .payload
        .as_ref()
        .and_then(|p| p.producer.as_ref())
        .and_then(|p| p.event.as_ref())
    {
        return Ok((event.ans_id.clone(), event.ans_name.clone()));
    }
    Ok((envelope.ans_id, envelope.ans_name))
}
