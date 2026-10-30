//! Offline Verified Identity control proofs and terminal revocation state.
//!
//! Operator proofs are reconstructed from the proof event, not from a badge's
//! computed key list. Historical proof validity is separate from current TL
//! status. Read current badges from an explicitly trusted HTTPS TL.

use crate::{ScittError, ScittKeyStore, verify_receipt};
use ans_types::{
    IdentityBadge, IdentityEvent, IdentityEventType, IdentityKind, IdentityProofInput,
};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;

/// Defensive SDK bound on an individual compact identity proof.
pub const MAX_IDENTITY_PROOF_SIZE: usize = 64 * 1024;

/// A failed or incomplete identity-verification decision.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IdentityVerificationError {
    /// The TL receipt did not verify.
    #[error("identity receipt verification failed: {0}")]
    Receipt(#[from] ScittError),
    /// Malformed sealed event or JOSE input.
    #[error("invalid identity evidence: {0}")]
    InvalidEvidence(&'static str),
    /// Required proof-event evidence is unavailable.
    #[error("incomplete identity evidence: {0}")]
    IncompleteEvidence(&'static str),
    /// An unsupported/deferred identity profile or key encoding.
    #[error("unsupported identity proof: {0}")]
    Unsupported(&'static str),
    /// An operator signature failed under the sealed public key.
    #[error("identity control signature is invalid")]
    SignatureInvalid,
    /// An identity or registration binding disagrees.
    #[error("identity evidence does not match: {0}")]
    BindingMismatch(&'static str),
    /// Revocation is permanent for this identity stream.
    #[error("identity is revoked")]
    Revoked,
    /// A current view does not attest VERIFIED status.
    #[error("identity is not currently VERIFIED")]
    NotVerified,
}

type Result<T> = std::result::Result<T, IdentityVerificationError>;

/// Verified historical possession proofs from one sealed proof event.
#[derive(Debug, Clone)]
pub struct VerifiedIdentityProof {
    identity_id: String,
    kind: IdentityKind,
    value: String,
    log_id: String,
    methods: Vec<Value>,
}
impl VerifiedIdentityProof {
    /// Identity stream identifier.
    pub fn identity_id(&self) -> &str {
        &self.identity_id
    }
    /// Identifier profile.
    pub const fn kind(&self) -> IdentityKind {
        self.kind
    }
    /// Canonical proven identifier.
    pub fn value(&self) -> &str {
        &self.value
    }
    /// Proof event's log identifier, used to match a current badge's keysLogId.
    pub fn log_id(&self) -> &str {
        &self.log_id
    }
    /// Verbatim methods whose possession proofs all verified.
    pub fn verification_methods(&self) -> &[Value] {
        &self.methods
    }
}

/// Verification state for one identity stream.
///
/// Feed observed events in log order when selecting the latest proof. Any known
/// revocation dominates every later event regardless of arrival order. This is
/// not an audit-completeness or checkpoint-consistency proof; current status
/// comes from a trusted TL badge and is checked separately with `verify_badge`.
#[derive(Debug)]
pub struct IdentityVerifier {
    identity_id: String,
    revoked: bool,
    proof: Option<VerifiedIdentityProof>,
}
impl IdentityVerifier {
    /// Bind the verifier to the requested identity before consuming evidence.
    pub fn new(identity_id: impl Into<String>) -> Result<Self> {
        let identity_id = identity_id.into();
        if identity_id.is_empty() {
            return Err(IdentityVerificationError::InvalidEvidence(
                "empty identityId",
            ));
        }
        Ok(Self {
            identity_id,
            revoked: false,
            proof: None,
        })
    }

    /// Verify a COSE receipt and observe its signed identity event.
    pub fn observe_receipt(&mut self, bytes: &[u8], keys: &ScittKeyStore) -> Result<()> {
        let receipt = verify_receipt(bytes, keys)?;
        let entry: IdentityBadge = serde_json::from_slice(&receipt.event_bytes).map_err(|_| {
            IdentityVerificationError::InvalidEvidence("receipt is not an identity envelope")
        })?;
        self.observe_trusted_entry(&entry)
    }

    /// Observe a proof/audit entry fetched from a configured trusted TL over HTTPS.
    ///
    /// This verifies every operator proof, but relies on the fetch channel for
    /// the TL envelope's provenance. For untrusted receipt bytes, use
    /// `observe_receipt` instead. A link-only entry is not proof evidence: fetch
    /// the proof event named by the current badge's `keysLogId` from its audit.
    pub fn observe_trusted_entry(&mut self, entry: &IdentityBadge) -> Result<()> {
        self.check_entry(entry)?;
        let event = &entry.payload.producer.event;
        match event.event_type {
            IdentityEventType::IdentityRevoked => {
                // Once authenticated, a revocation is never undone, even if a
                // later proof or a stale computed badge still says VERIFIED.
                self.revoked = true;
                self.proof = None;
            }
            IdentityEventType::IdentityVerified | IdentityEventType::IdentityUpdated => {
                let methods = verify_control_proofs(event)?;
                if !self.revoked {
                    self.proof = Some(VerifiedIdentityProof {
                        identity_id: event.identity_id.clone(),
                        kind: event.kind,
                        value: event.value.clone(),
                        log_id: entry.payload.log_id.clone(),
                        methods,
                    });
                }
            }
            IdentityEventType::IdentityLinked | IdentityEventType::IdentityUnlinked => {
                if event.ans_ids.is_empty() {
                    return Err(IdentityVerificationError::InvalidEvidence(
                        "link event has no ansIds",
                    ));
                }
            }
            _ => {
                return Err(IdentityVerificationError::Unsupported(
                    "unknown identity event",
                ));
            }
        }
        Ok(())
    }

    /// Whether authenticated evidence has ever revoked this identity.
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Bind verified historical proofs to a current badge fetched from a trusted TL.
    ///
    /// Revoked badges are remembered permanently. A valid historical receipt
    /// alone never proves that an identity remains verified today.
    pub fn verify_badge(&mut self, badge: &IdentityBadge) -> Result<&VerifiedIdentityProof> {
        self.check_entry(badge)?;
        if self.revoked
            || badge.status == "REVOKED"
            || badge.payload.producer.event.event_type == IdentityEventType::IdentityRevoked
        {
            self.revoked = true;
            self.proof = None;
            return Err(IdentityVerificationError::Revoked);
        }
        if badge.status != "VERIFIED" {
            return Err(IdentityVerificationError::NotVerified);
        }
        let proof = self
            .proof
            .as_ref()
            .ok_or(IdentityVerificationError::IncompleteEvidence(
                "fetch the signed proof event at keysLogId",
            ))?;
        let event = &badge.payload.producer.event;
        if event.kind != proof.kind || event.value != proof.value {
            return Err(IdentityVerificationError::BindingMismatch(
                "badge identifier",
            ));
        }
        if badge.keys_log_id.as_deref() != Some(proof.log_id.as_str()) {
            return Err(IdentityVerificationError::BindingMismatch("keysLogId"));
        }
        let ids: HashSet<_> = badge
            .keys
            .iter()
            .filter_map(|method| method.get("id").and_then(Value::as_str))
            .collect();
        if ids.len() != badge.keys.len()
            || badge.keys.len() != proof.methods.len()
            || !proof
                .methods
                .iter()
                .all(|method| badge.keys.contains(method))
        {
            return Err(IdentityVerificationError::BindingMismatch(
                "current verification methods",
            ));
        }
        Ok(proof)
    }

    fn check_entry(&self, entry: &IdentityBadge) -> Result<()> {
        if entry.schema_version != "V2" {
            return Err(IdentityVerificationError::Unsupported(
                "identity envelope must use V2",
            ));
        }
        if entry.payload.producer.event.identity_id != self.identity_id {
            return Err(IdentityVerificationError::BindingMismatch("identityId"));
        }
        if entry.payload.log_id.is_empty() {
            return Err(IdentityVerificationError::InvalidEvidence("empty logId"));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct JoseHeader {
    alg: String,
    kid: String,
    #[serde(flatten)]
    other: BTreeMap<String, Value>,
}

fn verify_control_proofs(event: &IdentityEvent) -> Result<Vec<Value>> {
    let ra_id = validate_proof_event(event)?;
    let mut kids = HashSet::new();
    let mut common_payload = None;
    let mut methods = Vec::new();
    for key in &event.keys {
        if key.signed_proof.len() > MAX_IDENTITY_PROOF_SIZE {
            return Err(IdentityVerificationError::InvalidEvidence(
                "proof exceeds 64 KiB",
            ));
        }
        let mut parts = key.signed_proof.split('.');
        let protected = parts.next().unwrap_or_default();
        let payload = parts
            .next()
            .ok_or(IdentityVerificationError::InvalidEvidence(
                "compact JWS structure",
            ))?;
        let signature = parts
            .next()
            .ok_or(IdentityVerificationError::InvalidEvidence(
                "compact JWS structure",
            ))?;
        if parts.next().is_some() {
            return Err(IdentityVerificationError::InvalidEvidence(
                "compact JWS structure",
            ));
        }
        let header: JoseHeader = serde_json::from_slice(&decode(protected)?)
            .map_err(|_| IdentityVerificationError::InvalidEvidence("JOSE header"))?;
        if header.other.contains_key("crit")
            || header
                .other
                .get("b64")
                .is_some_and(|v| v != &Value::Bool(true))
        {
            return Err(IdentityVerificationError::Unsupported(
                "critical or unencoded JOSE extension",
            ));
        }
        if header.kid.is_empty() || !kids.insert(header.kid.clone()) {
            return Err(IdentityVerificationError::InvalidEvidence(
                "missing or duplicate kid",
            ));
        }
        let input: IdentityProofInput = serde_json::from_slice(&decode(payload)?)
            .map_err(|_| IdentityVerificationError::InvalidEvidence("identity proof payload"))?;
        if decode(&input.nonce)?.len() != 32 {
            return Err(IdentityVerificationError::InvalidEvidence(
                "nonce must contain 32 bytes",
            ));
        }
        let expected = IdentityProofInput::new(
            &event.value,
            &event.identity_id,
            &input.nonce,
            ra_id,
            event.kind,
        );
        let canonical = serde_json_canonicalizer::to_vec(&expected)
            .map_err(|_| IdentityVerificationError::InvalidEvidence("canonical proof input"))?;
        if payload != BASE64_URL_SAFE_NO_PAD.encode(canonical) {
            return Err(IdentityVerificationError::BindingMismatch(
                "canonical IdentityProofInput",
            ));
        }
        if common_payload.is_some_and(|prior| prior != payload) {
            return Err(IdentityVerificationError::BindingMismatch(
                "keys must prove one challenge round",
            ));
        }
        common_payload = Some(payload);
        validate_method_binding(event, &key.verification_method, &header.kid)?;
        let message = format!("{protected}.{payload}");
        verify_method(
            &key.verification_method,
            &header.alg,
            message.as_bytes(),
            &decode(signature)?,
        )?;
        methods.push(key.verification_method.clone());
    }
    Ok(methods)
}

fn validate_proof_event(event: &IdentityEvent) -> Result<&str> {
    if !matches!(event.kind, IdentityKind::DidWeb | IdentityKind::DidKey) {
        return Err(IdentityVerificationError::Unsupported(
            "LEI and ENS proofs are postponed",
        ));
    }
    let proof_method = if event.kind == IdentityKind::DidKey {
        "did-key-sig"
    } else {
        "did-web-sig"
    };
    if event.proof_method.as_deref() != Some(proof_method) {
        return Err(IdentityVerificationError::InvalidEvidence(
            "proof method does not match identifier kind",
        ));
    }
    if event.verified_at.is_none()
        || event.provider_id.as_deref().is_none_or(str::is_empty)
        || !event.ans_ids.is_empty()
    {
        return Err(IdentityVerificationError::InvalidEvidence(
            "proof event metadata",
        ));
    }
    let ra_id = event.ra_id.as_deref().filter(|s| !s.is_empty()).ok_or(
        IdentityVerificationError::IncompleteEvidence(
            "sealed raId is required; do not infer it from the JWS",
        ),
    )?;
    if !(1..=16).contains(&event.keys.len()) {
        return Err(IdentityVerificationError::InvalidEvidence(
            "proof event must contain 1 through 16 keys",
        ));
    }
    if event.kind == IdentityKind::DidKey && event.keys.len() != 1 {
        return Err(IdentityVerificationError::InvalidEvidence(
            "did:key is single-key",
        ));
    }
    if !event
        .value
        .starts_with(&format!("{}:", event.kind.as_str()))
        || event.value.len() == event.kind.as_str().len() + 1
    {
        return Err(IdentityVerificationError::InvalidEvidence(
            "identifier kind/value mismatch",
        ));
    }
    Ok(ra_id)
}

fn validate_method_binding(
    event: &IdentityEvent,
    verification_method: &Value,
    kid: &str,
) -> Result<()> {
    let method =
        verification_method
            .as_object()
            .ok_or(IdentityVerificationError::InvalidEvidence(
                "verification method must be an object",
            ))?;
    if method.get("id").and_then(Value::as_str) != Some(kid) {
        return Err(IdentityVerificationError::BindingMismatch(
            "kid and sealed method id",
        ));
    }
    let prefix = format!("{}#", event.value);
    if !kid.starts_with(&prefix) || kid.len() == prefix.len() {
        return Err(IdentityVerificationError::BindingMismatch(
            "kid must belong to this DID",
        ));
    }
    if method
        .get("controller")
        .is_some_and(|v| v.as_str() != Some(event.value.as_str()))
    {
        return Err(IdentityVerificationError::BindingMismatch(
            "verification method controller",
        ));
    }
    if event.kind == IdentityKind::DidKey {
        let multibase = event
            .value
            .strip_prefix("did:key:")
            .ok_or(IdentityVerificationError::InvalidEvidence("did:key value"))?;
        if kid != format!("{}#{multibase}", event.value)
            || method.get("publicKeyMultibase").and_then(Value::as_str) != Some(multibase)
            || method.get("controller").and_then(Value::as_str) != Some(event.value.as_str())
            || method.get("type").and_then(Value::as_str) != Some("Multikey")
        {
            return Err(IdentityVerificationError::BindingMismatch(
                "did:key derived method",
            ));
        }
    }
    Ok(())
}

fn decode(value: &str) -> Result<Vec<u8>> {
    BASE64_URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| IdentityVerificationError::InvalidEvidence("base64url encoding"))
}

fn verify_method(method: &Value, alg: &str, message: &[u8], signature: &[u8]) -> Result<()> {
    match (method.get("publicKeyJwk"), method.get("publicKeyMultibase")) {
        (Some(jwk), None) => verify_jwk(jwk, alg, message, signature),
        (None, Some(Value::String(multibase))) => {
            verify_multibase(multibase, alg, message, signature)
        }
        (Some(jwk), Some(Value::String(multibase))) => {
            // The schema permits both representations. They must describe
            // the same public key, not merely supply competing alternatives.
            verify_jwk(jwk, alg, message, signature)?;
            verify_multibase(multibase, alg, message, signature)?;
            if !same_public_key(jwk, multibase)? {
                return Err(IdentityVerificationError::BindingMismatch(
                    "public key representations",
                ));
            }
            Ok(())
        }
        _ => Err(IdentityVerificationError::InvalidEvidence(
            "missing or malformed public key representation",
        )),
    }
}

fn verify_multibase(multibase: &str, alg: &str, message: &[u8], signature: &[u8]) -> Result<()> {
    let (code, key) = decode_multikey(multibase)?;
    match (code, alg) {
        (0xed, "EdDSA") if key.len() == 32 => verify_ed25519(&key, message, signature),
        (0x1200, "ES256") => verify_p256(&key, message, signature),
        (0x1205, "RS256") => ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            key,
        )
        .verify(message, signature)
        .map_err(|_| IdentityVerificationError::SignatureInvalid),
        _ => Err(IdentityVerificationError::Unsupported(
            "multicodec/algorithm combination",
        )),
    }
}

fn same_public_key(jwk: &Value, multibase: &str) -> Result<bool> {
    let part = |name| {
        decode(jwk.get(name).and_then(Value::as_str).ok_or(
            IdentityVerificationError::InvalidEvidence("missing JWK parameter"),
        )?)
    };
    let (code, key) = decode_multikey(multibase)?;
    match code {
        0xed => Ok(part("x")? == key),
        0x1200 => {
            let key = VerifyingKey::from_sec1_bytes(&key)
                .map_err(|_| IdentityVerificationError::InvalidEvidence("P-256 key"))?;
            let mut expected = vec![4];
            expected.extend(part("x")?);
            expected.extend(part("y")?);
            Ok(key.to_sec1_point(false).as_bytes() == expected)
        }
        0x1205 => {
            use x509_parser::prelude::FromDer as _;
            let (rest, rsa) = x509_parser::public_key::RSAPublicKey::from_der(&key)
                .map_err(|_| IdentityVerificationError::InvalidEvidence("RSA public key"))?;
            let n = rsa.modulus.strip_prefix(&[0]).unwrap_or(rsa.modulus);
            let e = rsa.exponent.strip_prefix(&[0]).unwrap_or(rsa.exponent);
            Ok(rest.is_empty() && n == part("n")? && e == part("e")?)
        }
        _ => Err(IdentityVerificationError::Unsupported("multicodec")),
    }
}

fn verify_jwk(jwk: &Value, alg: &str, message: &[u8], signature: &[u8]) -> Result<()> {
    let object = jwk
        .as_object()
        .ok_or(IdentityVerificationError::InvalidEvidence(
            "public JWK must be an object",
        ))?;
    if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
        .iter()
        .any(|name| object.contains_key(*name))
    {
        return Err(IdentityVerificationError::InvalidEvidence(
            "private JWK parameters",
        ));
    }
    let bytes = |name| -> Result<Vec<u8>> {
        decode(object.get(name).and_then(Value::as_str).ok_or(
            IdentityVerificationError::InvalidEvidence("missing public JWK parameter"),
        )?)
    };
    match (object.get("kty").and_then(Value::as_str), alg) {
        (Some("OKP"), "EdDSA") if object.get("crv").and_then(Value::as_str) == Some("Ed25519") => {
            let key = bytes("x")?;
            if key.len() != 32 {
                return Err(IdentityVerificationError::InvalidEvidence(
                    "Ed25519 key length",
                ));
            }
            verify_ed25519(&key, message, signature)
        }
        (Some("EC"), "ES256") if object.get("crv").and_then(Value::as_str) == Some("P-256") => {
            let x = bytes("x")?;
            let y = bytes("y")?;
            if x.len() != 32 || y.len() != 32 {
                return Err(IdentityVerificationError::InvalidEvidence(
                    "P-256 coordinate width",
                ));
            }
            let mut key = vec![4];
            key.extend(x);
            key.extend(y);
            verify_p256(&key, message, signature)
        }
        (Some("RSA"), "RS256") => {
            let n = bytes("n")?;
            let e = bytes("e")?;
            if n.first().is_none_or(|b| *b == 0) || e.first().is_none_or(|b| *b == 0) {
                return Err(IdentityVerificationError::InvalidEvidence(
                    "RSA integers must be minimally encoded",
                ));
            }
            ring::signature::RsaPublicKeyComponents { n: &n, e: &e }
                .verify(
                    &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                    message,
                    signature,
                )
                .map_err(|_| IdentityVerificationError::SignatureInvalid)
        }
        _ => Err(IdentityVerificationError::Unsupported(
            "public key type/curve/algorithm combination",
        )),
    }
}

fn verify_ed25519(key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(message, signature)
        .map_err(|_| IdentityVerificationError::SignatureInvalid)
}

fn verify_p256(key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let key = VerifyingKey::from_sec1_bytes(key)
        .map_err(|_| IdentityVerificationError::InvalidEvidence("P-256 key"))?;
    let signature = Signature::from_slice(signature).map_err(|_| {
        IdentityVerificationError::InvalidEvidence("ES256 signature must use P1363")
    })?;
    if !crate::p256_verify::verify_p256_sha256(&key, message, &signature) {
        return Err(IdentityVerificationError::SignatureInvalid);
    }
    Ok(())
}

fn decode_multikey(value: &str) -> Result<(u64, Vec<u8>)> {
    let encoded = value
        .strip_prefix('z')
        .ok_or(IdentityVerificationError::Unsupported(
            "Multikey must use base58btc",
        ))?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| IdentityVerificationError::InvalidEvidence("base58btc key"))?;
    let mut code = 0u64;
    for (i, byte) in bytes.iter().copied().take(10).enumerate() {
        if i == 9 && byte > 1 {
            break;
        }
        code |= u64::from(byte & 0x7f) << (i * 7);
        if byte & 0x80 == 0 {
            if i > 0 && byte == 0 {
                break;
            }
            return Ok((code, bytes[i + 1..].to_vec()));
        }
    }
    Err(IdentityVerificationError::InvalidEvidence(
        "multicodec prefix",
    ))
}

#[cfg(test)]
mod tests;
