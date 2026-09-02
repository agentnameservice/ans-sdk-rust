//! Compact-JWS ES256 mechanics for `DPoP` proofs (RFC 7515 / RFC 7518).

use base64::Engine as _;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use super::error::{PopError, PopErrorKind};

/// Fixed length of a P-256 ES256 signature (`R ‖ S`).
pub const P256_SIG_LEN: usize = 64;
/// Big-endian length of each of `R` and `S` (and of each JWK coordinate).
pub const COORD_LEN: usize = 32;

pub fn b64url_encode(bytes: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>, PopError> {
    BASE64_URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| PopError::with_source(PopErrorKind::MalformedProof, "base64url decode", e))
}

pub fn split_compact_jws(token: &str) -> Result<(&str, &str, &str), PopError> {
    let mut parts = token.split('.');
    let header = parts.next();
    let payload = parts.next();
    let signature = parts.next();
    let extra = parts.next();
    match (header, payload, signature, extra) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() && !s.is_empty() => {
            Ok((h, p, s))
        }
        _ => Err(PopError::new(
            PopErrorKind::MalformedProof,
            "compact JWS must have 3 non-empty segments",
        )),
    }
}

pub fn jws_signing_input(header_b64: &str, payload_b64: &str) -> String {
    format!("{header_b64}.{payload_b64}")
}

pub fn sign_es256(key: &SigningKey, signing_input: &[u8]) -> Result<String, PopError> {
    let digest = Sha256::digest(signing_input);
    let (sig, _): (Signature, _) = key
        .sign_prehash(&digest)
        .map_err(|e| PopError::with_source(PopErrorKind::SignatureInvalid, "ecdsa sign", e))?;
    Ok(b64url_encode(&sig.to_bytes()))
}

pub fn verify_es256(
    pub_key: &VerifyingKey,
    signing_input: &[u8],
    sig_b64: &str,
) -> Result<(), PopError> {
    let sig = b64url_decode(sig_b64)?;
    if sig.len() != P256_SIG_LEN {
        return Err(PopError::new(
            PopErrorKind::SignatureInvalid,
            format!(
                "signature must be {P256_SIG_LEN} bytes (R‖S), got {}",
                sig.len()
            ),
        ));
    }
    let signature = Signature::from_slice(&sig).map_err(|_| {
        PopError::new(
            PopErrorKind::SignatureInvalid,
            "signature is not a valid P1363 encoding",
        )
    })?;
    if crate::p256_verify::verify_p256_sha256(pub_key, signing_input, &signature) {
        Ok(())
    } else {
        Err(PopError::new(
            PopErrorKind::SignatureInvalid,
            "ECDSA signature verification failed",
        ))
    }
}
