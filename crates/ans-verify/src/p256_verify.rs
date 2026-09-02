//! ECDSA P-256 (ES256) signature-verification backend.
//!
//! The default backend is the pure-Rust `p256` crate, keeping the dependency
//! tree free of native code. The `fast-verify` feature swaps verification to
//! `ring`'s assembly implementation (~3x faster on typical hardware) — the
//! same backend the `rustls` feature already links for TLS. Signing stays on
//! `p256` either way; verification dominates every hot path.

use p256::ecdsa::{Signature, VerifyingKey};

/// Verify an ECDSA P-256 signature over `SHA-256(message)`.
///
/// `signature` is the fixed-width `R || S` form that both COSE (RFC 9053)
/// and JWS ES256 (RFC 7518 §3.4) carry on the wire.
#[cfg(feature = "fast-verify")]
pub fn verify_p256_sha256(key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    let point = key.to_sec1_point(false);
    let sig_bytes = signature.to_bytes();
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        point.as_bytes(),
    )
    .verify(message, sig_bytes.as_ref())
    .is_ok()
}

/// Verify an ECDSA P-256 signature over `SHA-256(message)`.
///
/// `signature` is the fixed-width `R || S` form that both COSE (RFC 9053)
/// and JWS ES256 (RFC 7518 §3.4) carry on the wire.
#[cfg(not(feature = "fast-verify"))]
pub fn verify_p256_sha256(key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    key.verify(message, signature).is_ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};

    use super::verify_p256_sha256;

    #[test]
    fn accepts_valid_signature_and_rejects_tampering() {
        let key = SigningKey::from_slice(&[42u8; 32]).unwrap();
        let message = b"backend equivalence check";
        let signature: Signature = key.sign(message);

        assert!(verify_p256_sha256(key.verifying_key(), message, &signature));
        assert!(!verify_p256_sha256(
            key.verifying_key(),
            b"different message",
            &signature
        ));

        let other = SigningKey::from_slice(&[43u8; 32]).unwrap();
        assert!(!verify_p256_sha256(
            other.verifying_key(),
            message,
            &signature
        ));
    }
}
