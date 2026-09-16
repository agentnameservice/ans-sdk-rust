//! ECDSA P-256 (ES256) signature-verification backend.
//!
//! The default verification backend is `p256`. The `fast-verify` feature uses
//! `ring` instead; signing stays on `p256`. Both verification paths are tested
//! in CI. The networking dependency graph already includes native code
//! regardless of this feature; compare performance on the deployment target
//! with `benches/scitt_verification.rs`.

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
    fn rfc6979_p256_sha256_known_answer() {
        // RFC 6979 Appendix A.2.5, SHA-256 with message "sample".
        // Fixed public key/signature from the RFC, independent of our signer.
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(
            &hex::decode(concat!(
                "04",
                "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
                "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
            ))
            .unwrap(),
        )
        .unwrap();
        let signature = Signature::from_slice(
            &hex::decode(concat!(
                "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
                "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
            ))
            .unwrap(),
        )
        .unwrap();
        assert!(verify_p256_sha256(&key, b"sample", &signature));
        assert!(!verify_p256_sha256(&key, b"tampered", &signature));
    }

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
