//! `COSE_Sign1` parsing for SCITT receipts and status tokens.
//!
//! Implements parsing of `COSE_Sign1` structures (RFC 9052) using `ciborium`
//! for CBOR decoding. Provides the byte-level primitives needed for ECDSA
//! signature verification: [`parse_cose_sign1`], [`build_sig_structure`],
//! and [`compute_sig_structure_digest`].
//!
//! # Wire format
//!
//! `COSE_Sign1` is either:
//! - CBOR Tag 18 wrapping a 4-element array, or
//! - An untagged 4-element array (RFC 9052 §4.2)
//!
//! The 4 elements are:
//! 1. `protected` — bstr-wrapped CBOR map of protected header fields
//! 2. `unprotected` — CBOR map of unprotected header fields
//! 3. `payload` — bstr (attached) or null (detached; not supported here)
//! 4. `signature` — bstr, exactly 64 bytes for ES256 P1363 format

use std::io::Cursor;

#[cfg(any(test, feature = "test-support"))]
use sha2::{Digest, Sha256};

use super::error::ScittError;

/// Maximum allowed `COSE_Sign1` input size (1 MiB).
pub const MAX_COSE_INPUT_SIZE: usize = 1024 * 1024;

/// A parsed `COSE_Sign1` structure (CBOR Tag 18 or untagged array).
#[derive(Debug, Clone)]
pub struct ParsedCoseSign1 {
    /// Raw protected header bytes (preserved verbatim for `Sig_structure`).
    pub protected_bytes: Vec<u8>,
    /// Decoded protected header fields.
    pub protected: ProtectedHeader,
    /// Unprotected header as raw CBOR Value (may contain VDP at label 396).
    pub unprotected: ciborium::Value,
    /// Payload bytes (attached, not detached/Null).
    pub payload: Vec<u8>,
    /// Signature bytes (exactly 64 bytes for P1363 ES256).
    pub signature: Vec<u8>,
}

/// Decoded fields from the COSE protected header.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields are populated during parsing; used by tests and for completeness
pub struct ProtectedHeader {
    /// Algorithm: must be -7 (ES256).
    pub alg: i64,
    /// Key ID: 4 bytes.
    pub kid: [u8; 4],
    /// Verification Data Structure: 1 = `RFC9162_SHA256` (present in receipts).
    pub vds: Option<i64>,
    /// Content type (present in status tokens).
    pub content_type: Option<String>,
    /// CWT claims (label 15): issuer (`iss`, CWT key 1).
    pub cwt_iss: Option<String>,
    /// CWT claims (label 15): issued-at (`iat`, CWT key 6) as Unix seconds.
    pub cwt_iat: Option<i64>,
}

/// Parse a `COSE_Sign1` structure from raw bytes.
///
/// Accepts both CBOR Tag 18 and untagged 4-element array forms (RFC 9052 §4.2).
/// Detached payloads (`null`) are not supported.
///
/// # Errors
///
/// - [`ScittError::OversizedInput`] if `bytes.len() > MAX_COSE_INPUT_SIZE`
/// - [`ScittError::CborDecodeError`] if the bytes are not valid CBOR
/// - [`ScittError::NotACoseSign1`] if the top-level CBOR is not Tag(18) or an array
/// - [`ScittError::InvalidArrayLength`] if the array does not have exactly 4 elements
/// - [`ScittError::InvalidProtectedHeader`] if the protected header is malformed
/// - [`ScittError::UnsupportedAlgorithm`] if `alg` is not -7 (ES256)
/// - [`ScittError::MissingKid`] if the `kid` field is absent
/// - [`ScittError::InvalidSignatureLength`] if the signature is not 64 bytes
pub fn parse_cose_sign1(bytes: &[u8]) -> Result<ParsedCoseSign1, ScittError> {
    // Step 1: size check
    if bytes.len() > MAX_COSE_INPUT_SIZE {
        return Err(ScittError::OversizedInput {
            max_bytes: MAX_COSE_INPUT_SIZE,
        });
    }

    // Step 2: CBOR decode — reject trailing bytes (RFC 9052 §2)
    let mut cursor = Cursor::new(bytes);
    let value: ciborium::Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|e| ScittError::CborDecodeError(e.to_string()))?;
    // usize → u64 is infallible on all supported platforms (32-bit and 64-bit)
    if cursor.position() != bytes.len() as u64 {
        return Err(ScittError::CborDecodeError(
            "trailing bytes after COSE_Sign1".to_string(),
        ));
    }

    // Step 3: unwrap Tag(18) or accept untagged array
    let inner = match value {
        ciborium::Value::Tag(18, boxed) => *boxed,
        ciborium::Value::Array(_) => value,
        _ => return Err(ScittError::NotACoseSign1),
    };

    // Step 4: extract 4-element array
    let ciborium::Value::Array(array) = inner else {
        return Err(ScittError::NotACoseSign1);
    };

    if array.len() != 4 {
        return Err(ScittError::InvalidArrayLength { found: array.len() });
    }

    let mut iter = array.into_iter();

    // Element 0: protected header bytes (bstr)
    let Some(ciborium::Value::Bytes(protected_bytes)) = iter.next() else {
        return Err(ScittError::InvalidProtectedHeader(
            "protected header must be a bstr".to_string(),
        ));
    };

    // Element 1: unprotected header (CBOR map)
    let unprotected = iter.next().ok_or_else(|| {
        ScittError::InvalidProtectedHeader("missing unprotected header".to_string())
    })?;

    // Element 2: payload (bstr, not null)
    let payload = match iter.next() {
        Some(ciborium::Value::Bytes(b)) => b,
        Some(ciborium::Value::Null) => {
            return Err(ScittError::InvalidProtectedHeader(
                "detached payload (null) is not supported".to_string(),
            ));
        }
        _ => {
            return Err(ScittError::InvalidProtectedHeader(
                "payload must be a bstr".to_string(),
            ));
        }
    };

    // Element 3: signature (bstr, exactly 64 bytes)
    let Some(ciborium::Value::Bytes(signature)) = iter.next() else {
        return Err(ScittError::InvalidProtectedHeader(
            "signature must be a bstr".to_string(),
        ));
    };

    if signature.len() != 64 {
        return Err(ScittError::InvalidSignatureLength {
            actual: signature.len(),
        });
    }

    // Step 5: decode protected header bytes as CBOR map
    let protected = decode_protected_header(&protected_bytes)?;

    Ok(ParsedCoseSign1 {
        protected_bytes,
        protected,
        unprotected,
        payload,
        signature,
    })
}

/// Decode the protected header bstr into [`ProtectedHeader`].
fn decode_protected_header(bytes: &[u8]) -> Result<ProtectedHeader, ScittError> {
    if bytes.is_empty() {
        return Err(ScittError::InvalidProtectedHeader(
            "protected header bytes are empty".to_string(),
        ));
    }

    let mut cursor = Cursor::new(bytes);
    let value: ciborium::Value = ciborium::de::from_reader(&mut cursor)
        .map_err(|e| ScittError::InvalidProtectedHeader(format!("CBOR decode: {e}")))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(ScittError::InvalidProtectedHeader(
            "trailing bytes after protected header".to_string(),
        ));
    }

    let ciborium::Value::Map(map) = value else {
        return Err(ScittError::InvalidProtectedHeader(
            "protected header must be a CBOR map".to_string(),
        ));
    };

    let mut alg: Option<i64> = None;
    let mut kid: Option<Vec<u8>> = None;
    let mut vds: Option<i64> = None;
    let mut content_type: Option<String> = None;
    let mut cwt_iss: Option<String> = None;
    let mut cwt_iat: Option<i64> = None;

    for (k, v) in map {
        let label = cbor_value_to_i64(&k);
        match label {
            Some(1) => {
                // alg
                alg = cbor_value_to_i64(&v);
            }
            Some(3) => {
                // content_type
                if let ciborium::Value::Text(s) = v {
                    content_type = Some(s);
                }
            }
            Some(4) => {
                // kid
                if let ciborium::Value::Bytes(b) = v {
                    kid = Some(b);
                }
            }
            Some(15) => {
                // CWT claims (RFC 8392): nested CBOR map
                // key 1 = iss (text), key 6 = iat (integer)
                if let ciborium::Value::Map(cwt_map) = v {
                    for (ck, cv) in cwt_map {
                        match cbor_value_to_i64(&ck) {
                            Some(1) => {
                                if let ciborium::Value::Text(s) = cv {
                                    cwt_iss = Some(s);
                                }
                            }
                            Some(6) => {
                                cwt_iat = cbor_value_to_i64(&cv);
                            }
                            _ => {}
                        }
                    }
                }
            }
            Some(395) => {
                // vds
                vds = cbor_value_to_i64(&v);
            }
            _ => {}
        }
    }

    // Validate alg: must be -7 (ES256)
    let alg = match alg {
        None => {
            return Err(ScittError::InvalidProtectedHeader(
                "missing alg field (label 1)".to_string(),
            ));
        }
        Some(v) if v == -7 => v,
        Some(other) => {
            return Err(ScittError::UnsupportedAlgorithm(format!(
                "{other} (only ES256/-7 is supported)"
            )));
        }
    };

    // Validate kid: must be present and exactly 4 bytes
    let kid_vec = kid.ok_or(ScittError::MissingKid)?;
    if kid_vec.len() != 4 {
        return Err(ScittError::InvalidProtectedHeader(format!(
            "kid must be 4 bytes, got {}",
            kid_vec.len()
        )));
    }
    let kid: [u8; 4] = [kid_vec[0], kid_vec[1], kid_vec[2], kid_vec[3]];

    Ok(ProtectedHeader {
        alg,
        kid,
        vds,
        content_type,
        cwt_iss,
        cwt_iat,
    })
}

/// Convert a `ciborium::Value` integer (positive or negative) to `i64`, if possible.
fn cbor_value_to_i64(v: &ciborium::Value) -> Option<i64> {
    match v {
        ciborium::Value::Integer(i) => i128::from(*i).try_into().ok(),
        _ => None,
    }
}

/// Build the `Sig_structure` for ECDSA verification (RFC 9052 Section 4.4).
///
/// CRITICAL: Uses `protected_bytes` verbatim (never re-encoded).
///
/// The `Sig_structure` is:
/// ```text
/// CBOR_Array [
///     "Signature1",   // text string
///     protected,      // bstr (exact bytes as received)
///     h'',            // empty external_aad (bstr)
///     payload,        // bstr
/// ]
/// ```
pub fn build_sig_structure(protected_bytes: &[u8], payload: &[u8]) -> Result<Vec<u8>, ScittError> {
    let sig_structure = ciborium::Value::Array(vec![
        ciborium::Value::Text("Signature1".to_string()),
        ciborium::Value::Bytes(protected_bytes.to_vec()),
        ciborium::Value::Bytes(vec![]), // empty external_aad
        ciborium::Value::Bytes(payload.to_vec()),
    ]);

    let mut out = Vec::new();
    ciborium::ser::into_writer(&sig_structure, &mut out)
        .map_err(|e| ScittError::CborDecodeError(format!("Sig_structure serialization: {e}")))?;
    Ok(out)
}

/// Returns the SHA-256 digest of the `Sig_structure`, ready for ECDSA
/// `sign_prehash` — used by test fixtures that mint COSE artifacts.
/// Verification hashes via the backend in `crate::p256_verify` instead.
///
/// # Errors
///
/// Returns [`ScittError::CborDecodeError`] if CBOR serialization fails (should not
/// happen with well-formed inputs).
#[cfg(any(test, feature = "test-support"))]
pub fn compute_sig_structure_digest(
    protected_bytes: &[u8],
    payload: &[u8],
) -> Result<[u8; 32], ScittError> {
    let sig_structure_bytes = build_sig_structure(protected_bytes, payload)?;
    let digest = Sha256::digest(&sig_structure_bytes);
    Ok(digest.into())
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper: build a minimal valid COSE_Sign1 as bytes ──────────────────

    /// Build a protected header CBOR map and return its raw bytes.
    fn make_protected_bytes(alg: i64, kid: &[u8], vds: Option<i64>, ct: Option<&str>) -> Vec<u8> {
        let mut pairs: Vec<(ciborium::Value, ciborium::Value)> = vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer(alg.into()),
            ),
            (
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Bytes(kid.to_vec()),
            ),
        ];
        if let Some(v) = vds {
            pairs.push((
                ciborium::Value::Integer(395.into()),
                ciborium::Value::Integer(v.into()),
            ));
        }
        if let Some(s) = ct {
            pairs.push((
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Text(s.to_string()),
            ));
        }
        let map = ciborium::Value::Map(pairs);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        buf
    }

    /// Build a serialized COSE_Sign1 4-element array (no tag).
    fn make_cose_sign1_bytes(
        protected_bytes: Vec<u8>,
        payload: Vec<u8>,
        signature: Vec<u8>,
        tagged: bool,
    ) -> Vec<u8> {
        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            ciborium::Value::Map(vec![]),
            ciborium::Value::Bytes(payload),
            ciborium::Value::Bytes(signature),
        ]);
        let value = if tagged {
            ciborium::Value::Tag(18, Box::new(array))
        } else {
            array
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&value, &mut buf).unwrap();
        buf
    }

    fn valid_kid() -> Vec<u8> {
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    }

    fn valid_signature() -> Vec<u8> {
        vec![0u8; 64]
    }

    fn valid_payload() -> Vec<u8> {
        b"test payload".to_vec()
    }

    // ── Valid parsing ───────────────────────────────────────────────────────

    #[test]
    fn valid_receipt_parsing() {
        let protected_bytes = make_protected_bytes(-7, &valid_kid(), Some(1), None);
        let bytes = make_cose_sign1_bytes(
            protected_bytes.clone(),
            valid_payload(),
            valid_signature(),
            false,
        );
        let parsed = parse_cose_sign1(&bytes).unwrap();
        assert_eq!(parsed.protected_bytes, protected_bytes);
        assert_eq!(parsed.protected.alg, -7);
        assert_eq!(parsed.protected.kid, [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(parsed.protected.vds, Some(1));
        assert!(parsed.protected.content_type.is_none());
        assert_eq!(parsed.payload, valid_payload());
        assert_eq!(parsed.signature.len(), 64);
    }

    #[test]
    fn valid_status_token_parsing() {
        let protected_bytes =
            make_protected_bytes(-7, &valid_kid(), None, Some("application/json"));
        let bytes = make_cose_sign1_bytes(
            protected_bytes.clone(),
            valid_payload(),
            valid_signature(),
            false,
        );
        let parsed = parse_cose_sign1(&bytes).unwrap();
        assert_eq!(parsed.protected.alg, -7);
        assert_eq!(parsed.protected.vds, None);
        assert_eq!(
            parsed.protected.content_type.as_deref(),
            Some("application/json")
        );
    }

    #[test]
    fn cwt_claims_parsed_from_label_15() {
        // Build a protected header with CWT claims at label 15
        let cwt_claims = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Text("tl.example.com".to_string()),
            ),
            (
                ciborium::Value::Integer(6.into()),
                ciborium::Value::Integer(1_700_000_000_i64.into()),
            ),
        ]);
        let pairs: Vec<(ciborium::Value, ciborium::Value)> = vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer((-7_i64).into()),
            ),
            (
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Bytes(valid_kid()),
            ),
            (
                ciborium::Value::Integer(395.into()),
                ciborium::Value::Integer(1.into()),
            ),
            (ciborium::Value::Integer(15.into()), cwt_claims),
        ];
        let map = ciborium::Value::Map(pairs);
        let mut protected_bytes = Vec::new();
        ciborium::ser::into_writer(&map, &mut protected_bytes).unwrap();

        let bytes =
            make_cose_sign1_bytes(protected_bytes, valid_payload(), valid_signature(), false);
        let parsed = parse_cose_sign1(&bytes).unwrap();
        assert_eq!(parsed.protected.cwt_iss.as_deref(), Some("tl.example.com"));
        assert_eq!(parsed.protected.cwt_iat, Some(1_700_000_000));
    }

    #[test]
    fn cwt_claims_absent_returns_none() {
        let protected_bytes = make_protected_bytes(-7, &valid_kid(), Some(1), None);
        let bytes =
            make_cose_sign1_bytes(protected_bytes, valid_payload(), valid_signature(), false);
        let parsed = parse_cose_sign1(&bytes).unwrap();
        assert!(parsed.protected.cwt_iss.is_none());
        assert!(parsed.protected.cwt_iat.is_none());
    }

    #[test]
    fn tag_18_and_untagged_both_work() {
        let protected_bytes = make_protected_bytes(-7, &valid_kid(), None, None);
        let payload = valid_payload();
        let sig = valid_signature();

        // Untagged
        let untagged =
            make_cose_sign1_bytes(protected_bytes.clone(), payload.clone(), sig.clone(), false);
        let r1 = parse_cose_sign1(&untagged).unwrap();
        assert_eq!(r1.protected.alg, -7);

        // Tagged
        let tagged =
            make_cose_sign1_bytes(protected_bytes.clone(), payload.clone(), sig.clone(), true);
        let r2 = parse_cose_sign1(&tagged).unwrap();
        assert_eq!(r2.protected.alg, -7);
    }

    // ── Error: input too large ──────────────────────────────────────────────

    #[test]
    fn error_input_too_large() {
        let big = vec![0u8; MAX_COSE_INPUT_SIZE + 1];
        let err = parse_cose_sign1(&big).unwrap_err();
        assert!(matches!(
            err,
            ScittError::OversizedInput {
                max_bytes: MAX_COSE_INPUT_SIZE
            }
        ));
    }

    // ── Error: not CBOR ─────────────────────────────────────────────────────

    #[test]
    fn error_not_cbor() {
        // 0xFF is an invalid CBOR initial byte — guaranteed decode failure.
        let bytes = &[0xFF, 0xFF, 0xFF, 0xFF];
        let err = parse_cose_sign1(bytes).unwrap_err();
        assert!(matches!(err, ScittError::CborDecodeError(_)));
    }

    // ── Error: valid CBOR but not array or Tag(18) ──────────────────────────

    #[test]
    fn error_valid_cbor_not_array_or_tag() {
        // CBOR integer 42
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&ciborium::Value::Integer(42.into()), &mut buf).unwrap();
        let err = parse_cose_sign1(&buf).unwrap_err();
        assert!(matches!(err, ScittError::NotACoseSign1));
    }

    // ── Error: wrong array length ───────────────────────────────────────────

    #[test]
    fn error_array_3_elements() {
        let arr = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(vec![]),
            ciborium::Value::Map(vec![]),
            ciborium::Value::Bytes(vec![]),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&arr, &mut buf).unwrap();
        let err = parse_cose_sign1(&buf).unwrap_err();
        assert!(matches!(err, ScittError::InvalidArrayLength { found: 3 }));
    }

    #[test]
    fn error_array_5_elements() {
        let arr = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(vec![]),
            ciborium::Value::Map(vec![]),
            ciborium::Value::Bytes(vec![]),
            ciborium::Value::Bytes(vec![]),
            ciborium::Value::Bytes(vec![]),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&arr, &mut buf).unwrap();
        let err = parse_cose_sign1(&buf).unwrap_err();
        assert!(matches!(err, ScittError::InvalidArrayLength { found: 5 }));
    }

    // ── Error: detached payload (null) ─────────────────────────────────────

    #[test]
    fn error_detached_payload_null() {
        let protected_bytes = make_protected_bytes(-7, &valid_kid(), None, None);
        let arr = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            ciborium::Value::Map(vec![]),
            ciborium::Value::Null,
            ciborium::Value::Bytes(valid_signature()),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&arr, &mut buf).unwrap();
        let err = parse_cose_sign1(&buf).unwrap_err();
        assert!(matches!(err, ScittError::InvalidProtectedHeader(_)));
        assert!(err.to_string().contains("detached"));
    }

    // ── Error: signature wrong length ───────────────────────────────────────

    #[test]
    fn error_signature_32_bytes() {
        let protected_bytes = make_protected_bytes(-7, &valid_kid(), None, None);
        let bytes = make_cose_sign1_bytes(protected_bytes, valid_payload(), vec![0u8; 32], false);
        let err = parse_cose_sign1(&bytes).unwrap_err();
        assert!(matches!(
            err,
            ScittError::InvalidSignatureLength { actual: 32 }
        ));
    }

    #[test]
    fn error_signature_128_bytes() {
        let protected_bytes = make_protected_bytes(-7, &valid_kid(), None, None);
        let bytes = make_cose_sign1_bytes(protected_bytes, valid_payload(), vec![0u8; 128], false);
        let err = parse_cose_sign1(&bytes).unwrap_err();
        assert!(matches!(
            err,
            ScittError::InvalidSignatureLength { actual: 128 }
        ));
    }

    // ── Error: protected header missing alg ─────────────────────────────────

    #[test]
    fn error_protected_header_missing_alg() {
        // Build a protected header map without alg (label 1)
        let map = ciborium::Value::Map(vec![(
            ciborium::Value::Integer(4.into()),
            ciborium::Value::Bytes(valid_kid()),
        )]);
        let mut protected_bytes = Vec::new();
        ciborium::ser::into_writer(&map, &mut protected_bytes).unwrap();
        let bytes =
            make_cose_sign1_bytes(protected_bytes, valid_payload(), valid_signature(), false);
        let err = parse_cose_sign1(&bytes).unwrap_err();
        assert!(matches!(err, ScittError::InvalidProtectedHeader(_)));
        assert!(err.to_string().contains("alg"));
    }

    // ── Error: wrong alg (not -7) ───────────────────────────────────────────

    #[test]
    fn error_wrong_alg() {
        // alg = -35 (ES384) instead of -7
        let protected_bytes = make_protected_bytes(-35, &valid_kid(), None, None);
        let bytes =
            make_cose_sign1_bytes(protected_bytes, valid_payload(), valid_signature(), false);
        let err = parse_cose_sign1(&bytes).unwrap_err();
        assert!(matches!(err, ScittError::UnsupportedAlgorithm(_)));
        assert!(err.to_string().contains("-35"));
    }

    // ── Error: missing kid ──────────────────────────────────────────────────

    #[test]
    fn error_missing_kid() {
        // Build a protected header map without kid (label 4)
        let map = ciborium::Value::Map(vec![(
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Integer((-7_i64).into()),
        )]);
        let mut protected_bytes = Vec::new();
        ciborium::ser::into_writer(&map, &mut protected_bytes).unwrap();
        let bytes =
            make_cose_sign1_bytes(protected_bytes, valid_payload(), valid_signature(), false);
        let err = parse_cose_sign1(&bytes).unwrap_err();
        assert!(matches!(err, ScittError::MissingKid));
    }

    // ── Error: kid wrong length ─────────────────────────────────────────────

    #[test]
    fn error_kid_3_bytes() {
        let protected_bytes = make_protected_bytes(-7, &[0x01, 0x02, 0x03], None, None);
        let bytes =
            make_cose_sign1_bytes(protected_bytes, valid_payload(), valid_signature(), false);
        let err = parse_cose_sign1(&bytes).unwrap_err();
        assert!(matches!(err, ScittError::InvalidProtectedHeader(_)));
        assert!(err.to_string().contains("4 bytes"));
    }

    #[test]
    fn error_kid_5_bytes() {
        let protected_bytes = make_protected_bytes(-7, &[0x01, 0x02, 0x03, 0x04, 0x05], None, None);
        let bytes =
            make_cose_sign1_bytes(protected_bytes, valid_payload(), valid_signature(), false);
        let err = parse_cose_sign1(&bytes).unwrap_err();
        assert!(matches!(err, ScittError::InvalidProtectedHeader(_)));
        assert!(err.to_string().contains("4 bytes"));
    }

    // ── Sig_structure construction ──────────────────────────────────────────

    #[test]
    fn sig_structure_matches_expected_cbor() {
        let protected_bytes = b"\xa1\x01\x26"; // minimal: {1: -7}
        let payload = b"hello";

        let sig_structure = build_sig_structure(protected_bytes, payload).unwrap();

        // Decode it and verify the structure
        let decoded: ciborium::Value = ciborium::de::from_reader(sig_structure.as_slice()).unwrap();
        match decoded {
            ciborium::Value::Array(arr) => {
                assert_eq!(arr.len(), 4);
                assert_eq!(arr[0], ciborium::Value::Text("Signature1".to_string()));
                assert_eq!(arr[1], ciborium::Value::Bytes(protected_bytes.to_vec()));
                assert_eq!(arr[2], ciborium::Value::Bytes(vec![]));
                assert_eq!(arr[3], ciborium::Value::Bytes(payload.to_vec()));
            }
            other => panic!("Expected Array, got: {other:?}"),
        }
    }

    #[test]
    fn sig_structure_uses_protected_bytes_verbatim() {
        // Use protected bytes that are NOT a valid CBOR map — verbatim means verbatim
        let raw_protected = b"\xff\xfe\xfd";
        let payload = b"payload";

        let sig_structure = build_sig_structure(raw_protected, payload).unwrap();
        let decoded: ciborium::Value = ciborium::de::from_reader(sig_structure.as_slice()).unwrap();
        match decoded {
            ciborium::Value::Array(arr) => {
                // The exact bytes appear as the second element, unchanged
                assert_eq!(arr[1], ciborium::Value::Bytes(raw_protected.to_vec()));
            }
            other => panic!("Expected Array, got: {other:?}"),
        }
    }

    // ── compute_sig_structure_digest ────────────────────────────────────────

    #[test]
    fn digest_is_sha256_of_sig_structure() {
        let protected_bytes = b"\xa1\x01\x26";
        let payload = b"hello";

        let sig_structure = build_sig_structure(protected_bytes, payload).unwrap();
        let expected: [u8; 32] = Sha256::digest(&sig_structure).into();
        let actual = compute_sig_structure_digest(protected_bytes, payload).unwrap();
        assert_eq!(actual, expected);
    }
}
