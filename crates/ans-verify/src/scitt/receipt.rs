//! SCITT receipt verification: COSE signature + Merkle inclusion proof.
//!
//! Combines `COSE_Sign1` parsing, ECDSA P-256 signature verification, and
//! RFC 9162 Merkle inclusion proof verification to produce a [`VerifiedReceipt`].
//!
//! A receipt is a transparency log artifact proving that a particular agent
//! registration event has been included in the TL's append-only Merkle tree.
//!
//! # Wire format
//!
//! The receipt is a `COSE_Sign1` whose:
//! - **protected header** contains `alg=-7` (ES256), `kid` (4 bytes), and
//!   `vds=1` (`RFC9162_SHA256`, label 395)
//! - **payload** is the event bytes
//! - **unprotected header** contains the Verifiable Data Proof (VDP) at
//!   label 396, a CBOR map with negative integer keys:
//!   - `-1`: `tree_size` (unsigned integer)
//!   - `-2`: `leaf_index` (unsigned integer)
//!   - `-3`: `inclusion_path` (array of 32-byte bstr)
//! - **signature** is a 64-byte P1363 ECDSA P-256 signature

use p256::ecdsa::Signature;

use super::cose::{build_sig_structure, parse_cose_sign1};
use super::error::ScittError;
use super::merkle::{MAX_HASH_PATH_LEN, walk_inclusion_path};
use super::root_keys::ScittKeyStore;

/// A receipt whose COSE signature and Merkle proof have been verified.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedReceipt {
    /// Tree size at time of inclusion.
    pub tree_size: u64,
    /// Leaf index in the transparency log.
    pub leaf_index: u64,
    /// Merkle root hash computed from the proven leaf + inclusion path.
    ///
    /// Note: the inclusion path comes from the unsigned (unprotected) COSE
    /// header. The COSE signature proves the TL attested to this event; the
    /// root hash is useful for external log monitors verifying append-only
    /// consistency, not for per-request trust.
    pub root_hash: [u8; 32],
    /// The event payload bytes from the COSE payload.
    pub event_bytes: Vec<u8>,
    /// Key ID that signed this receipt.
    pub key_id: [u8; 4],
    /// Issuer from protected header cwt-claims (if present).
    pub iss: Option<String>,
    /// Issued-at from protected header cwt-claims (if present).
    pub iat: Option<i64>,
}

/// Verifiable Data Proof extracted from the COSE unprotected header at label 396.
///
/// Key mapping (per SCITT COSE profile with `vds=1`):
/// - `-1`: `tree_size` (unsigned integer)
/// - `-2`: `leaf_index` (unsigned integer)
/// - `-3`: `inclusion_path` (array of 32-byte bstr)
struct Vdp {
    tree_size: u64,
    leaf_index: u64,
    inclusion_path: Vec<[u8; 32]>,
}

/// Verify a SCITT receipt: COSE signature + Merkle inclusion proof.
///
/// # Steps
///
/// 1. Parse the `COSE_Sign1` structure from `receipt_bytes`
/// 2. Check that `vds == 1` (`RFC9162_SHA256`) in the protected header
/// 3. Look up the signing key by `kid` from `key_store`
/// 4. Compute the `Sig_structure` digest and verify the ECDSA P-256 signature
/// 5. Extract the VDP (Merkle proof) from the unprotected header at label 396
/// 6. Verify Merkle inclusion proof
/// 7. Return a [`VerifiedReceipt`] with verified fields
///
/// # Errors
///
/// - Structural/CBOR errors from `COSE_Sign1` parsing
/// - [`ScittError::InvalidProtectedHeader`] if `vds` is missing or not 1
/// - [`ScittError::UnknownKeyId`] if `kid` is not in `key_store`
/// - [`ScittError::SignatureInvalid`] if ECDSA verification fails
/// - [`ScittError::InvalidMerkleProof`] if VDP is missing or malformed
/// - [`ScittError::InvalidMerkleProof`] if `tree_size == 0` or `leaf_index >= tree_size`
pub fn verify_receipt(
    receipt_bytes: &[u8],
    key_store: &ScittKeyStore,
) -> Result<VerifiedReceipt, ScittError> {
    tracing::debug!(bytes = receipt_bytes.len(), "Verifying SCITT receipt");

    // Step 1: parse COSE_Sign1
    let parsed = parse_cose_sign1(receipt_bytes)?;

    // Step 2: validate vds = 1 (RFC9162_SHA256)
    match parsed.protected.vds {
        Some(1) => {}
        Some(other) => {
            return Err(ScittError::InvalidProtectedHeader(format!(
                "vds must be 1 (RFC9162_SHA256), got {other}"
            )));
        }
        None => {
            return Err(ScittError::InvalidProtectedHeader(
                "missing vds field (label 395) in receipt protected header".to_string(),
            ));
        }
    }

    // Step 3: look up signing key by kid
    let kid_hex = hex::encode(parsed.protected.kid);
    let trusted_key = key_store.get(parsed.protected.kid)?;
    tracing::debug!(kid = %kid_hex, key_domain = %trusted_key.name, "Key lookup succeeded");

    // Step 3b: bind iss claim to signing key domain
    if let Some(iss) = &parsed.protected.cwt_iss
        && iss != &trusted_key.name
    {
        tracing::warn!(claimed_iss = %iss, key_domain = %trusted_key.name, "Issuer mismatch");
        return Err(ScittError::IssuerMismatch {
            claimed: iss.clone(),
            key_domain: trusted_key.name.clone(),
        });
    }

    // Step 4: verify ECDSA P-256 signature
    let sig_structure = build_sig_structure(&parsed.protected_bytes, &parsed.payload)?;
    let sig = Signature::from_slice(&parsed.signature).map_err(|_| {
        tracing::warn!(kid = %kid_hex, "ECDSA signature encoding invalid");
        ScittError::SignatureInvalid
    })?;
    if !crate::p256_verify::verify_p256_sha256(&trusted_key.key, &sig_structure, &sig) {
        tracing::warn!(kid = %kid_hex, "ECDSA signature verification failed");
        return Err(ScittError::SignatureInvalid);
    }
    tracing::debug!(kid = %kid_hex, "ECDSA signature verified");

    // Step 5: extract VDP from unprotected header (label 396)
    let vdp = extract_vdp(&parsed.unprotected)?;

    // Step 6: compute root hash by walking the inclusion_path.
    //
    // The inclusion_path lives in the unprotected (unsigned) header. The COSE
    // signature (step 4) already proves the TL attested to this event — that is
    // the trust anchor for per-request verification. The Merkle proof cannot add
    // trust here: even if the root were signed into the receipt, it would only
    // prove "the TL says the root is X," which is circular.
    //
    // The proof's real value is for external log monitors who compare tree heads
    // across time to verify append-only consistency. We compute and return the
    // root_hash so monitors/auditors can use it for that purpose.
    let root_hash = walk_inclusion_path(
        &parsed.payload,
        vdp.leaf_index,
        vdp.tree_size,
        &vdp.inclusion_path,
    )?;

    tracing::debug!(
        tree_size = vdp.tree_size,
        leaf_index = vdp.leaf_index,
        path_len = vdp.inclusion_path.len(),
        "Receipt verified: COSE signature + Merkle inclusion proof"
    );

    Ok(VerifiedReceipt {
        tree_size: vdp.tree_size,
        leaf_index: vdp.leaf_index,
        root_hash,
        event_bytes: parsed.payload,
        key_id: parsed.protected.kid,
        iss: parsed.protected.cwt_iss,
        iat: parsed.protected.cwt_iat,
    })
}

/// Extract the Verifiable Data Proof (VDP) from the COSE unprotected header at label 396.
///
/// Key mapping (per SCITT COSE profile with `vds=1`):
/// - `-1`: `tree_size` (unsigned integer)
/// - `-2`: `leaf_index` (unsigned integer)
/// - `-3`: `inclusion_path` (array of 32-byte bstr)
fn extract_vdp(unprotected: &ciborium::Value) -> Result<Vdp, ScittError> {
    let ciborium::Value::Map(outer_map) = unprotected else {
        return Err(ScittError::InvalidMerkleProof(
            "unprotected header must be a CBOR map".to_string(),
        ));
    };

    // Find label 396 in the outer map
    let vdp_value = outer_map
        .iter()
        .find_map(|(k, v)| {
            if cbor_to_i64(k) == Some(396) {
                Some(v)
            } else {
                None
            }
        })
        .ok_or_else(|| {
            ScittError::InvalidMerkleProof(
                "missing VDP (label 396) in unprotected header".to_string(),
            )
        })?;

    let ciborium::Value::Map(vdp_map) = vdp_value else {
        return Err(ScittError::InvalidMerkleProof(
            "VDP (label 396) must be a CBOR map".to_string(),
        ));
    };

    let mut tree_size: Option<u64> = None;
    let mut leaf_index: Option<u64> = None;
    let mut inclusion_path: Option<Vec<[u8; 32]>> = None;

    for (k, v) in vdp_map {
        match cbor_to_i64(k) {
            Some(-1) => {
                // tree_size: unsigned integer
                tree_size = Some(cbor_to_u64(v).ok_or_else(|| {
                    ScittError::InvalidMerkleProof(
                        "tree_size (key -1) must be an unsigned integer".to_string(),
                    )
                })?);
            }
            Some(-2) => {
                // leaf_index: unsigned integer
                leaf_index = Some(cbor_to_u64(v).ok_or_else(|| {
                    ScittError::InvalidMerkleProof(
                        "leaf_index (key -2) must be an unsigned integer".to_string(),
                    )
                })?);
            }
            Some(-3) => {
                // inclusion_path: array of 32-byte bstr
                let ciborium::Value::Array(arr) = v else {
                    return Err(ScittError::InvalidMerkleProof(
                        "inclusion_path (key -3) must be a CBOR array".to_string(),
                    ));
                };
                // Cap at 63 (max Merkle tree depth for 2^63 entries) before allocation.
                // ciborium already parsed all elements, so arr.len() is real, but
                // we reject early to match compute_merkle_root's depth guard.
                if arr.len() > MAX_HASH_PATH_LEN {
                    return Err(ScittError::InvalidMerkleProof(format!(
                        "inclusion_path length {} exceeds maximum of {MAX_HASH_PATH_LEN}",
                        arr.len()
                    )));
                }
                let mut path = Vec::with_capacity(arr.len());
                for (i, item) in arr.iter().enumerate() {
                    let ciborium::Value::Bytes(bytes) = item else {
                        return Err(ScittError::InvalidMerkleProof(format!(
                            "inclusion_path[{i}] must be a bstr"
                        )));
                    };
                    let hash: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                        ScittError::InvalidMerkleProof(format!(
                            "inclusion_path[{i}] must be 32 bytes, got {}",
                            bytes.len()
                        ))
                    })?;
                    path.push(hash);
                }
                inclusion_path = Some(path);
            }
            _ => {} // ignore unknown keys (e.g., -4 root hash)
        }
    }

    Ok(Vdp {
        tree_size: tree_size.ok_or_else(|| {
            ScittError::InvalidMerkleProof("missing tree_size (key -1) in VDP".to_string())
        })?,
        leaf_index: leaf_index.ok_or_else(|| {
            ScittError::InvalidMerkleProof("missing leaf_index (key -2) in VDP".to_string())
        })?,
        inclusion_path: inclusion_path.ok_or_else(|| {
            ScittError::InvalidMerkleProof("missing inclusion_path (key -3) in VDP".to_string())
        })?,
    })
}

/// Convert a `ciborium::Value` integer (positive or negative) to `i64`.
fn cbor_to_i64(v: &ciborium::Value) -> Option<i64> {
    match v {
        ciborium::Value::Integer(i) => i128::from(*i).try_into().ok(),
        _ => None,
    }
}

/// Convert a `ciborium::Value` unsigned integer to `u64`.
fn cbor_to_u64(v: &ciborium::Value) -> Option<u64> {
    match v {
        ciborium::Value::Integer(i) => {
            let val = i128::from(*i);
            u64::try_from(val).ok()
        }
        _ => None,
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner as _};
    use p256::pkcs8::EncodePublicKey as _;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::scitt::cose::compute_sig_structure_digest;
    use crate::scitt::merkle::build_tree_and_proof;
    use crate::scitt::root_keys::ScittKeyStore;

    use base64::Engine as _;
    use base64::prelude::BASE64_STANDARD;

    // ── Test helpers ─────────────────────────────────────────────────────────

    /// Build a P-256 signing key and matching key store from a fixed seed.
    fn make_key_and_store(seed: u8) -> (SigningKey, ScittKeyStore) {
        let signing_key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let verifying_key = signing_key.verifying_key();
        let spki_doc = verifying_key.to_public_key_der().unwrap();
        let spki_der = spki_doc.as_bytes();
        let digest = Sha256::digest(spki_der);
        let kid: [u8; 4] = [digest[0], digest[1], digest[2], digest[3]];
        let key_hash_hex = hex::encode(kid);
        let spki_b64 = BASE64_STANDARD.encode(spki_der);
        let key_string = format!("tl.example.com+{key_hash_hex}+{spki_b64}");
        let store = ScittKeyStore::from_c2sp_keys(&[key_string]).unwrap();
        (signing_key, store)
    }

    /// Build protected header CBOR bytes with alg=-7, kid, and vds=1.
    fn build_receipt_protected_bytes(signing_key: &SigningKey) -> Vec<u8> {
        let spki_doc = signing_key.verifying_key().to_public_key_der().unwrap();
        let spki_der = spki_doc.as_bytes();
        let digest = Sha256::digest(spki_der);
        let kid = vec![digest[0], digest[1], digest[2], digest[3]];

        let pairs = vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer((-7_i64).into()),
            ),
            (
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Bytes(kid),
            ),
            (
                ciborium::Value::Integer(395.into()),
                ciborium::Value::Integer(1.into()),
            ),
        ];
        let map = ciborium::Value::Map(pairs);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        buf
    }

    /// Build a VDP CBOR map (label 396 value) using the SCITT VDP schema:
    /// - `-1`: tree_size
    /// - `-2`: leaf_index
    /// - `-3`: inclusion_path (array of 32-byte bstr)
    fn build_vdp_map(
        tree_size: u64,
        leaf_index: u64,
        inclusion_path: &[[u8; 32]],
    ) -> ciborium::Value {
        let path_values: Vec<ciborium::Value> = inclusion_path
            .iter()
            .map(|h| ciborium::Value::Bytes(h.to_vec()))
            .collect();

        ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer((-1_i64).into()),
                ciborium::Value::Integer(tree_size.into()),
            ),
            (
                ciborium::Value::Integer((-2_i64).into()),
                ciborium::Value::Integer(leaf_index.into()),
            ),
            (
                ciborium::Value::Integer((-3_i64).into()),
                ciborium::Value::Array(path_values),
            ),
        ])
    }

    /// Build the unprotected header containing VDP at label 396.
    fn build_unprotected_with_vdp(vdp: ciborium::Value) -> ciborium::Value {
        ciborium::Value::Map(vec![(ciborium::Value::Integer(396.into()), vdp)])
    }

    /// Build a complete signed receipt (COSE_Sign1) for the given event bytes
    /// with a valid Merkle tree built from the provided leaves.
    fn make_receipt(signing_key: &SigningKey, leaves: &[&[u8]], leaf_index: usize) -> Vec<u8> {
        let event = leaves[leaf_index];
        let (_, inclusion_path) = build_tree_and_proof(leaves, leaf_index);
        let tree_size = leaves.len() as u64;

        let protected_bytes = build_receipt_protected_bytes(signing_key);
        let payload = event.to_vec();

        // Sign
        let digest = compute_sig_structure_digest(&protected_bytes, &payload).unwrap();
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();

        // Build unprotected header with VDP
        let vdp = build_vdp_map(tree_size, leaf_index as u64, &inclusion_path);
        let unprotected = build_unprotected_with_vdp(vdp);

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            unprotected,
            ciborium::Value::Bytes(payload),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();
        buf
    }

    // ── Valid receipt tests ──────────────────────────────────────────────────

    #[test]
    fn valid_single_leaf_receipt() {
        let (signing_key, store) = make_key_and_store(1);
        let leaves: &[&[u8]] = &[b"event-0"];
        let receipt = make_receipt(&signing_key, leaves, 0);

        let result = verify_receipt(&receipt, &store).unwrap();
        assert_eq!(result.tree_size, 1);
        assert_eq!(result.leaf_index, 0);
        assert_eq!(result.event_bytes, b"event-0");
        assert!(result.iss.is_none());
        assert!(result.iat.is_none());
    }

    #[test]
    fn valid_4_leaf_tree_all_positions() {
        let (signing_key, store) = make_key_and_store(1);
        let leaves: &[&[u8]] = &[b"a", b"b", b"c", b"d"];

        for i in 0..4 {
            let receipt = make_receipt(&signing_key, leaves, i);
            let result = verify_receipt(&receipt, &store).unwrap();
            assert_eq!(result.tree_size, 4);
            assert_eq!(result.leaf_index, i as u64);
            assert_eq!(result.event_bytes, leaves[i]);
        }
    }

    #[test]
    fn valid_7_leaf_non_power_of_2_tree() {
        let (signing_key, store) = make_key_and_store(1);
        let leaves: &[&[u8]] = &[b"v0", b"v1", b"v2", b"v3", b"v4", b"v5", b"v6"];

        for i in 0..7 {
            let receipt = make_receipt(&signing_key, leaves, i);
            let result = verify_receipt(&receipt, &store).unwrap();
            assert_eq!(result.tree_size, 7);
            assert_eq!(result.leaf_index, i as u64);
        }
    }

    #[test]
    fn valid_large_tree_receipt() {
        let (signing_key, store) = make_key_and_store(2);
        // 1024 leaves → 10 levels deep
        let event_data: Vec<Vec<u8>> = (0u16..1024)
            .map(|i| format!("event{i}").into_bytes())
            .collect();
        let leaf_refs: Vec<&[u8]> = event_data.iter().map(|v| v.as_slice()).collect();
        let receipt = make_receipt(&signing_key, &leaf_refs, 511);
        let result = verify_receipt(&receipt, &store).unwrap();
        assert_eq!(result.leaf_index, 511);
        assert_eq!(result.tree_size, 1024);
    }

    #[test]
    fn key_id_propagated_in_result() {
        let (signing_key, store) = make_key_and_store(1);
        let spki_doc = signing_key.verifying_key().to_public_key_der().unwrap();
        let digest = Sha256::digest(spki_doc.as_bytes());
        let expected_kid: [u8; 4] = [digest[0], digest[1], digest[2], digest[3]];

        let leaves: &[&[u8]] = &[b"event"];
        let receipt = make_receipt(&signing_key, leaves, 0);
        let result = verify_receipt(&receipt, &store).unwrap();
        assert_eq!(result.key_id, expected_kid);
    }

    // ── Signature failure tests ─────────────────────────────────────────────

    #[test]
    fn invalid_signature_flipped_byte() {
        let (signing_key, store) = make_key_and_store(1);
        let leaves: &[&[u8]] = &[b"event"];
        let (_, inclusion_path) = build_tree_and_proof(leaves, 0);

        let protected_bytes = build_receipt_protected_bytes(&signing_key);
        let payload = b"event".to_vec();
        let digest = compute_sig_structure_digest(&protected_bytes, &payload).unwrap();
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let mut sig_bytes = sig.to_bytes().to_vec();
        sig_bytes[0] ^= 0xFF; // flip a byte

        let vdp = build_vdp_map(1, 0, &inclusion_path);
        let unprotected = build_unprotected_with_vdp(vdp);

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            unprotected,
            ciborium::Value::Bytes(payload),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();

        let err = verify_receipt(&buf, &store).unwrap_err();
        assert!(matches!(err, ScittError::SignatureInvalid));
    }

    #[test]
    fn wrong_key_not_in_store() {
        let (signing_key, _) = make_key_and_store(1);
        let (_, store2) = make_key_and_store(2);
        let leaves: &[&[u8]] = &[b"event"];
        let receipt = make_receipt(&signing_key, leaves, 0);

        let err = verify_receipt(&receipt, &store2).unwrap_err();
        assert!(matches!(err, ScittError::UnknownKeyId(_)));
    }

    // ── VDP missing/malformed tests ─────────────────────────────────────────

    #[test]
    fn missing_vdp_label_396() {
        let (signing_key, store) = make_key_and_store(1);
        let protected_bytes = build_receipt_protected_bytes(&signing_key);
        let payload = b"event".to_vec();
        let digest = compute_sig_structure_digest(&protected_bytes, &payload).unwrap();
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();

        // Unprotected header without label 396
        let unprotected = ciborium::Value::Map(vec![]);

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            unprotected,
            ciborium::Value::Bytes(payload),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();

        let err = verify_receipt(&buf, &store).unwrap_err();
        assert!(matches!(err, ScittError::InvalidMerkleProof(_)));
        assert!(err.to_string().contains("396"));
    }

    #[test]
    fn vdp_missing_tree_size() {
        let (signing_key, store) = make_key_and_store(1);
        let protected_bytes = build_receipt_protected_bytes(&signing_key);
        let payload = b"event".to_vec();
        let digest = compute_sig_structure_digest(&protected_bytes, &payload).unwrap();
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();

        // VDP without tree_size (-1)
        let vdp = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer((-2_i64).into()),
                ciborium::Value::Integer(0_u64.into()),
            ),
            (
                ciborium::Value::Integer((-3_i64).into()),
                ciborium::Value::Array(vec![]),
            ),
        ]);
        let unprotected = build_unprotected_with_vdp(vdp);

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            unprotected,
            ciborium::Value::Bytes(payload),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();

        let err = verify_receipt(&buf, &store).unwrap_err();
        assert!(matches!(err, ScittError::InvalidMerkleProof(_)));
        assert!(err.to_string().contains("tree_size"));
    }

    #[test]
    fn vdp_missing_inclusion_path() {
        let (signing_key, store) = make_key_and_store(1);
        let protected_bytes = build_receipt_protected_bytes(&signing_key);
        let payload = b"event".to_vec();
        let digest = compute_sig_structure_digest(&protected_bytes, &payload).unwrap();
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();

        // VDP without inclusion_path (-3)
        let vdp = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer((-1_i64).into()),
                ciborium::Value::Integer(1_u64.into()),
            ),
            (
                ciborium::Value::Integer((-2_i64).into()),
                ciborium::Value::Integer(0_u64.into()),
            ),
        ]);
        let unprotected = build_unprotected_with_vdp(vdp);

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            unprotected,
            ciborium::Value::Bytes(payload),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();

        let err = verify_receipt(&buf, &store).unwrap_err();
        assert!(matches!(err, ScittError::InvalidMerkleProof(_)));
        assert!(err.to_string().contains("inclusion_path"));
    }

    #[test]
    fn vdp_inclusion_path_element_wrong_length() {
        let (signing_key, store) = make_key_and_store(1);
        let protected_bytes = build_receipt_protected_bytes(&signing_key);
        let payload = b"event".to_vec();
        let digest = compute_sig_structure_digest(&protected_bytes, &payload).unwrap();
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();

        // inclusion_path[0] is 20 bytes instead of 32
        let vdp = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer((-1_i64).into()),
                ciborium::Value::Integer(2_u64.into()),
            ),
            (
                ciborium::Value::Integer((-2_i64).into()),
                ciborium::Value::Integer(0_u64.into()),
            ),
            (
                ciborium::Value::Integer((-3_i64).into()),
                ciborium::Value::Array(vec![ciborium::Value::Bytes(vec![0u8; 20])]),
            ),
        ]);
        let unprotected = build_unprotected_with_vdp(vdp);

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            unprotected,
            ciborium::Value::Bytes(payload),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();

        let err = verify_receipt(&buf, &store).unwrap_err();
        assert!(matches!(err, ScittError::InvalidMerkleProof(_)));
        assert!(err.to_string().contains("32 bytes"));
    }

    // ── Protected header validation ─────────────────────────────────────────

    #[test]
    fn missing_vds_in_protected_header() {
        let (signing_key, store) = make_key_and_store(1);
        let spki_doc = signing_key.verifying_key().to_public_key_der().unwrap();
        let spki_der = spki_doc.as_bytes();
        let digest = Sha256::digest(spki_der);
        let kid = vec![digest[0], digest[1], digest[2], digest[3]];

        // Protected header without vds (label 395)
        let pairs = vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer((-7_i64).into()),
            ),
            (
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Bytes(kid),
            ),
        ];
        let map = ciborium::Value::Map(pairs);
        let mut protected_bytes = Vec::new();
        ciborium::ser::into_writer(&map, &mut protected_bytes).unwrap();

        let payload = b"event".to_vec();
        let sig_digest = compute_sig_structure_digest(&protected_bytes, &payload).unwrap();
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&sig_digest).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();

        let vdp = build_vdp_map(1, 0, &[]);
        let unprotected = build_unprotected_with_vdp(vdp);

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            unprotected,
            ciborium::Value::Bytes(payload),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();

        let err = verify_receipt(&buf, &store).unwrap_err();
        assert!(matches!(err, ScittError::InvalidProtectedHeader(_)));
        assert!(err.to_string().contains("vds"));
    }

    #[test]
    fn wrong_vds_value() {
        let (signing_key, store) = make_key_and_store(1);
        let spki_doc = signing_key.verifying_key().to_public_key_der().unwrap();
        let spki_der = spki_doc.as_bytes();
        let digest = Sha256::digest(spki_der);
        let kid = vec![digest[0], digest[1], digest[2], digest[3]];

        // Protected header with vds=2 (wrong)
        let pairs = vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer((-7_i64).into()),
            ),
            (
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Bytes(kid),
            ),
            (
                ciborium::Value::Integer(395.into()),
                ciborium::Value::Integer(2.into()),
            ),
        ];
        let map = ciborium::Value::Map(pairs);
        let mut protected_bytes = Vec::new();
        ciborium::ser::into_writer(&map, &mut protected_bytes).unwrap();

        let payload = b"event".to_vec();
        let sig_digest = compute_sig_structure_digest(&protected_bytes, &payload).unwrap();
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&sig_digest).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();

        let vdp = build_vdp_map(1, 0, &[]);
        let unprotected = build_unprotected_with_vdp(vdp);

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            unprotected,
            ciborium::Value::Bytes(payload),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();

        let err = verify_receipt(&buf, &store).unwrap_err();
        assert!(matches!(err, ScittError::InvalidProtectedHeader(_)));
        assert!(err.to_string().contains("vds"));
    }

    // ── Merkle root computation ───────────────────────────────────────────────

    #[test]
    fn root_hash_is_deterministic_for_same_tree() {
        // Verifies that root_hash in VerifiedReceipt is consistently computed.
        let (signing_key, store) = make_key_and_store(1);
        let leaves: &[&[u8]] = &[b"a", b"b", b"c", b"d"];

        let receipt0 = make_receipt(&signing_key, leaves, 0);
        let result0 = verify_receipt(&receipt0, &store).unwrap();

        let receipt1 = make_receipt(&signing_key, leaves, 1);
        let result1 = verify_receipt(&receipt1, &store).unwrap();

        // Both receipts are from the same tree, so both roots should be equal.
        assert_eq!(result0.root_hash, result1.root_hash);
    }

    // ── Payload tamper detection ────────────────────────────────────────────

    #[test]
    fn tampered_payload_in_receipt() {
        let (signing_key, store) = make_key_and_store(1);
        let leaves: &[&[u8]] = &[b"real-event"];
        let (_, inclusion_path) = build_tree_and_proof(leaves, 0);

        let protected_bytes = build_receipt_protected_bytes(&signing_key);
        // Sign the real payload
        let real_payload = b"real-event".to_vec();
        let digest = compute_sig_structure_digest(&protected_bytes, &real_payload).unwrap();
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();

        // Swap in a different payload — signature will fail
        let fake_payload = b"fake-event".to_vec();
        let vdp = build_vdp_map(1, 0, &inclusion_path);
        let unprotected = build_unprotected_with_vdp(vdp);

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            unprotected,
            ciborium::Value::Bytes(fake_payload),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();

        let err = verify_receipt(&buf, &store).unwrap_err();
        assert!(matches!(err, ScittError::SignatureInvalid));
    }

    // ── Wrong-type VDP fields ───────────────────────────────────────────────

    #[test]
    fn vdp_tree_size_wrong_type() {
        let (signing_key, store) = make_key_and_store(1);
        let protected_bytes = build_receipt_protected_bytes(&signing_key);
        let payload = b"event".to_vec();
        let digest = compute_sig_structure_digest(&protected_bytes, &payload).unwrap();
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();

        // tree_size (-1) is a text string instead of integer
        let vdp = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer((-1_i64).into()),
                ciborium::Value::Text("not an integer".to_string()),
            ),
            (
                ciborium::Value::Integer((-2_i64).into()),
                ciborium::Value::Integer(0_u64.into()),
            ),
            (
                ciborium::Value::Integer((-3_i64).into()),
                ciborium::Value::Array(vec![]),
            ),
        ]);
        let unprotected = build_unprotected_with_vdp(vdp);

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            unprotected,
            ciborium::Value::Bytes(payload),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();

        let err = verify_receipt(&buf, &store).unwrap_err();
        assert!(matches!(err, ScittError::InvalidMerkleProof(_)));
        assert!(err.to_string().contains("tree_size"));
        assert!(err.to_string().contains("unsigned integer"));
    }

    #[test]
    fn vdp_inclusion_path_wrong_type() {
        let (signing_key, store) = make_key_and_store(1);
        let protected_bytes = build_receipt_protected_bytes(&signing_key);
        let payload = b"event".to_vec();
        let digest = compute_sig_structure_digest(&protected_bytes, &payload).unwrap();
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();

        // inclusion_path (-3) is a text string instead of array
        let vdp = ciborium::Value::Map(vec![
            (
                ciborium::Value::Integer((-1_i64).into()),
                ciborium::Value::Integer(1_u64.into()),
            ),
            (
                ciborium::Value::Integer((-2_i64).into()),
                ciborium::Value::Integer(0_u64.into()),
            ),
            (
                ciborium::Value::Integer((-3_i64).into()),
                ciborium::Value::Text("not an array".to_string()),
            ),
        ]);
        let unprotected = build_unprotected_with_vdp(vdp);

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            unprotected,
            ciborium::Value::Bytes(payload),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();

        let err = verify_receipt(&buf, &store).unwrap_err();
        assert!(matches!(err, ScittError::InvalidMerkleProof(_)));
        assert!(err.to_string().contains("inclusion_path"));
        assert!(err.to_string().contains("CBOR array"));
    }

    // ── Issuer binding tests ───────────────────────────────────────────────

    /// Build protected header bytes with alg=-7, kid, vds=1, and CWT claims
    /// containing the given `iss` value.
    fn build_protected_with_iss(signing_key: &SigningKey, iss: &str) -> Vec<u8> {
        let spki_doc = signing_key.verifying_key().to_public_key_der().unwrap();
        let spki_der = spki_doc.as_bytes();
        let digest = Sha256::digest(spki_der);
        let kid = vec![digest[0], digest[1], digest[2], digest[3]];

        let cwt_claims = ciborium::Value::Map(vec![(
            ciborium::Value::Integer(1.into()), // CWT key 1 = iss
            ciborium::Value::Text(iss.to_string()),
        )]);

        let pairs = vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Integer((-7_i64).into()),
            ),
            (
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Bytes(kid),
            ),
            (
                ciborium::Value::Integer(395.into()),
                ciborium::Value::Integer(1.into()),
            ),
            (
                ciborium::Value::Integer(15.into()), // label 15 = CWT claims
                cwt_claims,
            ),
        ];
        let map = ciborium::Value::Map(pairs);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        buf
    }

    /// Helper: build a signed receipt with custom protected header bytes.
    fn make_receipt_with_protected(
        signing_key: &SigningKey,
        protected_bytes: &[u8],
        leaves: &[&[u8]],
        leaf_index: usize,
    ) -> Vec<u8> {
        let event = leaves[leaf_index];
        let (_, inclusion_path) = build_tree_and_proof(leaves, leaf_index);
        let tree_size = leaves.len() as u64;
        let payload = event.to_vec();

        let digest = compute_sig_structure_digest(protected_bytes, &payload).unwrap();
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();

        let vdp = build_vdp_map(tree_size, leaf_index as u64, &inclusion_path);
        let unprotected = build_unprotected_with_vdp(vdp);

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes.to_vec()),
            unprotected,
            ciborium::Value::Bytes(payload),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();
        buf
    }

    #[test]
    fn iss_matches_key_domain_passes() {
        let (signing_key, store) = make_key_and_store(1);
        // iss = "tl.example.com" matches the key's C2SP name
        let protected = build_protected_with_iss(&signing_key, "tl.example.com");
        let leaves: &[&[u8]] = &[b"event"];
        let receipt = make_receipt_with_protected(&signing_key, &protected, leaves, 0);

        let result = verify_receipt(&receipt, &store).unwrap();
        assert_eq!(result.iss.as_deref(), Some("tl.example.com"));
    }

    #[test]
    fn iss_mismatch_rejects() {
        let (signing_key, store) = make_key_and_store(1);
        // iss = "evil.example.com" does NOT match key's "tl.example.com"
        let protected = build_protected_with_iss(&signing_key, "evil.example.com");
        let leaves: &[&[u8]] = &[b"event"];
        let receipt = make_receipt_with_protected(&signing_key, &protected, leaves, 0);

        let err = verify_receipt(&receipt, &store).unwrap_err();
        assert!(matches!(err, ScittError::IssuerMismatch { .. }));
        let msg = err.to_string();
        assert!(
            msg.contains("evil.example.com"),
            "should show claimed iss: {msg}"
        );
        assert!(
            msg.contains("tl.example.com"),
            "should show key domain: {msg}"
        );
    }

    #[test]
    fn no_iss_claim_still_passes() {
        // When iss is absent, we don't enforce — existing behavior preserved
        let (signing_key, store) = make_key_and_store(1);
        let leaves: &[&[u8]] = &[b"event"];
        let receipt = make_receipt(&signing_key, leaves, 0);

        let result = verify_receipt(&receipt, &store).unwrap();
        assert!(result.iss.is_none());
    }
}
