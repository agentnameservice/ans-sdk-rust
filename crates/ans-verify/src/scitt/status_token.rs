//! SCITT status token verification.
//!
//! Implements `COSE_Sign1` parse, ECDSA P-256 signature verification,
//! CBOR payload decoding, expiry checking, and status validation for
//! SCITT status tokens.
//!
//! Status tokens carry CBOR integer-keyed payloads:
//!
//! | Key | Field                 | Type                     |
//! |-----|-----------------------|--------------------------|
//! | 1   | `agent_id`            | text (UUID)              |
//! | 2   | `status`              | text (`SCREAMING_SNAKE_CASE`) |
//! | 3   | `iat`                 | integer (Unix seconds)   |
//! | 4   | `exp`                 | integer (Unix seconds)   |
//! | 5   | `ans_name`            | text                     |
//! | 6   | `valid_identity_certs`| array of maps            |
//! | 7   | `valid_server_certs`  | array of maps            |
//! | 8   | `metadata_hashes`     | map of text→text         |

use std::collections::BTreeMap;

use ans_types::{BadgeStatus, CertEntry, CertFingerprint, CertType, StatusTokenPayload};
use p256::ecdsa::Signature;
use uuid::Uuid;

use super::cose::{build_sig_structure, parse_cose_sign1};
use super::error::ScittError;
use super::root_keys::ScittKeyStore;

/// Maximum clock skew tolerance (24 hours). Larger values would make tokens
/// effectively non-expirable.
pub const MAX_CLOCK_SKEW_TOLERANCE_SECS: u64 = 24 * 60 * 60;

/// A status token whose COSE signature has been verified and expiry checked.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedStatusToken {
    /// The decoded and verified payload.
    pub payload: StatusTokenPayload,
    /// Key ID that signed this token.
    pub key_id: [u8; 4],
}

/// Verify a SCITT status token: COSE signature + expiry + status check.
///
/// Uses the system clock for expiry checks. See
/// [`verify_status_token_at`](crate::verify_status_token_at) for a variant
/// that accepts an explicit timestamp (useful in tests).
///
/// # Steps
/// 1. Parse `COSE_Sign1` structure
/// 2. Verify ECDSA P-256 signature using the key store
/// 3. Decode CBOR payload into [`StatusTokenPayload`]
/// 4. Check token expiry (with configurable clock skew tolerance)
/// 5. Validate agent status (`Active`/`Warning`/`Deprecated` OK; `Expired`/`Revoked` reject)
///
/// # Errors
/// - Structural/crypto errors from COSE parsing
/// - [`ScittError::TokenExpired`] if the token is past `exp + clock_skew`
/// - [`ScittError::TerminalStatus`] if status is `Expired` or `Revoked`
/// - [`ScittError::MissingTokenField`] if required CBOR keys are missing
pub fn verify_status_token(
    token_bytes: &[u8],
    key_store: &ScittKeyStore,
    clock_skew_tolerance: std::time::Duration,
) -> Result<VerifiedStatusToken, ScittError> {
    verify_status_token_at(
        token_bytes,
        key_store,
        clock_skew_tolerance,
        chrono::Utc::now().timestamp(),
    )
}

/// Verify a SCITT status token with an explicit `now` timestamp.
///
/// Identical to [`verify_status_token`] but accepts a caller-supplied Unix
/// timestamp instead of reading the system clock. This makes expiry logic
/// deterministically testable without wall-clock coupling.
pub fn verify_status_token_at(
    token_bytes: &[u8],
    key_store: &ScittKeyStore,
    clock_skew_tolerance: std::time::Duration,
    now: i64,
) -> Result<VerifiedStatusToken, ScittError> {
    tracing::debug!(bytes = token_bytes.len(), "Verifying SCITT status token");

    // Step 1: parse COSE_Sign1
    let parsed = parse_cose_sign1(token_bytes)?;

    // Step 2: verify ECDSA P-256 signature
    let sig_structure = build_sig_structure(&parsed.protected_bytes, &parsed.payload)?;
    let kid_hex = hex::encode(parsed.protected.kid);
    let sig = Signature::from_slice(&parsed.signature).map_err(|_| {
        tracing::warn!(kid = %kid_hex, "ECDSA signature encoding invalid");
        // Length is already validated as 64 bytes by parse_cose_sign1;
        // from_slice failure here means the bytes are not a valid P1363 encoding.
        ScittError::SignatureInvalid
    })?;
    let trusted_key = key_store.get(parsed.protected.kid)?;
    tracing::debug!(kid = %kid_hex, key_domain = %trusted_key.name, "Key lookup succeeded");
    if !crate::p256_verify::verify_p256_sha256(&trusted_key.key, &sig_structure, &sig) {
        tracing::warn!(kid = %kid_hex, "ECDSA signature verification failed");
        return Err(ScittError::SignatureInvalid);
    }
    tracing::debug!(kid = %kid_hex, "ECDSA signature verified");

    // Step 2b: bind iss claim to signing key domain (mirrors receipt.rs)
    if let Some(iss) = &parsed.protected.cwt_iss
        && iss != &trusted_key.name
    {
        return Err(ScittError::IssuerMismatch {
            claimed: iss.clone(),
            key_domain: trusted_key.name.clone(),
        });
    }

    // Step 3: decode CBOR payload
    let payload = decode_status_token_payload(&parsed.payload)?;

    // Step 4: check expiry
    let capped_secs = clock_skew_tolerance
        .as_secs()
        .min(MAX_CLOCK_SKEW_TOLERANCE_SECS);
    let tolerance = i64::try_from(capped_secs).unwrap_or(i64::MAX);
    if now > payload.exp.saturating_add(tolerance) {
        tracing::warn!(
            exp = payload.exp,
            now,
            tolerance_secs = capped_secs,
            "Status token expired"
        );
        return Err(ScittError::TokenExpired {
            exp: payload.exp,
            now,
        });
    }

    // Step 5: validate status
    if payload.status.should_reject() {
        tracing::warn!(status = ?payload.status, "Status token has terminal status");
        return Err(ScittError::TerminalStatus(payload.status));
    }

    tracing::debug!(
        status = ?payload.status,
        ans_name = %payload.ans_name,
        "Status token verified"
    );

    Ok(VerifiedStatusToken {
        payload,
        key_id: parsed.protected.kid,
    })
}

/// Check if a certificate fingerprint matches any entry in the token's server cert array.
///
/// For server verification, checks `valid_server_certs`.
pub fn matches_server_cert(payload: &StatusTokenPayload, fingerprint: &CertFingerprint) -> bool {
    payload
        .valid_server_certs
        .iter()
        .any(|entry| &entry.fingerprint == fingerprint)
}

/// Check if a certificate fingerprint matches any entry in the token's identity cert array.
///
/// For client/mTLS verification, checks `valid_identity_certs`.
pub fn matches_identity_cert(payload: &StatusTokenPayload, fingerprint: &CertFingerprint) -> bool {
    payload
        .valid_identity_certs
        .iter()
        .any(|entry| &entry.fingerprint == fingerprint)
}

/// Decode a CBOR status token payload from raw bytes.
///
/// Expects a CBOR map with integer keys 1–8.
fn decode_status_token_payload(payload_bytes: &[u8]) -> Result<StatusTokenPayload, ScittError> {
    let value: ciborium::Value = ciborium::de::from_reader(payload_bytes)
        .map_err(|e| ScittError::CborDecodeError(e.to_string()))?;

    let ciborium::Value::Map(map) = value else {
        return Err(ScittError::CborDecodeError(
            "status token payload must be a CBOR map".to_string(),
        ));
    };

    let mut agent_id: Option<Uuid> = None;
    let mut status: Option<BadgeStatus> = None;
    let mut iat: Option<i64> = None;
    let mut exp: Option<i64> = None;
    let mut ans_name: Option<String> = None;
    let mut valid_identity_certs: Vec<CertEntry> = Vec::new();
    let mut valid_server_certs: Vec<CertEntry> = Vec::new();
    let mut metadata_hashes: BTreeMap<String, String> = BTreeMap::new();

    for (k, v) in map {
        let key = cbor_to_i64(&k);
        match key {
            Some(1) => {
                // agent_id: text UUID
                if let ciborium::Value::Text(s) = v {
                    agent_id = Some(
                        s.parse::<Uuid>()
                            .map_err(|e| ScittError::CborDecodeError(format!("agent_id: {e}")))?,
                    );
                }
            }
            Some(2) => {
                // status: SCREAMING_SNAKE_CASE text
                if let ciborium::Value::Text(s) = v {
                    status = Some(parse_badge_status(&s)?);
                }
            }
            Some(3) => {
                // iat: integer
                iat = cbor_to_i64(&v);
            }
            Some(4) => {
                // exp: integer
                exp = cbor_to_i64(&v);
            }
            Some(5) => {
                // ans_name: text
                if let ciborium::Value::Text(s) = v {
                    ans_name = Some(s);
                }
            }
            Some(6) => {
                // valid_identity_certs: array of maps
                if let ciborium::Value::Array(arr) = v {
                    valid_identity_certs = parse_cert_entries(arr)?;
                }
            }
            Some(7) => {
                // valid_server_certs: array of maps
                if let ciborium::Value::Array(arr) = v {
                    valid_server_certs = parse_cert_entries(arr)?;
                }
            }
            Some(8) => {
                // metadata_hashes: map of text→text
                if let ciborium::Value::Map(m) = v {
                    const MAX_METADATA_ENTRIES: usize = 256;
                    if m.len() > MAX_METADATA_ENTRIES {
                        return Err(ScittError::CborDecodeError(format!(
                            "metadata_hashes has {} entries, maximum is {MAX_METADATA_ENTRIES}",
                            m.len()
                        )));
                    }
                    for (mk, mv) in m {
                        if let (ciborium::Value::Text(k), ciborium::Value::Text(val)) = (mk, mv) {
                            metadata_hashes.insert(k, val);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(StatusTokenPayload::new(
        agent_id.ok_or_else(|| ScittError::MissingTokenField("agent_id (key 1)".to_string()))?,
        status.ok_or_else(|| ScittError::MissingTokenField("status (key 2)".to_string()))?,
        iat.ok_or_else(|| ScittError::MissingTokenField("iat (key 3)".to_string()))?,
        exp.ok_or_else(|| ScittError::MissingTokenField("exp (key 4)".to_string()))?,
        {
            let raw = ans_name
                .ok_or_else(|| ScittError::MissingTokenField("ans_name (key 5)".to_string()))?;
            ans_types::AnsName::parse(&raw).map_err(|e| {
                ScittError::MissingTokenField(format!("invalid ans_name (key 5): {e}"))
            })?
        },
        valid_identity_certs,
        valid_server_certs,
        metadata_hashes,
    ))
}

/// Parse a `SCREAMING_SNAKE_CASE` status string into [`BadgeStatus`].
fn parse_badge_status(s: &str) -> Result<BadgeStatus, ScittError> {
    match s {
        "ACTIVE" => Ok(BadgeStatus::Active),
        "WARNING" => Ok(BadgeStatus::Warning),
        "DEPRECATED" => Ok(BadgeStatus::Deprecated),
        "EXPIRED" => Ok(BadgeStatus::Expired),
        "REVOKED" => Ok(BadgeStatus::Revoked),
        other => Err(ScittError::CborDecodeError(format!(
            "unknown status: {other}"
        ))),
    }
}

/// Parse an array of CBOR maps into [`CertEntry`] values.
///
/// Supports both integer-keyed maps (`{1: fingerprint, 2: cert_type}`) from
/// production tokens and string-keyed maps (`{"fingerprint": ..., "cert_type": ...}`)
/// for test compatibility.
fn parse_cert_entries(arr: Vec<ciborium::Value>) -> Result<Vec<CertEntry>, ScittError> {
    // An agent has at most a handful of certs. Cap to prevent allocation amplification
    // from a crafted CBOR array with many elements under MAX_COSE_INPUT_SIZE.
    const MAX_CERT_ENTRIES: usize = 128;
    if arr.len() > MAX_CERT_ENTRIES {
        return Err(ScittError::CborDecodeError(format!(
            "cert array has {} entries, maximum is {MAX_CERT_ENTRIES}",
            arr.len()
        )));
    }
    let mut entries = Vec::with_capacity(arr.len());
    for item in arr {
        let ciborium::Value::Map(m) = item else {
            return Err(ScittError::CborDecodeError(
                "cert entry must be a CBOR map".to_string(),
            ));
        };

        let mut fingerprint: Option<CertFingerprint> = None;
        let mut cert_type: Option<CertType> = None;

        for (k, v) in m {
            // Match by integer key (production) or string key (test compat)
            let is_fingerprint = cbor_to_i64(&k) == Some(1)
                || matches!(&k, ciborium::Value::Text(s) if s == "fingerprint");
            let is_cert_type = cbor_to_i64(&k) == Some(2)
                || matches!(&k, ciborium::Value::Text(s) if s == "cert_type");

            if is_fingerprint {
                fingerprint = match v {
                    ciborium::Value::Text(fp_str) => {
                        Some(CertFingerprint::parse(&fp_str).map_err(|e| {
                            ScittError::CborDecodeError(format!("fingerprint: {e}"))
                        })?)
                    }
                    ciborium::Value::Bytes(b) if b.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&b);
                        Some(CertFingerprint::from_bytes(arr))
                    }
                    _ => None,
                };
            } else if is_cert_type && let ciborium::Value::Text(t) = v {
                cert_type = Some(t.parse::<CertType>().map_err(ScittError::CborDecodeError)?);
            }
        }

        entries.push(CertEntry::new(
            fingerprint.ok_or_else(|| {
                ScittError::MissingTokenField("cert entry missing fingerprint".to_string())
            })?,
            cert_type.ok_or_else(|| {
                ScittError::MissingTokenField("cert entry missing cert_type".to_string())
            })?,
        ));
    }
    Ok(entries)
}

/// Convert a `ciborium::Value` integer to `i64`.
fn cbor_to_i64(v: &ciborium::Value) -> Option<i64> {
    match v {
        ciborium::Value::Integer(i) => i128::from(*i).try_into().ok(),
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

    /// Build the CBOR payload bytes for a status token with integer keys 1–8.
    fn build_cbor_payload(
        agent_id: &str,
        status: &str,
        iat: i64,
        exp: i64,
        ans_name: &str,
        identity_certs: &[(String, String)],
        server_certs: &[(String, String)],
        metadata: &[(String, String)],
    ) -> Vec<u8> {
        let mut pairs: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();

        // key 1: agent_id
        pairs.push((
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text(agent_id.to_string()),
        ));
        // key 2: status
        pairs.push((
            ciborium::Value::Integer(2.into()),
            ciborium::Value::Text(status.to_string()),
        ));
        // key 3: iat
        pairs.push((
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Integer(iat.into()),
        ));
        // key 4: exp
        pairs.push((
            ciborium::Value::Integer(4.into()),
            ciborium::Value::Integer(exp.into()),
        ));
        // key 5: ans_name
        pairs.push((
            ciborium::Value::Integer(5.into()),
            ciborium::Value::Text(ans_name.to_string()),
        ));
        // key 6: valid_identity_certs
        let id_certs: Vec<ciborium::Value> = identity_certs
            .iter()
            .map(|(fp, ct)| {
                ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Text("fingerprint".to_string()),
                        ciborium::Value::Text(fp.clone()),
                    ),
                    (
                        ciborium::Value::Text("cert_type".to_string()),
                        ciborium::Value::Text(ct.clone()),
                    ),
                ])
            })
            .collect();
        pairs.push((
            ciborium::Value::Integer(6.into()),
            ciborium::Value::Array(id_certs),
        ));
        // key 7: valid_server_certs
        let srv_certs: Vec<ciborium::Value> = server_certs
            .iter()
            .map(|(fp, ct)| {
                ciborium::Value::Map(vec![
                    (
                        ciborium::Value::Text("fingerprint".to_string()),
                        ciborium::Value::Text(fp.clone()),
                    ),
                    (
                        ciborium::Value::Text("cert_type".to_string()),
                        ciborium::Value::Text(ct.clone()),
                    ),
                ])
            })
            .collect();
        pairs.push((
            ciborium::Value::Integer(7.into()),
            ciborium::Value::Array(srv_certs),
        ));
        // key 8: metadata_hashes
        let meta: Vec<(ciborium::Value, ciborium::Value)> = metadata
            .iter()
            .map(|(k, v)| {
                (
                    ciborium::Value::Text(k.clone()),
                    ciborium::Value::Text(v.clone()),
                )
            })
            .collect();
        pairs.push((
            ciborium::Value::Integer(8.into()),
            ciborium::Value::Map(meta),
        ));

        let map = ciborium::Value::Map(pairs);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        buf
    }

    /// Build the protected header bytes for key ID derived from `signing_key`.
    fn build_protected_bytes(signing_key: &SigningKey) -> Vec<u8> {
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
        ];
        let map = ciborium::Value::Map(pairs);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&map, &mut buf).unwrap();
        buf
    }

    /// Sign a payload and return a valid COSE_Sign1 token bytes.
    fn make_token(signing_key: &SigningKey, payload: &[u8]) -> Vec<u8> {
        let protected_bytes = build_protected_bytes(signing_key);
        let digest = compute_sig_structure_digest(&protected_bytes, payload).unwrap();
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let sig_bytes = sig.to_bytes().to_vec();

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            ciborium::Value::Map(vec![]),
            ciborium::Value::Bytes(payload.to_vec()),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&array, &mut buf).unwrap();
        buf
    }

    /// A far-future expiry timestamp (year 2100).
    fn future_exp() -> i64 {
        4_102_444_800 // 2100-01-01 00:00:00 UTC
    }

    /// A past expiry timestamp (year 2000).
    fn past_exp() -> i64 {
        946_684_800 // 2000-01-01 00:00:00 UTC
    }

    fn nil_uuid() -> String {
        "00000000-0000-0000-0000-000000000000".to_string()
    }

    fn test_fp() -> String {
        // 32 zero bytes as SHA256:000...000
        format!("SHA256:{}", "00".repeat(32))
    }

    fn test_fp2() -> String {
        format!("SHA256:{}", "11".repeat(32))
    }

    // ── Valid token tests ─────────────────────────────────────────────────────

    #[test]
    fn valid_active_token() {
        let (signing_key, store) = make_key_and_store(1);
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            0,
            future_exp(),
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        let result =
            verify_status_token(&token, &store, std::time::Duration::from_secs(0)).unwrap();
        assert_eq!(result.payload.status, BadgeStatus::Active);
        assert_eq!(
            result.payload.ans_name,
            ans_types::AnsName::parse("ans://v1.0.0.agent.example.com").unwrap()
        );
    }

    #[test]
    fn valid_warning_status_passes() {
        let (signing_key, store) = make_key_and_store(1);
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "WARNING",
            0,
            future_exp(),
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        let result =
            verify_status_token(&token, &store, std::time::Duration::from_secs(0)).unwrap();
        assert_eq!(result.payload.status, BadgeStatus::Warning);
    }

    #[test]
    fn valid_deprecated_status_passes() {
        let (signing_key, store) = make_key_and_store(1);
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "DEPRECATED",
            0,
            future_exp(),
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        let result =
            verify_status_token(&token, &store, std::time::Duration::from_secs(0)).unwrap();
        assert_eq!(result.payload.status, BadgeStatus::Deprecated);
    }

    // ── Terminal status tests ─────────────────────────────────────────────────

    #[test]
    fn expired_status_terminal() {
        let (signing_key, store) = make_key_and_store(1);
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "EXPIRED",
            0,
            future_exp(),
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        let err =
            verify_status_token(&token, &store, std::time::Duration::from_secs(0)).unwrap_err();
        assert!(matches!(
            err,
            ScittError::TerminalStatus(BadgeStatus::Expired)
        ));
    }

    #[test]
    fn revoked_status_terminal() {
        let (signing_key, store) = make_key_and_store(1);
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "REVOKED",
            0,
            future_exp(),
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        let err =
            verify_status_token(&token, &store, std::time::Duration::from_secs(0)).unwrap_err();
        assert!(matches!(
            err,
            ScittError::TerminalStatus(BadgeStatus::Revoked)
        ));
    }

    // ── Expiry tests ──────────────────────────────────────────────────────────

    #[test]
    fn token_expired_in_past() {
        let (signing_key, store) = make_key_and_store(1);
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            0,
            past_exp(),
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        let err =
            verify_status_token(&token, &store, std::time::Duration::from_secs(0)).unwrap_err();
        assert!(matches!(err, ScittError::TokenExpired { .. }));
    }

    #[test]
    fn token_not_expired_with_clock_skew() {
        let (signing_key, store) = make_key_and_store(1);
        // exp = 1 second in the past
        let exp = chrono::Utc::now().timestamp() - 1;
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            0,
            exp,
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        // 10-second tolerance should cover 1 second past
        let result =
            verify_status_token(&token, &store, std::time::Duration::from_secs(10)).unwrap();
        assert_eq!(result.payload.status, BadgeStatus::Active);
    }

    #[test]
    fn token_barely_expired_within_tolerance() {
        let (signing_key, store) = make_key_and_store(1);
        // exp = exactly at clock_skew boundary: exp = now - tolerance
        let tolerance_secs = 300_i64;
        let exp = chrono::Utc::now().timestamp() - tolerance_secs;
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            0,
            exp,
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        // Token expired exactly at tolerance boundary: now == exp + tolerance, NOT > so passes
        let result = verify_status_token(
            &token,
            &store,
            std::time::Duration::from_secs(tolerance_secs as u64),
        )
        .unwrap();
        assert_eq!(result.payload.status, BadgeStatus::Active);
    }

    #[test]
    fn token_expired_beyond_tolerance() {
        let (signing_key, store) = make_key_and_store(1);
        // exp far in the past, tolerance = 5 seconds, still expired
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            0,
            past_exp(),
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        let err =
            verify_status_token(&token, &store, std::time::Duration::from_secs(5)).unwrap_err();
        assert!(matches!(err, ScittError::TokenExpired { .. }));
    }

    // ── Crypto failure tests ──────────────────────────────────────────────────

    #[test]
    fn invalid_signature_flipped_byte() {
        let (signing_key, store) = make_key_and_store(1);
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            0,
            future_exp(),
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        // Build the token, then flip one signature byte
        let protected_bytes = build_protected_bytes(&signing_key);
        let digest = compute_sig_structure_digest(&protected_bytes, &payload_bytes).unwrap();
        let (sig, _): (p256::ecdsa::Signature, _) = signing_key.sign_prehash(&digest).unwrap();
        let mut sig_bytes = sig.to_bytes().to_vec();
        sig_bytes[0] ^= 0xFF; // flip a byte

        let array = ciborium::Value::Array(vec![
            ciborium::Value::Bytes(protected_bytes),
            ciborium::Value::Map(vec![]),
            ciborium::Value::Bytes(payload_bytes),
            ciborium::Value::Bytes(sig_bytes),
        ]);
        let mut token_bytes = Vec::new();
        ciborium::ser::into_writer(&array, &mut token_bytes).unwrap();

        let err = verify_status_token(&token_bytes, &store, std::time::Duration::from_secs(0))
            .unwrap_err();
        assert!(matches!(err, ScittError::SignatureInvalid));
    }

    #[test]
    fn wrong_key_not_in_store() {
        let (signing_key, _store) = make_key_and_store(1);
        // Build a store with a different key (seed 2)
        let (_, store2) = make_key_and_store(2);
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            0,
            future_exp(),
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        // signing_key is seed=1 but store2 only has seed=2
        let err =
            verify_status_token(&token, &store2, std::time::Duration::from_secs(0)).unwrap_err();
        assert!(matches!(err, ScittError::UnknownKeyId(_)));
    }

    // ── Missing field tests ───────────────────────────────────────────────────

    #[test]
    fn missing_agent_id() {
        let (signing_key, store) = make_key_and_store(1);
        // Build payload without key 1 (agent_id)
        let pairs = vec![
            (
                ciborium::Value::Integer(2.into()),
                ciborium::Value::Text("ACTIVE".to_string()),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Integer(0_i64.into()),
            ),
            (
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Integer(future_exp().into()),
            ),
            (
                ciborium::Value::Integer(5.into()),
                ciborium::Value::Text("ans://v1.0.0.a.example.com".to_string()),
            ),
            (
                ciborium::Value::Integer(6.into()),
                ciborium::Value::Array(vec![]),
            ),
            (
                ciborium::Value::Integer(7.into()),
                ciborium::Value::Array(vec![]),
            ),
            (
                ciborium::Value::Integer(8.into()),
                ciborium::Value::Map(vec![]),
            ),
        ];
        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&ciborium::Value::Map(pairs), &mut payload_bytes).unwrap();
        let token = make_token(&signing_key, &payload_bytes);
        let err =
            verify_status_token(&token, &store, std::time::Duration::from_secs(0)).unwrap_err();
        assert!(matches!(err, ScittError::MissingTokenField(_)));
        assert!(err.to_string().contains("agent_id"));
    }

    #[test]
    fn missing_exp() {
        let (signing_key, store) = make_key_and_store(1);
        // Build payload without key 4 (exp)
        let pairs = vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Text(nil_uuid()),
            ),
            (
                ciborium::Value::Integer(2.into()),
                ciborium::Value::Text("ACTIVE".to_string()),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Integer(0_i64.into()),
            ),
            (
                ciborium::Value::Integer(5.into()),
                ciborium::Value::Text("ans://v1.0.0.a.example.com".to_string()),
            ),
            (
                ciborium::Value::Integer(6.into()),
                ciborium::Value::Array(vec![]),
            ),
            (
                ciborium::Value::Integer(7.into()),
                ciborium::Value::Array(vec![]),
            ),
            (
                ciborium::Value::Integer(8.into()),
                ciborium::Value::Map(vec![]),
            ),
        ];
        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&ciborium::Value::Map(pairs), &mut payload_bytes).unwrap();
        let token = make_token(&signing_key, &payload_bytes);
        let err =
            verify_status_token(&token, &store, std::time::Duration::from_secs(0)).unwrap_err();
        assert!(matches!(err, ScittError::MissingTokenField(_)));
        assert!(err.to_string().contains("exp"));
    }

    #[test]
    fn missing_status() {
        let (signing_key, store) = make_key_and_store(1);
        // Build payload without key 2 (status)
        let pairs = vec![
            (
                ciborium::Value::Integer(1.into()),
                ciborium::Value::Text(nil_uuid()),
            ),
            (
                ciborium::Value::Integer(3.into()),
                ciborium::Value::Integer(0_i64.into()),
            ),
            (
                ciborium::Value::Integer(4.into()),
                ciborium::Value::Integer(future_exp().into()),
            ),
            (
                ciborium::Value::Integer(5.into()),
                ciborium::Value::Text("ans://v1.0.0.a.example.com".to_string()),
            ),
            (
                ciborium::Value::Integer(6.into()),
                ciborium::Value::Array(vec![]),
            ),
            (
                ciborium::Value::Integer(7.into()),
                ciborium::Value::Array(vec![]),
            ),
            (
                ciborium::Value::Integer(8.into()),
                ciborium::Value::Map(vec![]),
            ),
        ];
        let mut payload_bytes = Vec::new();
        ciborium::ser::into_writer(&ciborium::Value::Map(pairs), &mut payload_bytes).unwrap();
        let token = make_token(&signing_key, &payload_bytes);
        let err =
            verify_status_token(&token, &store, std::time::Duration::from_secs(0)).unwrap_err();
        assert!(matches!(err, ScittError::MissingTokenField(_)));
        assert!(err.to_string().contains("status"));
    }

    // ── Cert matching tests ───────────────────────────────────────────────────

    #[test]
    fn empty_cert_arrays_valid() {
        let (signing_key, store) = make_key_and_store(1);
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            0,
            future_exp(),
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        let result =
            verify_status_token(&token, &store, std::time::Duration::from_secs(0)).unwrap();
        assert!(result.payload.valid_server_certs.is_empty());
        assert!(result.payload.valid_identity_certs.is_empty());
    }

    #[test]
    fn matches_server_cert_found() {
        let (signing_key, store) = make_key_and_store(1);
        let fp = test_fp();
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            0,
            future_exp(),
            "ans://v1.0.0.agent.example.com",
            &[],
            &[(fp.clone(), "X509-DV-SERVER".to_string())],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        let result =
            verify_status_token(&token, &store, std::time::Duration::from_secs(0)).unwrap();
        let fingerprint = CertFingerprint::parse(&fp).unwrap();
        assert!(matches_server_cert(&result.payload, &fingerprint));
    }

    #[test]
    fn matches_server_cert_not_found() {
        let (signing_key, store) = make_key_and_store(1);
        let fp = test_fp();
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            0,
            future_exp(),
            "ans://v1.0.0.agent.example.com",
            &[],
            &[(fp, "X509-DV-SERVER".to_string())],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        let result =
            verify_status_token(&token, &store, std::time::Duration::from_secs(0)).unwrap();
        let other_fp = CertFingerprint::parse(&test_fp2()).unwrap();
        assert!(!matches_server_cert(&result.payload, &other_fp));
    }

    #[test]
    fn matches_identity_cert_works() {
        let (signing_key, store) = make_key_and_store(1);
        let fp = test_fp();
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            0,
            future_exp(),
            "ans://v1.0.0.agent.example.com",
            &[(fp.clone(), "X509-OV-CLIENT".to_string())],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        let result =
            verify_status_token(&token, &store, std::time::Duration::from_secs(0)).unwrap();
        let fingerprint = CertFingerprint::parse(&fp).unwrap();
        assert!(matches_identity_cert(&result.payload, &fingerprint));
        // server certs are empty, so that should not match
        assert!(!matches_server_cert(&result.payload, &fingerprint));
    }

    #[test]
    fn multiple_certs_any_match_succeeds() {
        let (signing_key, store) = make_key_and_store(1);
        let fp1 = test_fp();
        let fp2 = test_fp2();
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            0,
            future_exp(),
            "ans://v1.0.0.agent.example.com",
            &[],
            &[
                (fp1.clone(), "X509-DV-SERVER".to_string()),
                (fp2.clone(), "X509-DV-SERVER".to_string()),
            ],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        let result =
            verify_status_token(&token, &store, std::time::Duration::from_secs(0)).unwrap();
        // First cert matches
        assert!(matches_server_cert(
            &result.payload,
            &CertFingerprint::parse(&fp1).unwrap()
        ));
        // Second cert matches
        assert!(matches_server_cert(
            &result.payload,
            &CertFingerprint::parse(&fp2).unwrap()
        ));
        // Unrelated cert does not match
        let other = format!("SHA256:{}", "ab".repeat(32));
        assert!(!matches_server_cert(
            &result.payload,
            &CertFingerprint::parse(&other).unwrap()
        ));
    }

    // ── verify_status_token_at (clock abstraction) ─────────────────────────────

    #[test]
    fn verify_at_deterministic_expiry_pass() {
        let (signing_key, store) = make_key_and_store(1);
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            1_000_000,
            1_000_100, // exp = now + 100
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        // "now" is before exp — should pass
        let result =
            verify_status_token_at(&token, &store, std::time::Duration::from_secs(0), 1_000_050)
                .unwrap();
        assert_eq!(result.payload.status, BadgeStatus::Active);
    }

    #[test]
    fn verify_at_deterministic_expiry_fail() {
        let (signing_key, store) = make_key_and_store(1);
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            1_000_000,
            1_000_100, // exp = 1_000_100
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        // "now" is past exp — should fail
        let err =
            verify_status_token_at(&token, &store, std::time::Duration::from_secs(0), 1_000_200)
                .unwrap_err();
        assert!(matches!(
            err,
            ScittError::TokenExpired {
                exp: 1_000_100,
                now: 1_000_200
            }
        ));
    }

    #[test]
    fn verify_at_tolerance_boundary() {
        let (signing_key, store) = make_key_and_store(1);
        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            1_000_000,
            1_000_100, // exp = 1_000_100
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        // now = exp + tolerance (exactly at boundary): now == 1_000_160, exp + tol = 1_000_160
        // Condition is now > exp + tol, so equal means pass
        let result = verify_status_token_at(
            &token,
            &store,
            std::time::Duration::from_secs(60),
            1_000_160,
        )
        .unwrap();
        assert_eq!(result.payload.status, BadgeStatus::Active);

        // now = exp + tolerance + 1 → should fail
        let err = verify_status_token_at(
            &token,
            &store,
            std::time::Duration::from_secs(60),
            1_000_161,
        )
        .unwrap_err();
        assert!(matches!(err, ScittError::TokenExpired { .. }));
    }

    // ── key_id propagated correctly ───────────────────────────────────────────

    #[test]
    fn key_id_propagated_in_result() {
        let (signing_key, store) = make_key_and_store(1);
        let spki_doc = signing_key.verifying_key().to_public_key_der().unwrap();
        let digest = Sha256::digest(spki_doc.as_bytes());
        let expected_kid: [u8; 4] = [digest[0], digest[1], digest[2], digest[3]];

        let payload_bytes = build_cbor_payload(
            &nil_uuid(),
            "ACTIVE",
            0,
            future_exp(),
            "ans://v1.0.0.agent.example.com",
            &[],
            &[],
            &[],
        );
        let token = make_token(&signing_key, &payload_bytes);
        let result =
            verify_status_token(&token, &store, std::time::Duration::from_secs(0)).unwrap();
        assert_eq!(result.key_id, expected_kid);
    }
}
