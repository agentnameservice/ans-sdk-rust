//! C2SP root key format parsing and trusted key store.
//!
//! The C2SP key format encodes an ECDSA P-256 public key as:
//!
//! ```text
//! <name>+<key_hash_hex>+<base64-SPKI-DER>
//! ```
//!
//! where `key_hash_hex` is the first 4 bytes of `SHA-256(SPKI-DER)` encoded
//! as lowercase hex.
//!
//! The [`ScittKeyStore`] indexes parsed keys by their 4-byte key ID for O(1)
//! COSE `kid` lookup during receipt and status token verification.

use std::collections::HashMap;

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey as _;
use sha2::{Digest, Sha256};
use tracing::warn;

use super::error::ScittError;

/// Maximum base64 length for SPKI-DER in C2SP keys.
/// P-256 SPKI-DER is 91 bytes (~124 base64 chars). 1KB is extremely generous.
const MAX_SPKI_BASE64_LEN: usize = 1024;

/// A trusted ECDSA P-256 signing key parsed from C2SP format.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    /// The TL domain this key belongs to.
    pub name: String,
    /// 4-byte key ID (first 4 bytes of SHA-256 of SPKI-DER).
    pub kid: [u8; 4],
    /// The P-256 verifying key.
    pub key: VerifyingKey,
}

/// Store of trusted root keys, indexed by 4-byte key ID for O(1) lookup.
///
/// Both TL keys (for receipts) and RA keys (for status tokens) come from the
/// same `/root-keys` endpoint. They are distinguished by the `kid` in the
/// COSE protected header at verification time.
#[derive(Debug, Clone)]
pub struct ScittKeyStore {
    keys: HashMap<[u8; 4], TrustedKey>,
}

impl ScittKeyStore {
    /// Parse a set of C2SP key strings into a key store.
    ///
    /// Invalid keys are logged at `tracing::warn!` and skipped (not fatal).
    /// Returns error only if NO valid keys could be parsed.
    ///
    /// # Errors
    ///
    /// Returns [`ScittError::InvalidKeyFormat`] if no valid keys could be parsed
    /// from the input.
    pub fn from_c2sp_keys(key_strings: &[String]) -> Result<Self, ScittError> {
        let mut keys: HashMap<[u8; 4], TrustedKey> = HashMap::new();

        for key_string in key_strings {
            match parse_c2sp_key(key_string) {
                Ok(trusted_key) => {
                    if let Some(existing) = keys.get(&trusted_key.kid)
                        && existing.name != trusted_key.name
                    {
                        warn!(
                            kid = %hex::encode(trusted_key.kid),
                            existing = %existing.name,
                            new = %trusted_key.name,
                            "Key ID collision detected — overwriting existing key"
                        );
                    }
                    keys.insert(trusted_key.kid, trusted_key);
                }
                Err(err) => {
                    warn!(key = %key_string, error = %err, "Skipping invalid C2SP key");
                }
            }
        }

        if keys.is_empty() {
            return Err(ScittError::InvalidKeyFormat(
                "no valid keys could be parsed from input".to_string(),
            ));
        }

        Ok(Self { keys })
    }

    /// Look up a key by its 4-byte key ID.
    ///
    /// # Errors
    ///
    /// Returns [`ScittError::UnknownKeyId`] if no key with the given ID exists.
    pub fn get(&self, kid: [u8; 4]) -> Result<&TrustedKey, ScittError> {
        self.keys.get(&kid).ok_or(ScittError::UnknownKeyId(kid))
    }

    /// Returns the number of trusted keys in the store.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns true if the store contains no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Create a new store containing all keys from `self` plus any newly
    /// parsed keys from `additional_key_strings`.
    ///
    /// - Keys already present (same `kid`) are kept unchanged.
    /// - New valid keys are merged in.
    /// - Invalid keys in `additional_key_strings` are warned and skipped.
    ///
    /// Unlike [`from_c2sp_keys`](Self::from_c2sp_keys), this method never
    /// returns an error: if zero new keys are parsed, the existing keys are
    /// still present.
    pub fn merge_from(&self, additional_key_strings: &[String]) -> Self {
        let mut keys = self.keys.clone();
        let before = keys.len();

        for key_string in additional_key_strings {
            match parse_c2sp_key(key_string) {
                Ok(trusted_key) => {
                    use std::collections::hash_map::Entry;
                    match keys.entry(trusted_key.kid) {
                        Entry::Occupied(e) => {
                            // ANS-6 §4.5: collisions fail toward the cache — a line whose
                            // kid matches but whose name or key material differs is a finding.
                            if e.get().name != trusted_key.name || e.get().key != trusted_key.key {
                                warn!(
                                    kid = %hex::encode(trusted_key.kid),
                                    existing = %e.get().name,
                                    new = %trusted_key.name,
                                    "Key ID collision detected during merge — keeping existing key"
                                );
                            }
                        }
                        Entry::Vacant(e) => {
                            e.insert(trusted_key);
                        }
                    }
                }
                Err(err) => {
                    warn!(key = %key_string, error = %err, "Skipping invalid C2SP key during merge");
                }
            }
        }

        let added = keys.len() - before;
        if added > 0 {
            tracing::debug!(added, total = keys.len(), "Merged new root keys into store");
        }

        Self { keys }
    }
}

/// Parse a single C2SP key string into its components.
///
/// Public for testing; production code uses [`ScittKeyStore::from_c2sp_keys`].
///
/// # Format
///
/// ```text
/// <name>+<key_hash_hex>+<base64-SPKI-DER>
/// ```
///
/// # Errors
///
/// - [`ScittError::InvalidKeyFormat`] — wrong number of `+` delimiters, invalid
///   hex, wrong key hash length, or invalid Base64
/// - [`ScittError::KeyHashMismatch`] — key hash does not match SHA-256 of SPKI-DER
/// - [`ScittError::InvalidPublicKey`] — SPKI-DER does not encode a valid P-256 key
pub fn parse_c2sp_key(key_string: &str) -> Result<TrustedKey, ScittError> {
    let parts: Vec<&str> = key_string.splitn(3, '+').collect();
    if parts.len() != 3 {
        return Err(ScittError::InvalidKeyFormat(format!(
            "expected 3 '+'-delimited parts, got {}",
            parts.len()
        )));
    }

    let name = parts[0];
    let key_hash_hex = parts[1];
    let spki_b64 = parts[2];

    if name.is_empty() {
        return Err(ScittError::InvalidKeyFormat(
            "name (part 0) is empty".to_string(),
        ));
    }

    // Hex-decode the key hash
    let key_hash_bytes = hex::decode(key_hash_hex)
        .map_err(|e| ScittError::InvalidKeyFormat(format!("key_hash is not valid hex: {e}")))?;

    // Must be exactly 4 bytes
    if key_hash_bytes.len() != 4 {
        return Err(ScittError::InvalidKeyFormat(format!(
            "key_hash must be 4 bytes (8 hex chars), got {} bytes",
            key_hash_bytes.len()
        )));
    }

    let kid: [u8; 4] = [
        key_hash_bytes[0],
        key_hash_bytes[1],
        key_hash_bytes[2],
        key_hash_bytes[3],
    ];

    // Base64-decode the key material.
    // Cap before allocation to prevent amplification from a crafted response.
    if spki_b64.len() > MAX_SPKI_BASE64_LEN {
        return Err(ScittError::InvalidKeyFormat(format!(
            "SPKI base64 is {} chars, maximum is {MAX_SPKI_BASE64_LEN}",
            spki_b64.len()
        )));
    }
    let decoded = BASE64_STANDARD
        .decode(spki_b64)
        .map_err(|e| ScittError::InvalidKeyFormat(format!("SPKI-DER is not valid Base64: {e}")))?;

    // C2SP signed-note format: base64 content may be prefixed with a type byte
    // (0x02 = ECDSA). Strip it to get the raw SPKI-DER.
    let spki_der = if decoded.first() == Some(&0x02) && decoded.len() > 1 {
        &decoded[1..]
    } else {
        &decoded
    };

    // Verify key hash: SHA-256(spki_der)[0..4] must equal kid
    let digest = Sha256::digest(spki_der);
    let expected_kid: [u8; 4] = [digest[0], digest[1], digest[2], digest[3]];
    if expected_kid != kid {
        return Err(ScittError::KeyHashMismatch);
    }

    // Parse SPKI-DER as a P-256 verifying key
    let key = VerifyingKey::from_public_key_der(spki_der)
        .map_err(|e| ScittError::InvalidPublicKey(e.to_string()))?;

    Ok(TrustedKey {
        name: name.to_string(),
        kid,
        key,
    })
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey as _;

    use super::*;

    /// Build a valid C2SP key string for a test P-256 key derived from a fixed seed byte.
    fn make_c2sp_key(seed: u8, name: &str) -> (String, TrustedKey) {
        let seed_bytes = [seed; 32];
        let signing_key = SigningKey::from_slice(&seed_bytes).unwrap();
        let verifying_key = signing_key.verifying_key();
        let spki_doc = verifying_key.to_public_key_der().unwrap();
        let spki_der = spki_doc.as_bytes();
        let digest = Sha256::digest(spki_der);
        let kid: [u8; 4] = [digest[0], digest[1], digest[2], digest[3]];
        let key_hash_hex = hex::encode(kid);
        let spki_b64 = BASE64_STANDARD.encode(spki_der);
        let key_string = format!("{name}+{key_hash_hex}+{spki_b64}");
        let trusted_key = TrustedKey {
            name: name.to_string(),
            kid,
            key: *verifying_key,
        };
        (key_string, trusted_key)
    }

    // ── parse_c2sp_key happy path ──

    #[test]
    fn parse_valid_c2sp_key() {
        let (key_string, expected) = make_c2sp_key(1, "tl.example.com");
        let parsed = parse_c2sp_key(&key_string).unwrap();
        assert_eq!(parsed.name, expected.name);
        assert_eq!(parsed.kid, expected.kid);
        // Compare by encoding both back to DER
        let parsed_der = parsed.key.to_public_key_der().unwrap();
        let expected_der = expected.key.to_public_key_der().unwrap();
        assert_eq!(parsed_der.as_bytes(), expected_der.as_bytes());
    }

    // ── wrong number of '+' delimiters ──

    #[test]
    fn error_zero_plus_delimiters() {
        let err = parse_c2sp_key("noplusdelimiters").unwrap_err();
        assert!(matches!(err, ScittError::InvalidKeyFormat(_)));
    }

    #[test]
    fn error_one_plus_delimiter() {
        let err = parse_c2sp_key("tl.example.com+a1b2c3d4").unwrap_err();
        assert!(matches!(err, ScittError::InvalidKeyFormat(_)));
    }

    #[test]
    fn error_no_extra_parts_via_splitn() {
        // splitn(3) means a 4th+ part gets merged into the last segment;
        // so with 4 real '+' chars we get 3 parts and the last part has a '+' in it.
        // That's fine as long as the SPKI base64 is invalid.
        // But with only 2 '+' we get only 2 parts (splitn returns <=n pieces).
        let err = parse_c2sp_key("a+b").unwrap_err();
        assert!(matches!(err, ScittError::InvalidKeyFormat(_)));
    }

    // ── key_hash not valid hex ──

    #[test]
    fn error_key_hash_not_valid_hex() {
        let (_, _) = make_c2sp_key(1, "tl.example.com");
        let err = parse_c2sp_key("tl.example.com+ZZZZZZZZ+YWJj").unwrap_err();
        assert!(matches!(err, ScittError::InvalidKeyFormat(_)));
    }

    // ── key_hash wrong length ──

    #[test]
    fn error_key_hash_too_short_3_bytes() {
        // 3 bytes = 6 hex chars
        let err = parse_c2sp_key("tl.example.com+a1b2c3+YWJj").unwrap_err();
        assert!(matches!(err, ScittError::InvalidKeyFormat(_)));
    }

    #[test]
    fn error_key_hash_too_long_5_bytes() {
        // 5 bytes = 10 hex chars
        let err = parse_c2sp_key("tl.example.com+a1b2c3d4e5+YWJj").unwrap_err();
        assert!(matches!(err, ScittError::InvalidKeyFormat(_)));
    }

    // ── SPKI-DER not valid Base64 ──

    #[test]
    fn error_spki_not_valid_base64() {
        let err = parse_c2sp_key("tl.example.com+a1b2c3d4+!!!not_base64!!!").unwrap_err();
        assert!(matches!(err, ScittError::InvalidKeyFormat(_)));
    }

    // ── key hash doesn't match SPKI-DER hash ──

    #[test]
    fn error_key_hash_mismatch() {
        let (key_string, _) = make_c2sp_key(1, "tl.example.com");
        // Tamper the hash portion (parts[1]) by flipping first nibble
        let parts: Vec<&str> = key_string.splitn(3, '+').collect();
        let bad_hash = format!("ff{}", &parts[1][2..]);
        let tampered = format!("{}+{}+{}", parts[0], bad_hash, parts[2]);
        let err = parse_c2sp_key(&tampered).unwrap_err();
        assert!(matches!(err, ScittError::KeyHashMismatch));
    }

    // ── SPKI-DER valid Base64 but not a valid P-256 key ──

    #[test]
    fn error_spki_valid_base64_but_not_p256() {
        // Build a fake SPKI-DER that is just random bytes
        let fake_der = vec![0u8; 32];
        let digest = Sha256::digest(&fake_der);
        let kid: [u8; 4] = [digest[0], digest[1], digest[2], digest[3]];
        let key_hash_hex = hex::encode(kid);
        let spki_b64 = BASE64_STANDARD.encode(&fake_der);
        let key_string = format!("tl.example.com+{key_hash_hex}+{spki_b64}");
        let err = parse_c2sp_key(&key_string).unwrap_err();
        assert!(matches!(err, ScittError::InvalidPublicKey(_)));
    }

    // ── ScittKeyStore lookup found and not found ──

    #[test]
    fn keystore_lookup_found_and_not_found() {
        let (key_string, expected) = make_c2sp_key(1, "tl.example.com");
        let store = ScittKeyStore::from_c2sp_keys(&[key_string]).unwrap();

        // Found
        let found = store.get(expected.kid).unwrap();
        assert_eq!(found.name, "tl.example.com");
        assert_eq!(found.kid, expected.kid);

        // Not found — a random different kid
        let other_kid = [0xde, 0xad, 0xbe, 0xef];
        let err = store.get(other_kid).unwrap_err();
        assert!(matches!(err, ScittError::UnknownKeyId(k) if k == other_kid));
    }

    // ── ScittKeyStore with multiple keys having different kids ──

    #[test]
    fn keystore_multiple_keys() {
        let (k1, trusted1) = make_c2sp_key(1, "tl.example.com");
        let (k2, trusted2) = make_c2sp_key(2, "tl2.example.com");
        let store = ScittKeyStore::from_c2sp_keys(&[k1, k2]).unwrap();
        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());

        let found1 = store.get(trusted1.kid).unwrap();
        assert_eq!(found1.name, "tl.example.com");

        let found2 = store.get(trusted2.kid).unwrap();
        assert_eq!(found2.name, "tl2.example.com");
    }

    // ── ScittKeyStore: all keys invalid returns error ──

    #[test]
    fn keystore_all_invalid_returns_error() {
        let bad_keys = vec!["no+plus".to_string(), "also+bad".to_string()];
        let err = ScittKeyStore::from_c2sp_keys(&bad_keys).unwrap_err();
        assert!(matches!(err, ScittError::InvalidKeyFormat(_)));
    }

    // ── ScittKeyStore: some valid some invalid, valid ones stored ──

    #[test]
    fn keystore_mixed_valid_and_invalid() {
        let (valid_key, trusted) = make_c2sp_key(1, "tl.example.com");
        let keys = vec!["not+valid".to_string(), valid_key, "also+bad".to_string()];
        let store = ScittKeyStore::from_c2sp_keys(&keys).unwrap();
        assert_eq!(store.len(), 1);
        let found = store.get(trusted.kid).unwrap();
        assert_eq!(found.name, "tl.example.com");
    }

    // ── ScittKeyStore: empty input returns error ──

    #[test]
    fn keystore_empty_input_returns_error() {
        let err = ScittKeyStore::from_c2sp_keys(&[]).unwrap_err();
        assert!(matches!(err, ScittError::InvalidKeyFormat(_)));
    }

    // ── len / is_empty ──

    #[test]
    fn keystore_len_and_is_empty() {
        let (k1, _) = make_c2sp_key(3, "tl.example.com");
        let store = ScittKeyStore::from_c2sp_keys(&[k1]).unwrap();
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
    }

    // ── merge_from ──

    #[test]
    fn merge_from_adds_new_key() {
        let (k1, trusted1) = make_c2sp_key(1, "tl.example.com");
        let (k2, trusted2) = make_c2sp_key(2, "tl2.example.com");
        let store = ScittKeyStore::from_c2sp_keys(&[k1]).unwrap();
        assert_eq!(store.len(), 1);

        let merged = store.merge_from(&[k2]);
        assert_eq!(merged.len(), 2);
        assert!(merged.get(trusted1.kid).is_ok());
        assert!(merged.get(trusted2.kid).is_ok());
    }

    #[test]
    fn merge_from_does_not_overwrite_existing_key() {
        let (k1, trusted1) = make_c2sp_key(1, "tl.example.com");
        let store = ScittKeyStore::from_c2sp_keys(&[k1.clone()]).unwrap();
        let original_der = store
            .get(trusted1.kid)
            .unwrap()
            .key
            .to_public_key_der()
            .unwrap();

        // Merge the same key string again — should not replace
        let merged = store.merge_from(&[k1]);
        assert_eq!(merged.len(), 1);
        let after_der = merged
            .get(trusted1.kid)
            .unwrap()
            .key
            .to_public_key_der()
            .unwrap();
        assert_eq!(original_der.as_bytes(), after_der.as_bytes());
    }

    #[test]
    fn merge_from_with_empty_input_returns_same_keys() {
        let (k1, trusted1) = make_c2sp_key(1, "tl.example.com");
        let (k2, trusted2) = make_c2sp_key(2, "tl2.example.com");
        let store = ScittKeyStore::from_c2sp_keys(&[k1, k2]).unwrap();
        assert_eq!(store.len(), 2);

        let merged = store.merge_from(&[]);
        assert_eq!(merged.len(), 2);
        assert!(merged.get(trusted1.kid).is_ok());
        assert!(merged.get(trusted2.kid).is_ok());
    }

    #[test]
    fn merge_from_skips_invalid_keys() {
        let (k1, trusted1) = make_c2sp_key(1, "tl.example.com");
        let (k2, trusted2) = make_c2sp_key(2, "tl2.example.com");
        let store = ScittKeyStore::from_c2sp_keys(&[k1]).unwrap();

        let merged = store.merge_from(&["not+valid".to_string(), k2, "also+bad".to_string()]);
        assert_eq!(merged.len(), 2);
        assert!(merged.get(trusted1.kid).is_ok());
        assert!(merged.get(trusted2.kid).is_ok());
    }
}
