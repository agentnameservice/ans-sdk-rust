//! SCITT artifact extraction from HTTP headers.
//!
//! The SDK is framework-agnostic: callers extract header values from their
//! HTTP framework (reqwest, axum, actix, etc.) and pass raw strings here.
//! This module handles Base64 decoding only.

use super::cose::MAX_COSE_INPUT_SIZE;
use super::error::ScittError;
use base64::prelude::{BASE64_STANDARD, Engine};

/// Maximum base64-encoded header size: `MAX_COSE_INPUT_SIZE` * 4/3 rounded up.
/// Rejects obviously oversized input before allocating for the decode.
const MAX_BASE64_HEADER_SIZE: usize = MAX_COSE_INPUT_SIZE.div_ceil(3) * 4;

/// SCITT artifacts extracted from HTTP headers.
///
/// Created from Base64-encoded header values via [`ScittHeaders::from_base64`],
/// or from pre-decoded bytes via [`ScittHeaders::new`].
///
/// # Header names
///
/// - `X-SCITT-Receipt` → receipt bytes (`COSE_Sign1` with Merkle proof)
/// - `X-ANS-Status-Token` → status token bytes (`COSE_Sign1` with status claim)
///
/// The HTTP adapter MUST reject duplicate occurrences of either header
/// before selecting a value (ANS-6 §4.6). Method B also rejects duplicate
/// `DPoP` and `Authorization` headers. Use [`crate::reject_duplicate_header`]
/// with the count from the framework's original header collection.
///
/// # Fallback behavior
///
/// - `None` for both fields → badge fallback only if the configured policy allows
/// - Present but decode fails → hard reject (not fallback)
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ScittHeaders {
    /// Decoded receipt bytes from `X-SCITT-Receipt`, if the header was present.
    pub receipt: Option<Vec<u8>>,
    /// Decoded status token bytes from `X-ANS-Status-Token`, if the header was present.
    pub status_token: Option<Vec<u8>>,
}

impl ScittHeaders {
    /// Construct from raw Base64 strings as they appear in HTTP headers.
    ///
    /// Pass `None` for headers that were not present in the request/response.
    /// An empty string (`Some("")`) is treated as "present but empty" and will
    /// decode to an empty byte vector (not an error).
    ///
    /// # Errors
    ///
    /// Returns [`ScittError::Base64Decode`] if a non-`None` value contains
    /// invalid Base64.
    pub fn from_base64(
        receipt_base64: Option<&str>,
        status_token_base64: Option<&str>,
    ) -> Result<Self, ScittError> {
        let receipt = receipt_base64
            .map(|s| {
                if s.len() > MAX_BASE64_HEADER_SIZE {
                    return Err(ScittError::OversizedInput {
                        max_bytes: MAX_COSE_INPUT_SIZE,
                    });
                }
                BASE64_STANDARD
                    .decode(s)
                    .map_err(|e| ScittError::Base64Decode(format!("receipt: {e}")))
            })
            .transpose()?;

        let status_token = status_token_base64
            .map(|s| {
                if s.len() > MAX_BASE64_HEADER_SIZE {
                    return Err(ScittError::OversizedInput {
                        max_bytes: MAX_COSE_INPUT_SIZE,
                    });
                }
                BASE64_STANDARD
                    .decode(s)
                    .map_err(|e| ScittError::Base64Decode(format!("status_token: {e}")))
            })
            .transpose()?;

        Ok(Self {
            receipt,
            status_token,
        })
    }

    /// Construct from already-decoded bytes.
    ///
    /// Use this when the caller has already decoded the Base64 (e.g., from a
    /// framework that provides raw bytes).
    pub fn new(receipt: Option<Vec<u8>>, status_token: Option<Vec<u8>>) -> Self {
        Self {
            receipt,
            status_token,
        }
    }

    /// Returns `true` if neither receipt nor status token is present.
    ///
    /// Badge fallback then depends on the configured policy. Method B always
    /// requires a status token and cannot use badge fallback.
    pub fn is_empty(&self) -> bool {
        self.receipt.is_none() && self.status_token.is_none()
    }

    /// Returns `true` if at least a status token is present.
    ///
    /// A status token is the minimum required for SCITT verification.
    /// A receipt without a status token is not sufficient on its own.
    pub fn has_status_token(&self) -> bool {
        self.status_token.is_some()
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_base64_both_present() {
        // "hello" in Base64
        let receipt_b64 = "aGVsbG8=";
        // "world" in Base64
        let token_b64 = "d29ybGQ=";

        let headers = ScittHeaders::from_base64(Some(receipt_b64), Some(token_b64)).unwrap();
        assert_eq!(headers.receipt.as_deref(), Some(b"hello".as_slice()));
        assert_eq!(headers.status_token.as_deref(), Some(b"world".as_slice()));
        assert!(!headers.is_empty());
        assert!(headers.has_status_token());
    }

    #[test]
    fn from_base64_both_none() {
        let headers = ScittHeaders::from_base64(None, None).unwrap();
        assert!(headers.receipt.is_none());
        assert!(headers.status_token.is_none());
        assert!(headers.is_empty());
        assert!(!headers.has_status_token());
    }

    #[test]
    fn from_base64_receipt_only() {
        let headers = ScittHeaders::from_base64(Some("aGVsbG8="), None).unwrap();
        assert!(headers.receipt.is_some());
        assert!(headers.status_token.is_none());
        assert!(!headers.is_empty());
        assert!(!headers.has_status_token());
    }

    #[test]
    fn from_base64_token_only() {
        let headers = ScittHeaders::from_base64(None, Some("d29ybGQ=")).unwrap();
        assert!(headers.receipt.is_none());
        assert!(headers.status_token.is_some());
        assert!(!headers.is_empty());
        assert!(headers.has_status_token());
    }

    #[test]
    fn from_base64_invalid_receipt() {
        let result = ScittHeaders::from_base64(Some("not!valid!base64!"), None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ScittError::Base64Decode(msg) => assert!(msg.contains("receipt")),
            other => panic!("Expected Base64Decode, got: {other}"),
        }
    }

    #[test]
    fn from_base64_invalid_token() {
        let result = ScittHeaders::from_base64(None, Some("!!!"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ScittError::Base64Decode(msg) => assert!(msg.contains("status_token")),
            other => panic!("Expected Base64Decode, got: {other}"),
        }
    }

    #[test]
    fn from_base64_empty_strings() {
        // Empty string is valid Base64 (decodes to empty bytes)
        let headers = ScittHeaders::from_base64(Some(""), Some("")).unwrap();
        assert_eq!(headers.receipt, Some(vec![]));
        assert_eq!(headers.status_token, Some(vec![]));
        // Not empty — the headers are present (just zero-length)
        assert!(!headers.is_empty());
    }

    #[test]
    fn from_base64_receipt_invalid_token_valid() {
        // If receipt is invalid, error is returned even if token is valid
        let result = ScittHeaders::from_base64(Some("!!!"), Some("d29ybGQ="));
        assert!(result.is_err());
    }

    #[test]
    fn new_with_bytes() {
        let headers = ScittHeaders::new(Some(vec![1, 2, 3]), Some(vec![4, 5, 6]));
        assert_eq!(headers.receipt, Some(vec![1, 2, 3]));
        assert_eq!(headers.status_token, Some(vec![4, 5, 6]));
    }

    #[test]
    fn new_with_none() {
        let headers = ScittHeaders::new(None, None);
        assert!(headers.is_empty());
    }

    #[test]
    fn clone_preserves_data() {
        let original = ScittHeaders::from_base64(Some("aGVsbG8="), Some("d29ybGQ=")).unwrap();
        let cloned = original.clone();
        assert_eq!(original.receipt, cloned.receipt);
        assert_eq!(original.status_token, cloned.status_token);
    }

    #[test]
    fn debug_format() {
        let headers = ScittHeaders::new(Some(vec![0xDE, 0xAD]), None);
        let debug = format!("{headers:?}");
        assert!(debug.contains("ScittHeaders"));
    }

    #[test]
    fn from_base64_large_valid_input() {
        // 1KB of zeros in Base64
        let zeros = vec![0u8; 1024];
        let b64 = BASE64_STANDARD.encode(&zeros);
        let headers = ScittHeaders::from_base64(Some(&b64), None).unwrap();
        assert_eq!(headers.receipt.unwrap().len(), 1024);
    }

    #[test]
    fn from_base64_with_padding() {
        // Test various padding scenarios
        // 1 byte → 2 chars + 2 padding
        let headers = ScittHeaders::from_base64(Some("YQ=="), None).unwrap();
        assert_eq!(headers.receipt.as_deref(), Some(b"a".as_slice()));

        // 2 bytes → 3 chars + 1 padding
        let headers = ScittHeaders::from_base64(Some("YWI="), None).unwrap();
        assert_eq!(headers.receipt.as_deref(), Some(b"ab".as_slice()));

        // 3 bytes → 4 chars, no padding
        let headers = ScittHeaders::from_base64(Some("YWJj"), None).unwrap();
        assert_eq!(headers.receipt.as_deref(), Some(b"abc".as_slice()));
    }

    #[test]
    fn rejects_oversized_receipt() {
        let big = "A".repeat(MAX_BASE64_HEADER_SIZE + 1);
        let result = ScittHeaders::from_base64(Some(&big), None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ScittError::OversizedInput { .. }
        ));
    }

    #[test]
    fn rejects_oversized_token() {
        let big = "A".repeat(MAX_BASE64_HEADER_SIZE + 1);
        let result = ScittHeaders::from_base64(None, Some(&big));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ScittError::OversizedInput { .. }
        ));
    }
}
