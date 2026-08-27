//! HTTP helpers for `DPoP`: header names, `Authorization` parsing, attach.

use super::error::{PopError, PopErrorKind};
use super::sign::Signer;

/// HTTP header that carries the compact `DPoP` proof (RFC 9449).
pub const DPOP_HEADER: &str = "DPoP";

/// Extract the access token from an `Authorization` header value when it uses
/// the `DPoP` scheme (RFC 9449 §7.1). Scheme comparison is case-insensitive.
///
/// Bearer or absent Authorization yields `None`: such a token is not
/// sender-constrained, so the proof must carry no `ath`.
pub fn access_token_from_authorization(value: &str) -> Option<&str> {
    const SCHEME: &str = "DPoP";
    if value.len() <= SCHEME.len() {
        return None;
    }
    // Byte comparison: an ASCII scheme match guarantees a char boundary for
    // the slice below, so a multi-byte char in the header cannot panic.
    if !value.as_bytes()[..SCHEME.len()].eq_ignore_ascii_case(SCHEME.as_bytes()) {
        return None;
    }
    let rest = &value[SCHEME.len()..];
    let first = rest.as_bytes().first()?;
    if *first != b' ' && *first != b'\t' {
        return None;
    }
    let tok = rest.trim_matches([' ', '\t']);
    if tok.is_empty() { None } else { Some(tok) }
}

/// Reject a request when a verification-decision header appears more than once.
///
/// RFC 9449 §4.3 requires this for `DPoP`; the same reasoning covers
/// `Authorization`, `X-SCITT-Receipt`, and `X-ANS-Status-Token`.
pub fn reject_duplicate_header(name: &str, value_count: usize) -> Result<(), PopError> {
    if value_count > 1 {
        Err(PopError::new(
            PopErrorKind::MalformedProof,
            format!("duplicate {name} header"),
        ))
    } else {
        Ok(())
    }
}

/// Mint a `DPoP` proof for an outbound request.
///
/// If `authorization` is `Authorization: DPoP <token>`, the proof is bound
/// via `ath`. SCITT headers are owned by [`crate::ScittHeaderSupplier`]; this
/// function only produces the `DPoP` header value.
///
/// # Errors
///
/// Returns a [`PopError`] if signing fails.
pub fn attach_identity(
    signer: &Signer,
    method: &str,
    url: &str,
    authorization: Option<&str>,
) -> Result<String, PopError> {
    let token = authorization.and_then(access_token_from_authorization);
    signer.sign(method, url, token)
}
