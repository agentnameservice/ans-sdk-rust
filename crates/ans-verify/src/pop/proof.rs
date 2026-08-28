//! `DPoP` proof JOSE header/payload decode, `htu` normalization, and JWK helpers.

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use p256::ecdsa::VerifyingKey;
use p256::pkcs8::DecodePublicKey as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::{Position, Url};

use super::error::{PopError, PopErrorKind};
use super::jws::{COORD_LEN, b64url_decode, b64url_encode};

pub const DPOP_TYP: &str = "dpop+jwt";
pub const DPOP_ALG: &str = "ES256";
const JWK_KTY: &str = "EC";
const JWK_CRV: &str = "P-256";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofHeader {
    pub typ: String,
    pub alg: String,
    pub jwk: ProofJwk,
    pub x5c: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

#[derive(Debug, Deserialize)]
pub struct ProofPayload {
    pub htm: String,
    pub htu: String,
    pub iat: i64,
    pub jti: String,
    #[serde(default)]
    pub ath: Option<String>,
}

pub fn decode_proof_header(header_b64: &str) -> Result<ProofHeader, PopError> {
    let raw = b64url_decode(header_b64)?;
    serde_json::from_slice(&raw).map_err(|e| {
        PopError::with_source(
            PopErrorKind::MalformedProof,
            "decode proof header (unknown fields rejected)",
            e,
        )
    })
}

pub fn decode_proof_payload(payload_b64: &str) -> Result<ProofPayload, PopError> {
    let raw = b64url_decode(payload_b64)?;
    serde_json::from_slice(&raw)
        .map_err(|e| PopError::with_source(PopErrorKind::MalformedProof, "decode proof payload", e))
}

pub fn accept_es256_dpop(header: &ProofHeader) -> Result<(), PopError> {
    if header.typ != DPOP_TYP {
        return Err(PopError::new(
            PopErrorKind::UnsupportedAlg,
            format!(
                "typ must be \"{DPOP_TYP}\", got \"{}\"",
                PopError::echo(&header.typ)
            ),
        ));
    }
    if header.alg != DPOP_ALG {
        return Err(PopError::new(
            PopErrorKind::UnsupportedAlg,
            format!(
                "alg must be \"{DPOP_ALG}\", got \"{}\"",
                PopError::echo(&header.alg)
            ),
        ));
    }
    if header.x5c.len() != 1 {
        return Err(PopError::new(
            PopErrorKind::CertInvalid,
            "proof header x5c must carry exactly one certificate",
        ));
    }
    Ok(())
}

pub fn leaf_cert(
    header: &ProofHeader,
    now: i64,
    skew_secs: i64,
) -> Result<(Vec<u8>, VerifyingKey), PopError> {
    let der = BASE64_STANDARD.decode(&header.x5c[0]).map_err(|e| {
        PopError::with_source(PopErrorKind::CertInvalid, "x5c[0] std-base64 decode", e)
    })?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| PopError::with_source(PopErrorKind::CertInvalid, "x5c[0] parse", e))?;
    // ANS-6 §7.5: fingerprint arrays never prune a rotated-away certificate,
    // so the certificate's own dates are the only expiry the system carries
    // for it. The freshness skew is allowed on both bounds.
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    if now < not_before.saturating_sub(skew_secs) || now > not_after.saturating_add(skew_secs) {
        return Err(PopError::new(
            PopErrorKind::CertInvalid,
            "x5c[0] validity period does not contain the current time",
        ));
    }
    let verifying_key = VerifyingKey::from_public_key_der(cert.public_key().raw).map_err(|e| {
        PopError::with_source(
            PopErrorKind::CertInvalid,
            "x5c[0] key is not ECDSA P-256",
            e,
        )
    })?;
    Ok((der, verifying_key))
}

pub fn public_jwk(pub_key: &VerifyingKey) -> Result<ProofJwk, PopError> {
    let (x, y) = coords_from_key(pub_key)?;
    Ok(ProofJwk {
        kty: JWK_KTY.to_string(),
        crv: JWK_CRV.to_string(),
        x: b64url_encode(&x),
        y: b64url_encode(&y),
    })
}

fn coords_from_key(pub_key: &VerifyingKey) -> Result<([u8; COORD_LEN], [u8; COORD_LEN]), PopError> {
    let point = pub_key.to_sec1_point(false);
    let x = point.x().ok_or_else(|| {
        PopError::new(
            PopErrorKind::CertInvalid,
            "P-256 public key missing x coordinate",
        )
    })?;
    let y = point.y().ok_or_else(|| {
        PopError::new(
            PopErrorKind::CertInvalid,
            "P-256 public key missing y coordinate",
        )
    })?;
    let mut x_out = [0u8; COORD_LEN];
    let mut y_out = [0u8; COORD_LEN];
    x_out.copy_from_slice(x);
    y_out.copy_from_slice(y);
    Ok((x_out, y_out))
}

fn jwk_coords(jwk: &ProofJwk) -> Result<(Vec<u8>, Vec<u8>), PopError> {
    if jwk.kty != JWK_KTY || jwk.crv != JWK_CRV {
        return Err(PopError::new(
            PopErrorKind::UnsupportedAlg,
            format!(
                "jwk must be kty=\"{JWK_KTY}\" crv=\"{JWK_CRV}\", got kty=\"{}\" crv=\"{}\"",
                PopError::echo(&jwk.kty),
                PopError::echo(&jwk.crv)
            ),
        ));
    }
    let x = b64url_decode(&jwk.x)?;
    let y = b64url_decode(&jwk.y)?;
    if x.len() != COORD_LEN || y.len() != COORD_LEN {
        return Err(PopError::new(
            PopErrorKind::MalformedProof,
            format!("jwk coordinates must be {COORD_LEN} bytes each"),
        ));
    }
    Ok((x, y))
}

pub fn match_jwk_to_cert(jwk: &ProofJwk, pub_key: &VerifyingKey) -> Result<(), PopError> {
    let (jx, jy) = jwk_coords(jwk)?;
    let (cx, cy) = coords_from_key(pub_key)?;
    if jx.as_slice() != cx.as_slice() || jy.as_slice() != cy.as_slice() {
        return Err(PopError::new(
            PopErrorKind::KeyMismatch,
            "jwk public key does not match the x5c[0] certificate key",
        ));
    }
    Ok(())
}

/// RFC 9449 §4.2 `ath` value: `base64url(SHA-256(token))`.
pub fn access_token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    b64url_encode(&digest)
}

/// RFC 7638 thumbprint of an EC P-256 public key, base64url-encoded.
///
/// Canonical JSON is concatenated (not `serde_json`) so `&`, `<`, `>` are not
/// escaped and member order is lexicographic (`crv`, `kty`, `x`, `y`).
pub fn jwk_thumbprint(pub_key: &VerifyingKey) -> Result<String, PopError> {
    let jwk = public_jwk(pub_key)?;
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(b64url_encode(&digest))
}

/// RFC 9449 §4.3 `htu` form: lowercase scheme/host, default port dropped,
/// query and fragment stripped, empty path normalized to `/`. The path is
/// otherwise preserved (case-sensitive, no dot-segment canonicalization).
pub fn normalize_htu(raw_url: &str) -> Result<String, PopError> {
    let (url, scheme, hostport) = parse_scheme_authority(raw_url)?;
    let path = &url[Position::BeforePath..Position::AfterPath];
    let path = if path.is_empty() { "/" } else { path };
    Ok(format!("{scheme}://{hostport}{path}"))
}

/// Normalized authority (`host[:port]`, lowercase, scheme-default port
/// dropped) of an absolute URL — the ANS-6 §7.7 comparison form for
/// trusted-authority allowlists.
///
/// # Errors
///
/// Returns a [`PopError`] when the URL is not absolute with a scheme and host.
pub fn request_authority(raw_url: &str) -> Result<String, PopError> {
    let (_, _, hostport) = parse_scheme_authority(raw_url)?;
    Ok(hostport)
}

fn parse_scheme_authority(raw_url: &str) -> Result<(Url, String, String), PopError> {
    let url = Url::parse(raw_url)
        .map_err(|e| PopError::with_source(PopErrorKind::MalformedProof, "parse URL for htu", e))?;
    let scheme = url.scheme().to_ascii_lowercase();
    let host = url.host_str().ok_or_else(|| {
        PopError::new(
            PopErrorKind::MalformedProof,
            "htu requires an absolute URL with scheme and host",
        )
    })?;
    if scheme.is_empty() || host.is_empty() {
        return Err(PopError::new(
            PopErrorKind::MalformedProof,
            "htu requires an absolute URL with scheme and host",
        ));
    }
    let host = host.to_ascii_lowercase();
    let hostport = match url.port() {
        Some(port) if (scheme == "https" && port == 443) || (scheme == "http" && port == 80) => {
            host
        }
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    Ok((url, scheme, hostport))
}

/// Lowercase an authority and drop a scheme default port so allowlist entries
/// compare in the same form [`normalize_htu`] produces.
pub fn normalize_authority(host: &str) -> String {
    let host = host.trim().to_ascii_lowercase();
    if let Some(stripped) = host.strip_suffix(":443") {
        stripped.to_string()
    } else if let Some(stripped) = host.strip_suffix(":80") {
        stripped.to_string()
    } else {
        host
    }
}

pub fn encode_proof_parts(
    header: &ProofHeader,
    payload: &ProofPayload,
) -> Result<(String, String), PopError> {
    #[derive(serde::Serialize)]
    struct HeaderOut<'a> {
        typ: &'a str,
        alg: &'a str,
        jwk: JwkOut<'a>,
        x5c: &'a [String],
    }
    #[derive(serde::Serialize)]
    struct JwkOut<'a> {
        kty: &'a str,
        crv: &'a str,
        x: &'a str,
        y: &'a str,
    }
    #[derive(serde::Serialize)]
    struct PayloadOut<'a> {
        htm: &'a str,
        htu: &'a str,
        iat: i64,
        jti: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        ath: Option<&'a str>,
    }
    let header_json = serde_json::to_vec(&HeaderOut {
        typ: &header.typ,
        alg: &header.alg,
        jwk: JwkOut {
            kty: &header.jwk.kty,
            crv: &header.jwk.crv,
            x: &header.jwk.x,
            y: &header.jwk.y,
        },
        x5c: &header.x5c,
    })
    .map_err(|e| PopError::with_source(PopErrorKind::MalformedProof, "marshal proof header", e))?;
    let payload_json = serde_json::to_vec(&PayloadOut {
        htm: &payload.htm,
        htu: &payload.htu,
        iat: payload.iat,
        jti: &payload.jti,
        ath: payload.ath.as_deref(),
    })
    .map_err(|e| PopError::with_source(PopErrorKind::MalformedProof, "marshal proof payload", e))?;
    Ok((b64url_encode(&header_json), b64url_encode(&payload_json)))
}
