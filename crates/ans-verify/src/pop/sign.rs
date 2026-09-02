//! Outbound `DPoP` proof minting.

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use rand::Rng as _;
use x509_parser::prelude::FromDer as _;

use sha2::{Digest, Sha256};

use super::error::{PopError, PopErrorKind};
use super::jws::sign_es256;
use super::proof::{
    ANS_PROFILE_REVISION, DPOP_ALG, DPOP_TYP, ProofHeader, ProofJwk, ProofPayload,
    encode_proof_parts, jwk_thumbprint, normalize_htu, public_jwk,
};

/// Mints `DPoP` proofs for an agent's outbound A2A requests.
///
/// Holds the identity private key and the DER of the matching identity
/// certificate — the certificate whose fingerprint the agent's status token
/// vouches for.
#[derive(Clone)]
pub struct Signer {
    key: SigningKey,
    cert_der: Vec<u8>,
    jwk: ProofJwk,
    now: fn() -> i64,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("cert_der_len", &self.cert_der.len())
            .finish_non_exhaustive()
    }
}

impl Signer {
    /// Build a signer from PKCS#8 DER of a P-256 private key and the matching
    /// identity certificate DER.
    ///
    /// # Errors
    ///
    /// Returns [`PopErrorKind::CertInvalid`] if the key or certificate cannot
    /// be parsed or they do not match.
    pub fn from_pkcs8_der(pkcs8_der: &[u8], cert_der: Vec<u8>) -> Result<Self, PopError> {
        let key = SigningKey::from_pkcs8_der(pkcs8_der).map_err(|e| {
            PopError::with_source(
                PopErrorKind::CertInvalid,
                "signer: PKCS#8 is not an ECDSA P-256 private key",
                e,
            )
        })?;
        Self::new(key, cert_der)
    }

    /// Build a signer from a P-256 private key and the DER of the identity
    /// certificate that binds the matching public key.
    ///
    /// Prefer [`Self::from_pkcs8_der`] if you do not already depend on `p256`.
    ///
    /// # Errors
    ///
    /// Returns [`PopErrorKind::CertInvalid`] if the certificate cannot be
    /// parsed or its public key does not equal the private key.
    pub fn new(key: SigningKey, cert_der: Vec<u8>) -> Result<Self, PopError> {
        let (_, cert) =
            x509_parser::certificate::X509Certificate::from_der(&cert_der).map_err(|e| {
                PopError::with_source(
                    PopErrorKind::CertInvalid,
                    "signer: parse certificate DER",
                    e,
                )
            })?;
        let verifying_key =
            VerifyingKey::from_public_key_der(cert.public_key().raw).map_err(|e| {
                PopError::with_source(
                    PopErrorKind::CertInvalid,
                    "signer: certificate public key is not ECDSA P-256",
                    e,
                )
            })?;
        if verifying_key != *key.verifying_key() {
            return Err(PopError::new(
                PopErrorKind::CertInvalid,
                "signer: certificate public key does not match private key",
            ));
        }
        let jwk = public_jwk(&verifying_key)?;
        Ok(Self {
            key,
            cert_der,
            jwk,
            now: now_unix,
        })
    }

    /// RFC 7638 thumbprint of the signer's public key (`cnf.jkt`).
    ///
    /// # Errors
    ///
    /// Returns [`PopErrorKind::CertInvalid`] if the key cannot be encoded as a JWK.
    pub fn jkt(&self) -> Result<String, PopError> {
        jwk_thumbprint(self.key.verifying_key())
    }

    /// Produce a compact `DPoP` proof binding `method` and `raw_url`.
    ///
    /// Pass `access_token` to bind an OAuth 2.0 access token via `ath`
    /// (`Authorization: DPoP <token>`). Requests that carry content should
    /// use [`Self::sign_with_content`] so the body is bound too (ANS-6
    /// §7.13).
    ///
    /// # Errors
    ///
    /// Returns a [`PopError`] if the URL cannot be normalized, JTI generation
    /// fails, or signing fails.
    pub fn sign(
        &self,
        method: &str,
        raw_url: &str,
        access_token: Option<&str>,
    ) -> Result<String, PopError> {
        self.sign_inner(method, raw_url, access_token, None)
    }

    /// Produce a proof that also binds the request content via
    /// `ans_content_digest` (ANS-6 §7.13). Empty `content` mints no claim —
    /// a zero-length body carries none.
    ///
    /// # Errors
    ///
    /// Returns a [`PopError`] if the URL cannot be normalized, JTI generation
    /// fails, or signing fails.
    pub fn sign_with_content(
        &self,
        method: &str,
        raw_url: &str,
        access_token: Option<&str>,
        content: &[u8],
    ) -> Result<String, PopError> {
        let digest = (!content.is_empty()).then(|| Sha256::digest(content).into());
        self.sign_inner(method, raw_url, access_token, digest)
    }

    fn sign_inner(
        &self,
        method: &str,
        raw_url: &str,
        access_token: Option<&str>,
        content_sha256: Option<[u8; 32]>,
    ) -> Result<String, PopError> {
        let htu = normalize_htu(raw_url)?;
        let jti = new_jti();
        let header = ProofHeader {
            typ: DPOP_TYP.to_string(),
            alg: DPOP_ALG.to_string(),
            jwk: ProofJwk {
                kty: self.jwk.kty.clone(),
                crv: self.jwk.crv.clone(),
                x: self.jwk.x.clone(),
                y: self.jwk.y.clone(),
            },
            x5c: vec![BASE64_STANDARD.encode(&self.cert_der)],
        };
        let payload = ProofPayload {
            htm: method.to_string(),
            htu,
            iat: (self.now)(),
            jti,
            ath: access_token.map(super::proof::access_token_hash),
            ans_profile: Some(ANS_PROFILE_REVISION),
            ans_content_digest: content_sha256.map(|d| super::jws::b64url_encode(&d)),
        };
        let (header_b64, payload_b64) = encode_proof_parts(&header, &payload)?;
        let signing_input = super::jws::jws_signing_input(&header_b64, &payload_b64);
        let sig_b64 = sign_es256(&self.key, signing_input.as_bytes())?;
        Ok(format!("{header_b64}.{payload_b64}.{sig_b64}"))
    }

    #[cfg(test)]
    pub(crate) fn with_clock(mut self, now: fn() -> i64) -> Self {
        self.now = now;
        self
    }
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

fn new_jti() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
