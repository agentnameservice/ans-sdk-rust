//! Prepare identity control proofs for local keys or external signing providers.
//! The RA's payload segment is preserved exactly; private keys stay with the caller.

use crate::{ClientError, Result, models::IdentityChallengeResponse};
use ans_types::{IdentityKind, IdentityProofInput};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use serde_json::{Value, json};

/// JWS algorithms supported by the merged DID identity profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityProofAlgorithm {
    /// ECDSA P-256/SHA-256 with a 64-byte P1363 signature.
    Es256,
    /// Ed25519 with a 64-byte signature.
    EdDsa,
    /// RSA PKCS#1 v1.5/SHA-256, at least 2048 bits.
    Rs256,
}
impl IdentityProofAlgorithm {
    /// Exact JOSE algorithm name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
        }
    }
}

/// Exact bytes to sign and the immutable RA payload segment.
#[derive(Debug, Clone)]
pub struct PreparedIdentityProof {
    signing_input: String,
    algorithm: IdentityProofAlgorithm,
}
impl PreparedIdentityProof {
    /// Sign these bytes with the selected algorithm, without reserializing them.
    pub fn signing_bytes(&self) -> &[u8] {
        self.signing_input.as_bytes()
    }
    /// Attach the raw JOSE signature to obtain the compact JWS for verify-control.
    pub fn finish(&self, signature: &[u8]) -> Result<String> {
        let valid = match self.algorithm {
            IdentityProofAlgorithm::Es256 | IdentityProofAlgorithm::EdDsa => signature.len() == 64,
            IdentityProofAlgorithm::Rs256 => signature.len() >= 256,
        };
        if !valid {
            return Err(ClientError::Configuration(
                "identity proof signature has the wrong encoding or size".into(),
            ));
        }
        Ok(format!(
            "{}.{}",
            self.signing_input,
            BASE64_URL_SAFE_NO_PAD.encode(signature)
        ))
    }
}

impl IdentityChallengeResponse {
    /// Prepare a proof for a key without changing the served payload segment.
    ///
    /// `ra_id` must come from the caller's trusted RA configuration. A public
    /// JWK is normally unnecessary; supply one only for a deployment requiring
    /// it. Private JWK parameters are rejected before they can leave the caller.
    pub fn prepare_proof(
        &self,
        ra_id: &str,
        algorithm: IdentityProofAlgorithm,
        kid: &str,
        public_jwk: Option<Value>,
    ) -> Result<PreparedIdentityProof> {
        let invalid = |message: &str| ClientError::Configuration(message.into());
        if self.expires_at <= chrono::Utc::now() {
            return Err(invalid("identity challenge has expired"));
        }
        if self.status == ans_types::IdentityStatus::Revoked {
            return Err(invalid("a revoked identity cannot prove a new challenge"));
        }
        if !matches!(self.kind, IdentityKind::DidWeb | IdentityKind::DidKey) {
            return Err(invalid("this identity profile has no supported JWS proof"));
        }
        if ra_id.is_empty() || kid.is_empty() {
            return Err(invalid("configured raId and kid are required"));
        }
        let prefix = format!("{}#", self.value);
        if !kid.starts_with(&prefix) || kid.len() == prefix.len() {
            return Err(invalid("kid must name a method of this identity"));
        }
        if self.kind == IdentityKind::DidKey {
            let id = self
                .value
                .strip_prefix("did:key:")
                .ok_or_else(|| invalid("did:key value is malformed"))?;
            if id.is_empty() || kid != format!("{}#{id}", self.value) {
                return Err(invalid("did:key has exactly one legal kid"));
            }
        } else if !self.value.starts_with("did:web:") {
            return Err(invalid("did:web value is malformed"));
        }
        let challenge = self
            .challenges
            .iter()
            .find(|c| c.kid.as_deref() == Some(kid))
            .or_else(|| self.challenges.iter().find(|c| c.kid.is_none()))
            .ok_or_else(|| invalid("kid is not eligible for this challenge round"))?;
        if self
            .challenges
            .iter()
            .any(|c| c.signing_input != challenge.signing_input)
        {
            return Err(invalid("challenge keys disagree on the signing input"));
        }
        let nonce = BASE64_URL_SAFE_NO_PAD
            .decode(&self.nonce)
            .map_err(|_| invalid("invalid challenge nonce"))?;
        if nonce.len() != 32 {
            return Err(invalid("challenge nonce must contain 32 bytes"));
        }
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(&challenge.signing_input)
            .map_err(|_| invalid("invalid served signingInput"))?;
        let served: IdentityProofInput = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("invalid identity proof payload"))?;
        let expected = IdentityProofInput::new(
            &self.value,
            &self.identity_id,
            &self.nonce,
            ra_id,
            self.kind,
        );
        if served != expected {
            return Err(invalid(
                "served proof input does not bind the expected identity, nonce and RA",
            ));
        }
        let mut header = json!({"alg":algorithm.as_str(),"kid":kid});
        if let Some(jwk) = public_jwk {
            let object = jwk
                .as_object()
                .ok_or_else(|| invalid("public JWK must be an object"))?;
            if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                .iter()
                .any(|name| object.contains_key(*name))
            {
                return Err(invalid("private JWK parameters must never be published"));
            }
            header["jwk"] = jwk;
        }
        let protected = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
        Ok(PreparedIdentityProof {
            signing_input: format!("{protected}.{}", challenge.signing_input),
            algorithm,
        })
    }
}
