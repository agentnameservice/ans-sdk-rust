//! CSR builder for ANS agent registration.
//!
//! Generates correctly-configured Certificate Signing Requests for both ANS
//! certificate types. Handles RSA-2048 key generation and sets all required
//! extensions so callers cannot accidentally submit an invalid CSR.
//!
//! ## Requirements enforced automatically
//!
//! | Certificate | EKU          | Key Usage                             |
//! |-------------|--------------|---------------------------------------|
//! | Server      | `ServerAuth` | `DigitalSignature`, `KeyEncipherment` |
//! | Identity    | `ClientAuth` | `DigitalSignature`                    |
//!
//! ## Example
//!
//! ```rust,no_run
//! use ans_client::csr::AnsCsrBuilder;
//!
//! # fn main() -> Result<(), ans_client::csr::CsrError> {
//! let server = AnsCsrBuilder::server("race-ready.ai", "0.1.2").build()?;
//! // server.csr_pem         — submit to ANS registration
//! // server.private_key_pem — RSA-2048 PKCS#8 PEM, store securely
//!
//! let identity = AnsCsrBuilder::identity("race-ready.ai", "0.1.2").build()?;
//! # Ok(())
//! # }
//! ```

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, PKCS_RSA_SHA256, SanType,
};
use thiserror::Error;

/// The output of a successful [`AnsCsrBuilder::build`] call.
#[derive(Debug, Clone)]
pub struct CsrOutput {
    /// PEM-encoded Certificate Signing Request ready for submission to ANS.
    pub csr_pem: String,
    /// PKCS#8 PEM-encoded RSA-2048 private key. Store this securely.
    pub private_key_pem: String,
}

/// Errors that can occur when building an ANS CSR.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CsrError {
    /// RSA key generation or PKCS#8 encoding failed.
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    /// The hostname or version produces an invalid ANS SAN URI.
    #[error("invalid SAN value: {0}")]
    InvalidSan(String),

    /// rcgen failed to serialize the CSR.
    #[error("CSR serialization failed: {0}")]
    Serialization(#[from] rcgen::Error),
}

enum CsrKind {
    Server,
    Identity,
}

/// Builder for ANS-compliant Certificate Signing Requests.
///
/// Use [`AnsCsrBuilder::server`] for the TLS server certificate CSR and
/// [`AnsCsrBuilder::identity`] for the mTLS client identity certificate CSR.
#[derive(Debug)]
pub struct AnsCsrBuilder {
    host: String,
    version: String,
    kind: CsrKind,
}

impl std::fmt::Debug for CsrKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Server => write!(f, "Server"),
            Self::Identity => write!(f, "Identity"),
        }
    }
}

impl AnsCsrBuilder {
    /// Build a **server** CSR: `ServerAuth` EKU, `DigitalSignature` +
    /// `KeyEncipherment` key usage.
    pub fn server(host: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            version: version.into(),
            kind: CsrKind::Server,
        }
    }

    /// Build an **identity** CSR: `ClientAuth` EKU, `DigitalSignature` key
    /// usage.
    pub fn identity(host: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            version: version.into(),
            kind: CsrKind::Identity,
        }
    }

    /// Generate the RSA-2048 key pair and produce the CSR.
    ///
    /// The returned [`CsrOutput`] contains the PEM-encoded CSR and the
    /// corresponding private key. The private key is not transmitted anywhere —
    /// the caller is responsible for storing it securely.
    pub fn build(self) -> Result<CsrOutput, CsrError> {
        let key_pair = generate_rsa_key_pair()?;
        let csr_pem = build_csr(&key_pair, &self.host, &self.version, &self.kind)?;
        Ok(CsrOutput {
            csr_pem,
            private_key_pem: key_pair.serialize_pem(),
        })
    }
}

fn generate_rsa_key_pair() -> Result<KeyPair, CsrError> {
    // RSA-2048 key generation via aws-lc-rs (BoringSSL).  The `ring` crate
    // does not support RSA key generation; the `rsa` pure-Rust crate carries
    // RUSTSEC-2023-0071 (Marvin Attack timing side-channel in decryption).
    KeyPair::generate_for(&PKCS_RSA_SHA256).map_err(CsrError::Serialization)
}

fn build_csr(
    key_pair: &KeyPair,
    host: &str,
    version: &str,
    kind: &CsrKind,
) -> Result<String, CsrError> {
    let ans_uri = format!("ans://v{version}.{host}");

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, host);

    let dns_san = rcgen::string::Ia5String::try_from(host.to_string())
        .map_err(|e| CsrError::InvalidSan(e.to_string()))?;
    let uri_san = rcgen::string::Ia5String::try_from(ans_uri)
        .map_err(|e| CsrError::InvalidSan(e.to_string()))?;

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName(dns_san), SanType::URI(uri_san)];

    match kind {
        CsrKind::Server => {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
        }
        CsrKind::Identity => {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        }
    }

    let csr = params.serialize_request(key_pair)?;
    Ok(csr.pem()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_csr_builds_without_error() {
        let out = AnsCsrBuilder::server("example.ai", "1.0.0")
            .build()
            .expect("server CSR should build");
        assert!(out.csr_pem.contains("CERTIFICATE REQUEST"));
        assert!(out.private_key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn identity_csr_builds_without_error() {
        let out = AnsCsrBuilder::identity("example.ai", "1.0.0")
            .build()
            .expect("identity CSR should build");
        assert!(out.csr_pem.contains("CERTIFICATE REQUEST"));
        assert!(out.private_key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn server_and_identity_keys_are_independent() {
        let server = AnsCsrBuilder::server("example.ai", "1.0.0")
            .build()
            .expect("server CSR");
        let identity = AnsCsrBuilder::identity("example.ai", "1.0.0")
            .build()
            .expect("identity CSR");
        assert_ne!(
            server.private_key_pem, identity.private_key_pem,
            "each call should produce a fresh key pair"
        );
    }
}
