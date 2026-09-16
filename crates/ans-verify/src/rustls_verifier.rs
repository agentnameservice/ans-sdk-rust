//! Rustls integration for ANS certificate verification.
//!
//! This module provides rustls verifier implementations for both client and server
//! certificate verification in the ANS ecosystem.
//!
//! # Server Certificate Verification (Client-side)
//!
//! Use [`AnsServerCertVerifier`] when connecting to an ANS agent server. It verifies
//! the server's certificate against the ANS transparency log badge during the TLS
//! handshake.
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use ans_verify::{AnsVerifier, AnsServerCertVerifier, CertFingerprint};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Fetch the badge to get the expected fingerprint
//! let verifier = AnsVerifier::new(["transparency.ans.godaddy.com"]).await?;
//! let badge = verifier.prefetch("agent.example.com").await?;
//!
//! // Create the server cert verifier
//! let expected_fp = CertFingerprint::parse(badge.server_cert_fingerprint())?;
//! let ans_verifier = AnsServerCertVerifier::new(expected_fp)?;
//!
//! // Use in rustls ClientConfig
//! let tls_config = rustls::ClientConfig::builder()
//!     .dangerous()
//!     .with_custom_certificate_verifier(Arc::new(ans_verifier))
//!     .with_no_client_auth();
//! # Ok(())
//! # }
//! ```
//!
//! # Client Certificate Verification (Server-side mTLS)
//!
//! Use [`AnsClientCertVerifier`] when accepting mTLS connections from ANS agent clients.
//! It validates that client certificates chain to the ANS Private CA during the handshake,
//! but does NOT perform badge verification (which would block the handshake).
//!
//! Badge verification should be performed **after** the handshake completes, before
//! processing any application requests:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use ans_verify::{AnsVerifier, AnsClientCertVerifier, CertIdentity};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Load the ANS Private CA certificate
//! let private_ca_pem = std::fs::read("ans-private-ca.pem")?;
//!
//! // Create client cert verifier for the TLS handshake
//! let client_verifier = AnsClientCertVerifier::from_pem(&private_ca_pem)?;
//!
//! // Use in rustls ServerConfig
//! # let server_certs = vec![];
//! # let server_key = todo!();
//! let server_config = rustls::ServerConfig::builder()
//!     .with_client_cert_verifier(Arc::new(client_verifier))
//!     .with_single_cert(server_certs, server_key)?;
//!
//! // After TLS handshake, verify client against badge:
//! // let peer_cert = tls_stream.get_ref().1.peer_certificates().unwrap()[0];
//! // let cert_identity = CertIdentity::from_der(peer_cert.as_ref())?;
//! // let outcome = verifier.verify_client(&cert_identity).await;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};

use crate::CertFingerprint;

/// A rustls [`ServerCertVerifier`] that validates server certificates against
/// an ANS transparency log badge fingerprint.
///
/// This verifier performs two layers of validation:
/// 1. Standard `WebPKI` certificate chain validation (via the delegate verifier)
/// 2. ANS badge fingerprint comparison
///
/// The server certificate must:
/// - Be valid according to `WebPKI` (trusted CA, not expired, correct hostname)
/// - Have a SHA-256 fingerprint matching the ANS badge
///
/// # Usage
///
/// Typically you would:
/// 1. Use [`AnsVerifier::prefetch`](crate::AnsVerifier::prefetch) to fetch the badge
/// 2. Extract the expected server certificate fingerprint from the badge
/// 3. Create an `AnsServerCertVerifier` with that fingerprint
/// 4. Use it in your rustls `ClientConfig`
///
/// The verification happens automatically during the TLS handshake.
#[derive(Debug)]
pub struct AnsServerCertVerifier {
    /// The expected certificate fingerprint from the ANS badge
    expected_fingerprint: CertFingerprint,
    /// Delegate to `WebPKI` for standard certificate validation
    webpki_verifier: Arc<rustls::client::WebPkiServerVerifier>,
}

impl AnsServerCertVerifier {
    /// Creates a new verifier with the expected server certificate fingerprint.
    ///
    /// Uses the default `WebPKI` root certificates for chain validation.
    ///
    /// # Arguments
    ///
    /// * `expected_fingerprint` - The SHA-256 fingerprint from the ANS badge's
    ///   `attestations.server_cert.fingerprint` field.
    pub fn new(expected_fingerprint: CertFingerprint) -> Result<Self, TlsError> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_root_store(expected_fingerprint, Arc::new(root_store))
    }

    /// Creates a new verifier with a custom root certificate store.
    ///
    /// Use this if you need to trust additional CAs or have a custom PKI.
    ///
    /// # Arguments
    ///
    /// * `expected_fingerprint` - The SHA-256 fingerprint from the ANS badge
    /// * `root_store` - Custom root certificate store for chain validation
    pub fn with_root_store(
        expected_fingerprint: CertFingerprint,
        root_store: Arc<rustls::RootCertStore>,
    ) -> Result<Self, TlsError> {
        let webpki_verifier = rustls::client::WebPkiServerVerifier::builder(root_store)
            .build()
            .map_err(|e| TlsError::General(format!("Failed to build WebPKI verifier: {e}")))?;

        Ok(Self {
            expected_fingerprint,
            webpki_verifier,
        })
    }

    /// Returns the expected fingerprint this verifier is checking against.
    pub fn expected_fingerprint(&self) -> &CertFingerprint {
        &self.expected_fingerprint
    }
}

impl ServerCertVerifier for AnsServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // First, do standard WebPKI validation (chain, expiry, hostname)
        self.webpki_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;

        // Now verify the certificate fingerprint against the ANS badge
        let actual_fingerprint = CertFingerprint::from_der(end_entity.as_ref());

        if self.expected_fingerprint == actual_fingerprint {
            tracing::debug!("ANS server certificate verification successful");
            Ok(ServerCertVerified::assertion())
        } else {
            tracing::warn!("ANS server certificate fingerprint mismatch");
            tracing::debug!(
                expected = %self.expected_fingerprint,
                actual = %actual_fingerprint,
                "Fingerprint mismatch details"
            );
            Err(TlsError::General(
                "Server certificate fingerprint does not match ANS badge".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.webpki_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.webpki_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki_verifier.supported_verify_schemes()
    }
}

/// A rustls [`ClientCertVerifier`] for server-side mTLS with ANS agents.
///
/// This verifier validates that client certificates chain to the ANS Private CA
/// during the TLS handshake. It does NOT perform badge verification during the
/// handshake to avoid blocking.
///
/// # Two-Phase Verification Flow
///
/// Per the ANS specification, client verification happens in two phases:
///
/// 1. **TLS Handshake** (this verifier): Validate certificate chains to Private CA
/// 2. **Post-Handshake** (application code): Verify against transparency log badge
///
/// The first phase completes the TLS handshake. The second phase must complete
/// before processing any application requests.
///
/// # Usage
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use ans_verify::{AnsClientCertVerifier, AnsVerifier, CertIdentity};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Load ANS Private CA
/// let ca_pem = std::fs::read("ans-private-ca.pem")?;
/// let client_verifier = AnsClientCertVerifier::from_pem(&ca_pem)?;
///
/// // Configure server
/// # let server_certs = vec![];
/// # let server_key = todo!();
/// let server_config = rustls::ServerConfig::builder()
///     .with_client_cert_verifier(Arc::new(client_verifier))
///     .with_single_cert(server_certs, server_key)?;
///
/// // After handshake, verify against badge before processing requests
/// let verifier = AnsVerifier::new(["transparency.ans.godaddy.com"]).await?;
/// // let cert_identity = CertIdentity::from_der(peer_cert)?;
/// // let outcome = verifier.verify_client(&cert_identity).await;
/// # Ok(())
/// # }
/// ```
pub struct AnsClientCertVerifier {
    /// Delegate to `WebPKI` for chain validation against the Private CA
    inner: Arc<dyn ClientCertVerifier>,
    /// Whether to require client certificates
    require_client_cert: bool,
}

impl std::fmt::Debug for AnsClientCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnsClientCertVerifier")
            .field("require_client_cert", &self.require_client_cert)
            .finish_non_exhaustive()
    }
}

impl AnsClientCertVerifier {
    /// Creates a verifier from PEM-encoded ANS Private CA certificate(s).
    ///
    /// Client certificates are required by default.
    ///
    /// # Arguments
    ///
    /// * `ca_pem` - PEM-encoded ANS Private CA certificate(s)
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM cannot be parsed or contains no certificates.
    pub fn from_pem(ca_pem: &[u8]) -> Result<Self, TlsError> {
        let mut root_store = rustls::RootCertStore::empty();
        let certs = Self::parse_pem_certs(ca_pem)?;

        for cert in certs {
            root_store
                .add(cert)
                .map_err(|e| TlsError::General(format!("Failed to add CA cert: {e}")))?;
        }

        Self::from_root_store(Arc::new(root_store), true)
    }

    /// Creates a verifier from a pre-built root certificate store.
    ///
    /// # Arguments
    ///
    /// * `root_store` - Root certificate store containing the ANS Private CA
    /// * `require_client_cert` - Whether to require client certificates
    pub fn from_root_store(
        root_store: Arc<rustls::RootCertStore>,
        require_client_cert: bool,
    ) -> Result<Self, TlsError> {
        let builder = rustls::server::WebPkiClientVerifier::builder(root_store);

        let inner = if require_client_cert {
            builder.build()
        } else {
            builder.allow_unauthenticated().build()
        }
        .map_err(|e| TlsError::General(format!("Failed to build client verifier: {e}")))?;

        Ok(Self {
            inner,
            require_client_cert,
        })
    }

    /// Creates a verifier that makes client certificates optional.
    ///
    /// Use this when you want to allow both authenticated and unauthenticated clients.
    /// Post-handshake verification will determine whether a client certificate was
    /// presented and whether it's valid.
    pub fn from_pem_optional(ca_pem: &[u8]) -> Result<Self, TlsError> {
        let mut root_store = rustls::RootCertStore::empty();
        let certs = Self::parse_pem_certs(ca_pem)?;

        for cert in certs {
            root_store
                .add(cert)
                .map_err(|e| TlsError::General(format!("Failed to add CA cert: {e}")))?;
        }

        Self::from_root_store(Arc::new(root_store), false)
    }

    /// Returns whether client certificates are required.
    pub fn requires_client_cert(&self) -> bool {
        self.require_client_cert
    }

    fn parse_pem_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
        use rustls_pki_types::pem::PemObject;

        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::General(format!("Failed to parse PEM: {e}")))?;

        if certs.is_empty() {
            return Err(TlsError::General(
                "No certificates found in PEM data".into(),
            ));
        }

        Ok(certs)
    }
}

impl ClientCertVerifier for AnsClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        // Delegate to WebPKI for chain validation against the Private CA
        // This does NOT perform ANS badge verification (that happens post-handshake)
        let result = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;

        // Log the certificate identity for debugging
        if let Ok(identity) = crate::CertIdentity::from_der(end_entity.as_ref()) {
            tracing::debug!(
                cn = ?identity.common_name,
                dns_sans = ?identity.dns_sans,
                uri_sans = ?identity.uri_sans,
                "Client certificate chain validated against Private CA (badge verification pending)"
            );
        }

        Ok(result)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.require_client_cert
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_creation() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let fp = CertFingerprint::parse(
            "SHA256:d8ff1383fe0965ca11b383e095b03cfecbf3285e45b096463a192cf58e18bc67",
        )
        .unwrap();
        let verifier = AnsServerCertVerifier::new(fp.clone()).unwrap();
        assert_eq!(verifier.expected_fingerprint(), &fp);
    }

    // ── 8a: AnsServerCertVerifier ────────────────────────────────────

    #[test]
    fn test_server_verifier_with_root_store() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let fp = CertFingerprint::from_bytes([0xab; 32]);
        let verifier =
            AnsServerCertVerifier::with_root_store(fp.clone(), Arc::new(root_store)).unwrap();
        assert_eq!(verifier.expected_fingerprint(), &fp);
    }

    #[test]
    fn test_server_verifier_supported_schemes_non_empty() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let fp = CertFingerprint::from_bytes([0xab; 32]);
        let verifier = AnsServerCertVerifier::new(fp).unwrap();
        assert!(!verifier.supported_verify_schemes().is_empty());
    }

    #[test]
    fn test_server_verifier_debug_format() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let fp = CertFingerprint::from_bytes([0xab; 32]);
        let verifier = AnsServerCertVerifier::new(fp).unwrap();
        let dbg = format!("{verifier:?}");
        assert!(dbg.contains("AnsServerCertVerifier"));
    }

    // ── 8b: AnsClientCertVerifier construction ───────────────────────

    fn generate_test_ca_pem() -> Vec<u8> {
        let ca = rcgen::generate_simple_self_signed(vec!["ANS Test CA".to_string()]).unwrap();
        ca.cert.pem().into_bytes()
    }

    #[test]
    fn test_client_verifier_from_pem_success() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pem = generate_test_ca_pem();
        let verifier = AnsClientCertVerifier::from_pem(&pem).unwrap();
        assert!(verifier.requires_client_cert());
    }

    #[test]
    fn test_client_verifier_from_pem_optional() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pem = generate_test_ca_pem();
        let verifier = AnsClientCertVerifier::from_pem_optional(&pem).unwrap();
        assert!(!verifier.requires_client_cert());
    }

    #[test]
    fn test_client_verifier_from_pem_invalid() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let result = AnsClientCertVerifier::from_pem(b"this is not PEM data");
        assert!(result.is_err());
    }

    #[test]
    fn test_client_verifier_from_pem_empty() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let result = AnsClientCertVerifier::from_pem(b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_client_verifier_from_root_store() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pem = generate_test_ca_pem();
        let certs = AnsClientCertVerifier::parse_pem_certs(&pem).unwrap();

        let mut root_store = rustls::RootCertStore::empty();
        for cert in certs {
            root_store.add(cert).unwrap();
        }

        let verifier = AnsClientCertVerifier::from_root_store(Arc::new(root_store), true).unwrap();
        assert!(verifier.requires_client_cert());
    }

    #[test]
    fn test_client_verifier_debug_format() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pem = generate_test_ca_pem();
        let verifier = AnsClientCertVerifier::from_pem(&pem).unwrap();
        let dbg = format!("{verifier:?}");
        assert!(dbg.contains("AnsClientCertVerifier"));
        assert!(dbg.contains("require_client_cert"));
    }

    // ── 8c: ClientCertVerifier trait methods ─────────────────────────

    #[test]
    fn test_client_auth_mandatory_required() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pem = generate_test_ca_pem();
        let verifier = AnsClientCertVerifier::from_pem(&pem).unwrap();
        assert!(verifier.client_auth_mandatory());
    }

    #[test]
    fn test_client_auth_mandatory_optional() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pem = generate_test_ca_pem();
        let verifier = AnsClientCertVerifier::from_pem_optional(&pem).unwrap();
        assert!(!verifier.client_auth_mandatory());
    }

    #[test]
    fn test_root_hint_subjects_callable() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pem = generate_test_ca_pem();
        let verifier = AnsClientCertVerifier::from_pem(&pem).unwrap();
        // Just verify this doesn't panic
        let _subjects = verifier.root_hint_subjects();
    }

    #[test]
    fn test_client_supported_verify_schemes() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pem = generate_test_ca_pem();
        let verifier = AnsClientCertVerifier::from_pem(&pem).unwrap();
        assert!(!verifier.supported_verify_schemes().is_empty());
    }
}
