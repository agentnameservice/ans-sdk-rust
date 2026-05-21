#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::items_after_test_module
)]
//! Tests for [`AnsCsrBuilder`].
//!
//! Each test parses the generated CSR with `x509-parser` to verify that
//! Subject CN, SANs, Extended Key Usage, and Key Usage extensions are exactly
//! what the ANS PKI requires.

use ans_client::csr::AnsCsrBuilder;
use rstest::rstest;
use x509_parser::{pem::parse_x509_pem, prelude::*, public_key::PublicKey};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Decode a PEM-encoded CSR to its raw DER bytes.
fn pem_to_der(pem: &str) -> Vec<u8> {
    let (_, pem_obj) = parse_x509_pem(pem.as_bytes()).expect("PEM decode failed");
    pem_obj.contents
}

// ── Subject CN ────────────────────────────────────────────────────────────────

#[test]
fn server_csr_cn_equals_hostname() {
    let out = AnsCsrBuilder::server("agent.example.com", "1.2.3")
        .build()
        .unwrap();
    let der = pem_to_der(&out.csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");

    let cn = csr
        .certification_request_info
        .subject
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .expect("subject must have a CN attribute");

    assert_eq!(cn, "agent.example.com");
}

#[test]
fn identity_csr_cn_equals_hostname() {
    let out = AnsCsrBuilder::identity("id.example.ai", "0.9.1")
        .build()
        .unwrap();
    let der = pem_to_der(&out.csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");

    let cn = csr
        .certification_request_info
        .subject
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .expect("subject must have a CN attribute");

    assert_eq!(cn, "id.example.ai");
}

// ── Subject Alternative Names ─────────────────────────────────────────────────

#[test]
fn server_csr_san_contains_dns_hostname() {
    let out = AnsCsrBuilder::server("svc.example.com", "2.0.0")
        .build()
        .unwrap();
    let der = pem_to_der(&out.csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");

    let has_dns = csr.requested_extensions().is_some_and(|mut exts| {
        exts.any(|ext| {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                san.general_names
                    .iter()
                    .any(|n| matches!(n, GeneralName::DNSName(d) if *d == "svc.example.com"))
            } else {
                false
            }
        })
    });

    assert!(has_dns, "SAN must contain DNS:svc.example.com");
}

#[test]
fn identity_csr_san_contains_dns_hostname() {
    let out = AnsCsrBuilder::identity("id.example.ai", "1.0.0")
        .build()
        .unwrap();
    let der = pem_to_der(&out.csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");

    let has_dns = csr.requested_extensions().is_some_and(|mut exts| {
        exts.any(|ext| {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                san.general_names
                    .iter()
                    .any(|n| matches!(n, GeneralName::DNSName(d) if *d == "id.example.ai"))
            } else {
                false
            }
        })
    });

    assert!(has_dns, "SAN must contain DNS:id.example.ai");
}

/// The URI SAN must be `ans://v{version}.{host}` so that the ANS verifier can
/// extract the version and FQDN from the mTLS identity certificate.
#[rstest]
#[case("example.ai", "1.0.0", "ans://v1.0.0.example.ai")]
#[case("my-agent.example.com", "0.1.2", "ans://v0.1.2.my-agent.example.com")]
#[case("race-ready.ai", "10.20.30", "ans://v10.20.30.race-ready.ai")]
fn server_csr_san_uri_is_ans_format(
    #[case] host: &str,
    #[case] version: &str,
    #[case] expected_uri: &str,
) {
    let out = AnsCsrBuilder::server(host, version).build().unwrap();
    let der = pem_to_der(&out.csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");

    let uri = csr
        .requested_extensions()
        .and_then(|mut exts| {
            exts.find_map(|ext| {
                if let ParsedExtension::SubjectAlternativeName(san) = ext {
                    san.general_names.iter().find_map(|n| {
                        if let GeneralName::URI(u) = n {
                            Some((*u).to_owned())
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            })
        })
        .expect("SAN must contain a URI entry");

    assert_eq!(uri, expected_uri);
}

#[rstest]
#[case("example.ai", "1.0.0", "ans://v1.0.0.example.ai")]
#[case("id.svc.com", "2.3.4", "ans://v2.3.4.id.svc.com")]
fn identity_csr_san_uri_is_ans_format(
    #[case] host: &str,
    #[case] version: &str,
    #[case] expected_uri: &str,
) {
    let out = AnsCsrBuilder::identity(host, version).build().unwrap();
    let der = pem_to_der(&out.csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");

    let uri = csr
        .requested_extensions()
        .and_then(|mut exts| {
            exts.find_map(|ext| {
                if let ParsedExtension::SubjectAlternativeName(san) = ext {
                    san.general_names.iter().find_map(|n| {
                        if let GeneralName::URI(u) = n {
                            Some((*u).to_owned())
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            })
        })
        .expect("SAN must contain a URI entry");

    assert_eq!(uri, expected_uri);
}

// ── Extended Key Usage ────────────────────────────────────────────────────────

/// Server CSRs must request `id-kp-serverAuth` (OID 1.3.6.1.5.5.7.3.1).
/// Submitting a CSR with `clientAuth` would result in a 422 from the ANS API.
#[test]
fn server_csr_has_server_auth_eku_only() {
    let out = AnsCsrBuilder::server("agent.example.com", "1.0.0")
        .build()
        .unwrap();
    let der = pem_to_der(&out.csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");

    let (server_auth, client_auth) = csr
        .requested_extensions()
        .and_then(|mut exts| {
            exts.find_map(|ext| {
                if let ParsedExtension::ExtendedKeyUsage(eku) = ext {
                    Some((eku.server_auth, eku.client_auth))
                } else {
                    None
                }
            })
        })
        .expect("EKU extension must be present");

    assert!(server_auth, "server CSR must request ServerAuth EKU");
    assert!(!client_auth, "server CSR must not request ClientAuth EKU");
}

/// Identity CSRs must request `id-kp-clientAuth` (OID 1.3.6.1.5.5.7.3.2).
/// Submitting a CSR with `serverAuth` would result in a 422 from the ANS API.
#[test]
fn identity_csr_has_client_auth_eku_only() {
    let out = AnsCsrBuilder::identity("agent.example.com", "1.0.0")
        .build()
        .unwrap();
    let der = pem_to_der(&out.csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");

    let (server_auth, client_auth) = csr
        .requested_extensions()
        .and_then(|mut exts| {
            exts.find_map(|ext| {
                if let ParsedExtension::ExtendedKeyUsage(eku) = ext {
                    Some((eku.server_auth, eku.client_auth))
                } else {
                    None
                }
            })
        })
        .expect("EKU extension must be present");

    assert!(!server_auth, "identity CSR must not request ServerAuth EKU");
    assert!(client_auth, "identity CSR must request ClientAuth EKU");
}

// ── Key Usage ─────────────────────────────────────────────────────────────────

/// Server certificates are used for TLS and need both `digitalSignature` (for
/// TLS 1.3 handshakes) and `keyEncipherment` (for RSA key exchange in TLS 1.2).
#[test]
fn server_csr_key_usage_digital_signature_and_key_encipherment() {
    let out = AnsCsrBuilder::server("agent.example.com", "1.0.0")
        .build()
        .unwrap();
    let der = pem_to_der(&out.csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");

    let ku = csr
        .requested_extensions()
        .and_then(|mut exts| {
            exts.find_map(|ext| {
                if let ParsedExtension::KeyUsage(ku) = ext {
                    Some(*ku)
                } else {
                    None
                }
            })
        })
        .expect("KeyUsage extension must be present");

    assert!(
        ku.digital_signature(),
        "server CSR must request DigitalSignature"
    );
    assert!(
        ku.key_encipherment(),
        "server CSR must request KeyEncipherment"
    );
    // Sanity: bits that must NOT be set
    assert!(
        !ku.key_agreement(),
        "server CSR must not request KeyAgreement"
    );
    assert!(
        !ku.data_encipherment(),
        "server CSR must not request DataEncipherment"
    );
}

/// Identity (mTLS client) certificates only need `digitalSignature`; they are
/// never used for key exchange, so `keyEncipherment` must be absent.
#[test]
fn identity_csr_key_usage_digital_signature_only() {
    let out = AnsCsrBuilder::identity("agent.example.com", "1.0.0")
        .build()
        .unwrap();
    let der = pem_to_der(&out.csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");

    let ku = csr
        .requested_extensions()
        .and_then(|mut exts| {
            exts.find_map(|ext| {
                if let ParsedExtension::KeyUsage(ku) = ext {
                    Some(*ku)
                } else {
                    None
                }
            })
        })
        .expect("KeyUsage extension must be present");

    assert!(
        ku.digital_signature(),
        "identity CSR must request DigitalSignature"
    );
    assert!(
        !ku.key_encipherment(),
        "identity CSR must not request KeyEncipherment"
    );
    assert!(
        !ku.key_agreement(),
        "identity CSR must not request KeyAgreement"
    );
}

// ── RSA-2048 key ──────────────────────────────────────────────────────────────

/// ANS PKI only accepts RSA-2048 keys; ECDSA keys lead to indefinite
/// `PENDING_CERTS` stalls with no error indication.
///
/// The key size is checked via the public key embedded in the CSR itself
/// (`SubjectPublicKeyInfo`), so no separate key-parsing dependency is needed.
#[test]
fn server_csr_embeds_rsa_2048_public_key() {
    let out = AnsCsrBuilder::server("agent.example.com", "1.0.0")
        .build()
        .unwrap();
    let der = pem_to_der(&out.csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");

    let Ok(PublicKey::RSA(rsa_pk)) = csr.certification_request_info.subject_pki.parsed() else {
        panic!("CSR must embed an RSA public key");
    };

    assert_eq!(
        rsa_pk.key_size(),
        2048,
        "embedded public key must be RSA-2048"
    );
}

#[test]
fn identity_csr_embeds_rsa_2048_public_key() {
    let out = AnsCsrBuilder::identity("agent.example.com", "1.0.0")
        .build()
        .unwrap();
    let der = pem_to_der(&out.csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");

    let Ok(PublicKey::RSA(rsa_pk)) = csr.certification_request_info.subject_pki.parsed() else {
        panic!("CSR must embed an RSA public key");
    };

    assert_eq!(
        rsa_pk.key_size(),
        2048,
        "embedded public key must be RSA-2048"
    );
}

/// Private key output must be in PKCS#8 PEM format so that it can be loaded
/// directly by TLS stacks (rustls, openssl) and other tools without conversion.
#[test]
fn server_private_key_pem_is_pkcs8() {
    let out = AnsCsrBuilder::server("agent.example.com", "1.0.0")
        .build()
        .unwrap();
    assert!(
        out.private_key_pem.contains("BEGIN PRIVATE KEY"),
        "private key must be PKCS#8 (BEGIN PRIVATE KEY), got: {}",
        &out.private_key_pem[..out.private_key_pem.find('\n').unwrap_or(40)]
    );
}

#[test]
fn identity_private_key_pem_is_pkcs8() {
    let out = AnsCsrBuilder::identity("agent.example.com", "1.0.0")
        .build()
        .unwrap();
    assert!(
        out.private_key_pem.contains("BEGIN PRIVATE KEY"),
        "private key must be PKCS#8 (BEGIN PRIVATE KEY), got: {}",
        &out.private_key_pem[..out.private_key_pem.find('\n').unwrap_or(40)]
    );
}

// ── Uniqueness ────────────────────────────────────────────────────────────────

/// Each call to `build()` must generate a fresh key pair so that two agents
/// running the same code never share a private key.
#[test]
fn two_server_csrs_differ() {
    let a = AnsCsrBuilder::server("agent.example.com", "1.0.0")
        .build()
        .unwrap();
    let b = AnsCsrBuilder::server("agent.example.com", "1.0.0")
        .build()
        .unwrap();

    assert_ne!(a.csr_pem, b.csr_pem, "each build must produce a unique CSR");
    assert_ne!(
        a.private_key_pem, b.private_key_pem,
        "each build must produce a unique private key"
    );
}

#[test]
fn two_identity_csrs_differ() {
    let a = AnsCsrBuilder::identity("agent.example.com", "1.0.0")
        .build()
        .unwrap();
    let b = AnsCsrBuilder::identity("agent.example.com", "1.0.0")
        .build()
        .unwrap();

    assert_ne!(a.csr_pem, b.csr_pem);
    assert_ne!(a.private_key_pem, b.private_key_pem);
}
