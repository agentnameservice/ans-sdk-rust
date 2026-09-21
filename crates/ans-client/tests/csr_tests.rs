#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::items_after_test_module
)]
//! Tests for [`AnsCsrBuilder`], asserting against the generated DER rather
//! than the builder's inputs.

use ans_client::csr::AnsCsrBuilder;
use ans_client::{AnsName, Fqdn, Version};
use rstest::rstest;
use secrecy::{ExposeSecret, SecretString};
use x509_parser::{pem::parse_x509_pem, prelude::*, public_key::PublicKey};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn fqdn(host: &str) -> Fqdn {
    Fqdn::new(host).expect("test host must be a valid FQDN")
}

fn version(v: &str) -> Version {
    Version::parse(v).expect("test version must be valid")
}

fn server_csr(host: &str, v: &str) -> ans_client::CsrOutput {
    AnsCsrBuilder::server(fqdn(host), version(v))
        .build()
        .expect("server CSR should build")
}

fn identity_csr(host: &str, v: &str) -> ans_client::CsrOutput {
    AnsCsrBuilder::identity(fqdn(host), version(v))
        .build()
        .expect("identity CSR should build")
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let (_, pem_obj) = parse_x509_pem(pem.as_bytes()).expect("PEM decode failed");
    pem_obj.contents
}

fn find_extension<T>(csr_pem: &str, f: impl FnMut(&ParsedExtension<'_>) -> Option<T>) -> Option<T> {
    let der = pem_to_der(csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");
    csr.requested_extensions()
        .and_then(|mut exts| exts.find_map(f))
}

fn subject_alt_names(csr_pem: &str) -> Vec<String> {
    find_extension(csr_pem, |ext| match ext {
        ParsedExtension::SubjectAlternativeName(san) => Some(
            san.general_names
                .iter()
                .map(|n| match n {
                    GeneralName::DNSName(d) => format!("DNS:{d}"),
                    GeneralName::URI(u) => format!("URI:{u}"),
                    other => format!("OTHER:{other:?}"),
                })
                .collect(),
        ),
        _ => None,
    })
    .expect("CSR must carry a SubjectAlternativeName extension")
}

fn key_usage(csr_pem: &str) -> KeyUsage {
    find_extension(csr_pem, |ext| match ext {
        ParsedExtension::KeyUsage(ku) => Some(*ku),
        _ => None,
    })
    .expect("KeyUsage extension must be present")
}

/// Returns `(server_auth, client_auth)`.
fn eku(csr_pem: &str) -> (bool, bool) {
    find_extension(csr_pem, |ext| match ext {
        ParsedExtension::ExtendedKeyUsage(eku) => Some((eku.server_auth, eku.client_auth)),
        _ => None,
    })
    .expect("ExtendedKeyUsage extension must be present")
}

fn common_name(csr_pem: &str) -> Option<String> {
    let der = pem_to_der(csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");
    csr.certification_request_info
        .subject
        .iter_common_name()
        .next()
        .map(|cn| {
            cn.as_str()
                .expect("CN must be a printable string")
                .to_string()
        })
}

fn rsa_key_size(csr_pem: &str) -> usize {
    let der = pem_to_der(csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");
    let Ok(PublicKey::RSA(rsa_pk)) = csr.certification_request_info.subject_pki.parsed() else {
        panic!("CSR must embed an RSA public key");
    };
    rsa_pk.key_size()
}

// ── Subject CN ────────────────────────────────────────────────────────────────

/// Deprecated and unread: public CAs and the RA both match the DNS SAN, and a
/// CN over RFC 5280's 64-character bound is dropped rather than honoured.
#[test]
fn server_csr_omits_common_name() {
    let out = server_csr("agent.example.com", "1.2.3");
    assert_eq!(
        common_name(&out.csr_pem),
        None,
        "server CSR must not carry a subject CN"
    );
}

/// Load-bearing: the ANS private CA copies this subject and adds no DNS SAN,
/// so dropping the CN would strip the identity cert's only FQDN carrier.
#[test]
fn identity_csr_cn_equals_hostname() {
    let out = identity_csr("id.example.ai", "0.9.1");
    assert_eq!(common_name(&out.csr_pem), Some("id.example.ai".to_string()));
}

/// A host too long for a conformant CN must still yield a usable server CSR,
/// with the name carried by the SAN rather than truncated into the subject.
#[test]
fn server_csr_with_long_host_omits_cn_and_still_builds() {
    let host = format!(
        "{}.{}.{}.example.com",
        "a".repeat(60),
        "b".repeat(60),
        "c".repeat(60)
    );
    assert!(
        host.len() > 64,
        "test host must exceed the 64-char CN limit"
    );

    let out = server_csr(&host, "1.0.0");
    assert_eq!(common_name(&out.csr_pem), None);
    assert_eq!(subject_alt_names(&out.csr_pem), vec![format!("DNS:{host}")]);
}

// ── SANs ──────────────────────────────────────────────────────────────────────

#[test]
fn server_csr_san_contains_dns_hostname() {
    let out = server_csr("svc.example.com", "2.0.0");
    assert!(
        subject_alt_names(&out.csr_pem).contains(&"DNS:svc.example.com".to_string()),
        "SAN must contain DNS:svc.example.com"
    );
}

#[test]
fn identity_csr_san_contains_dns_hostname() {
    let out = identity_csr("id.example.ai", "1.0.0");
    assert!(
        subject_alt_names(&out.csr_pem).contains(&"DNS:id.example.ai".to_string()),
        "SAN must contain DNS:id.example.ai"
    );
}

/// A URI SAN here is fatal: the RA forwards this CSR to a public CA unchanged,
/// and public CAs reject requests carrying one.
#[rstest]
#[case("example.ai", "1.0.0")]
#[case("my-agent.example.com", "0.1.2")]
#[case("race-ready.ai", "10.20.30")]
fn server_csr_has_no_uri_san(#[case] host: &str, #[case] v: &str) {
    let out = server_csr(host, v);
    let sans = subject_alt_names(&out.csr_pem);

    assert_eq!(
        sans,
        vec![format!("DNS:{host}")],
        "server CSR must carry the DNS SAN and nothing else"
    );
    assert!(
        !sans.iter().any(|s| s.starts_with("URI:")),
        "server CSR must not carry a URI SAN, got {sans:?}"
    );
}

/// The verifier recovers both version and FQDN from this SAN alone.
#[rstest]
#[case("example.ai", "1.0.0", "ans://v1.0.0.example.ai")]
#[case("id.svc.com", "2.3.4", "ans://v2.3.4.id.svc.com")]
#[case("my-agent.example.com", "0.1.2", "ans://v0.1.2.my-agent.example.com")]
#[case("race-ready.ai", "10.20.30", "ans://v10.20.30.race-ready.ai")]
fn identity_csr_san_uri_is_ans_format(
    #[case] host: &str,
    #[case] v: &str,
    #[case] expected_uri: &str,
) {
    let out = identity_csr(host, v);
    let sans = subject_alt_names(&out.csr_pem);

    assert_eq!(
        sans,
        vec![format!("DNS:{host}"), format!("URI:{expected_uri}")],
        "identity CSR must carry the DNS SAN followed by the ANS URI SAN"
    );
    AnsName::parse(expected_uri).expect("generated URI SAN must round-trip through AnsName");
}

/// `Version` already renders its own `v` prefix, so a second one would yield
/// `ans://vv1.2.3.…`.
#[test]
fn identity_csr_uri_san_does_not_double_prefix_version() {
    let out = AnsCsrBuilder::identity(fqdn("agent.example.com"), Version::new(1, 2, 3))
        .build()
        .expect("identity CSR should build");

    let uri = subject_alt_names(&out.csr_pem)
        .into_iter()
        .find_map(|s| s.strip_prefix("URI:").map(str::to_string))
        .expect("identity CSR must carry a URI SAN");

    assert_eq!(uri, "ans://v1.2.3.agent.example.com");
    assert!(!uri.contains("vv"), "version prefix must not be doubled");

    let parsed = AnsName::parse(&uri).expect("URI SAN must parse as an ANS name");
    assert_eq!(parsed.version(), &Version::new(1, 2, 3));
    assert_eq!(parsed.fqdn().as_str(), "agent.example.com");
}

/// `Version::parse` takes both `1.2.3` and `v1.2.3`; the SAN must not differ.
#[test]
fn identity_csr_uri_san_is_independent_of_version_spelling() {
    let bare = identity_csr("agent.example.com", "1.2.3");
    let prefixed = identity_csr("agent.example.com", "v1.2.3");

    assert_eq!(
        subject_alt_names(&bare.csr_pem),
        subject_alt_names(&prefixed.csr_pem)
    );
}

// ── Input validation ──────────────────────────────────────────────────────────

/// Malformed input is unrepresentable, so it never reaches key generation.
#[rstest]
#[case::empty("")]
#[case::space("bad host")]
#[case::empty_label("a..b")]
#[case::label_too_long(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com"
)]
#[case::underscore("bad_host.example.com")]
#[case::leading_hyphen("-bad.example.com")]
fn invalid_hosts_are_rejected(#[case] host: &str) {
    assert!(
        Fqdn::new(host).is_err(),
        "{host:?} must not parse as an FQDN"
    );
}

#[rstest]
#[case::empty("")]
#[case::two_parts("1.2")]
#[case::four_parts("1.2.3.4")]
#[case::prerelease("1.2.3-rc1")]
#[case::build_metadata("1.2.3+build.5")]
#[case::non_numeric("a.b.c")]
fn invalid_versions_are_rejected(#[case] v: &str) {
    assert!(Version::parse(v).is_err(), "{v:?} must not parse");
}

/// `Fqdn` lowercases, so caller spelling must not leak into any of the three
/// name fields.
#[test]
fn host_is_normalized_to_lowercase() {
    let out = identity_csr("Agent.Example.COM", "1.0.0");

    assert_eq!(
        common_name(&out.csr_pem),
        Some("agent.example.com".to_string())
    );
    assert_eq!(
        subject_alt_names(&out.csr_pem),
        vec![
            "DNS:agent.example.com".to_string(),
            "URI:ans://v1.0.0.agent.example.com".to_string(),
        ]
    );
}

// ── Extended Key Usage ────────────────────────────────────────────────────────

/// The wrong EKU here is a 422 from the RA, not a local error.
#[test]
fn server_csr_has_server_auth_eku_only() {
    let out = server_csr("agent.example.com", "1.0.0");
    let (server_auth, client_auth) = eku(&out.csr_pem);

    assert!(server_auth, "server CSR must request ServerAuth EKU");
    assert!(!client_auth, "server CSR must not request ClientAuth EKU");
}

#[test]
fn identity_csr_has_client_auth_eku_only() {
    let out = identity_csr("agent.example.com", "1.0.0");
    let (server_auth, client_auth) = eku(&out.csr_pem);

    assert!(!server_auth, "identity CSR must not request ServerAuth EKU");
    assert!(client_auth, "identity CSR must request ClientAuth EKU");
}

// ── Key Usage ─────────────────────────────────────────────────────────────────

/// `keyEncipherment` is required for TLS 1.2 RSA key exchange, not just 1.3.
#[test]
fn server_csr_key_usage_digital_signature_and_key_encipherment() {
    let out = server_csr("agent.example.com", "1.0.0");
    let ku = key_usage(&out.csr_pem);

    assert!(
        ku.digital_signature(),
        "server CSR must request DigitalSignature"
    );
    assert!(
        ku.key_encipherment(),
        "server CSR must request KeyEncipherment"
    );
    assert!(
        !ku.key_agreement(),
        "server CSR must not request KeyAgreement"
    );
    assert!(
        !ku.data_encipherment(),
        "server CSR must not request DataEncipherment"
    );
}

/// Identity certs never do key exchange, so `keyEncipherment` must be absent.
#[test]
fn identity_csr_key_usage_digital_signature_only() {
    let out = identity_csr("agent.example.com", "1.0.0");
    let ku = key_usage(&out.csr_pem);

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

/// Pins the default against drifting below the RA's 2048-bit floor; the RA
/// itself also accepts larger RSA and ECDSA P-256/P-384.
#[test]
fn server_csr_embeds_rsa_2048_public_key() {
    assert_eq!(
        rsa_key_size(&server_csr("agent.example.com", "1.0.0").csr_pem),
        2048
    );
}

#[test]
fn identity_csr_embeds_rsa_2048_public_key() {
    assert_eq!(
        rsa_key_size(&identity_csr("agent.example.com", "1.0.0").csr_pem),
        2048
    );
}

/// Strict-parsed, not substring-matched: rcgen stamps a PKCS#8 label on
/// whatever DER it holds, so only decoding the body proves the format.
#[rstest]
#[case::server(server_csr("agent.example.com", "1.0.0"))]
#[case::identity(identity_csr("agent.example.com", "1.0.0"))]
fn private_key_pem_parses_as_pkcs8(#[case] out: ans_client::CsrOutput) {
    let (oid, _) = strict_pkcs8(out.private_key_pem.expose_secret());
    assert_eq!(oid, RSA_ENCRYPTION);
}

// ── Secret handling ───────────────────────────────────────────────────────────

/// `CsrOutput` reaches `tracing::debug!(?output)` on ordinary paths.
#[rstest]
#[case::server(server_csr("agent.example.com", "1.0.0"))]
#[case::identity(identity_csr("agent.example.com", "1.0.0"))]
fn debug_output_redacts_private_key(#[case] out: ans_client::CsrOutput) {
    let rendered = format!("{out:?}");
    let key = out.private_key_pem.expose_secret();

    assert!(
        !rendered.contains("BEGIN PRIVATE KEY"),
        "Debug output must not contain the PEM header"
    );
    for line in key.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            !rendered.contains(line),
            "Debug output leaked a private-key line: {line}"
        );
    }
    assert!(
        rendered.contains("REDACTED"),
        "Debug output should mark the key as redacted, got: {rendered}"
    );
    // The CSR itself is public and stays visible for diagnostics.
    assert!(rendered.contains("CERTIFICATE REQUEST"));
}

// ── Uniqueness ────────────────────────────────────────────────────────────────

/// Two agents running identical code must not end up sharing a private key.
#[test]
fn two_server_csrs_differ() {
    let a = server_csr("agent.example.com", "1.0.0");
    let b = server_csr("agent.example.com", "1.0.0");

    assert_ne!(a.csr_pem, b.csr_pem, "each build must produce a unique CSR");
    assert_ne!(
        a.private_key_pem.expose_secret(),
        b.private_key_pem.expose_secret(),
        "each build must produce a unique private key"
    );
}

#[test]
fn two_identity_csrs_differ() {
    let a = identity_csr("agent.example.com", "1.0.0");
    let b = identity_csr("agent.example.com", "1.0.0");

    assert_ne!(a.csr_pem, b.csr_pem);
    assert_ne!(
        a.private_key_pem.expose_secret(),
        b.private_key_pem.expose_secret()
    );
}

// ── Key binding ───────────────────────────────────────────────────────────────

/// The CSR is only usable if it was signed by the key it embeds; a CA rejects
/// it otherwise.
#[rstest]
#[case::server(server_csr("agent.example.com", "1.0.0"))]
#[case::identity(identity_csr("agent.example.com", "1.0.0"))]
fn csr_self_signature_verifies(#[case] out: ans_client::CsrOutput) {
    let der = pem_to_der(&out.csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");
    csr.verify_signature()
        .expect("CSR self-signature must verify");
}

/// Guards the pairing itself: generating the key twice would still pass every
/// structural assertion above while yielding a certificate whose key the agent
/// does not hold.
#[rstest]
#[case::server(server_csr("agent.example.com", "1.0.0"))]
#[case::identity(identity_csr("agent.example.com", "1.0.0"))]
fn returned_private_key_matches_csr_public_key(#[case] out: ans_client::CsrOutput) {
    let der = pem_to_der(&out.csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");
    let key = rcgen::KeyPair::from_pem(out.private_key_pem.expose_secret())
        .expect("returned private key must parse");

    assert_eq!(
        key.public_key_raw(),
        csr.certification_request_info
            .subject_pki
            .subject_public_key
            .data
            .as_ref(),
        "CSR embeds a different public key than the returned private key"
    );
}

// ── Key reuse ─────────────────────────────────────────────────────────────────

/// Renewal reuses the key so the reissued certificate's public key is stable.
#[test]
fn supplied_key_pair_is_reused_verbatim() {
    let first = server_csr("agent.example.com", "1.0.0");
    let reused = AnsCsrBuilder::server(fqdn("agent.example.com"), version("1.0.1"))
        .with_key_pair_pem(SecretString::from(
            first.private_key_pem.expose_secret().to_string(),
        ))
        .build()
        .expect("CSR should build from the supplied key");

    assert_eq!(
        reused.private_key_pem.expose_secret(),
        first.private_key_pem.expose_secret()
    );
    let (a, b) = (pem_to_der(&first.csr_pem), pem_to_der(&reused.csr_pem));
    let (_, csr_a) = X509CertificationRequest::from_der(&a).expect("CSR parse failed");
    let (_, csr_b) = X509CertificationRequest::from_der(&b).expect("CSR parse failed");
    assert_eq!(
        csr_a.certification_request_info.subject_pki.raw,
        csr_b.certification_request_info.subject_pki.raw,
        "reusing a key must reproduce the same public key"
    );
}

/// A supplied ECDSA key must work: the RA accepts P-256, and Method B wants it.
#[test]
fn supplied_ecdsa_key_is_accepted() {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("P-256 keygen");
    let out = AnsCsrBuilder::identity(fqdn("agent.example.com"), version("1.0.0"))
        .with_key_pair_pem(SecretString::from(key.serialize_pem()))
        .build()
        .expect("P-256 identity CSR should build");

    let der = pem_to_der(&out.csr_pem);
    let (_, csr) = X509CertificationRequest::from_der(&der).expect("CSR parse failed");
    csr.verify_signature().expect("P-256 CSR must verify");
    assert!(matches!(
        csr.certification_request_info.subject_pki.parsed(),
        Ok(PublicKey::EC(_))
    ));
}

/// Ed25519 is outside the RA's allowlist, so it must fail here rather than at
/// registration.
#[test]
fn supplied_ed25519_key_is_rejected() {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keygen");
    let err = AnsCsrBuilder::server(fqdn("agent.example.com"), version("1.0.0"))
        .with_key_pair_pem(SecretString::from(key.serialize_pem()))
        .build()
        .expect_err("Ed25519 must be rejected");

    assert!(matches!(err, ans_client::CsrError::UnsupportedKeyAlgorithm));
}

#[test]
fn malformed_key_pair_is_rejected() {
    let err = AnsCsrBuilder::server(fqdn("agent.example.com"), version("1.0.0"))
        .with_key_pair_pem(SecretString::from("-----BEGIN PRIVATE KEY-----\nnope\n"))
        .build()
        .expect_err("garbage key must be rejected");

    assert!(matches!(err, ans_client::CsrError::InvalidKeyPair(_)));
}

// ── ANS host profile ──────────────────────────────────────────────────────────

type Ctor = fn(Fqdn, Version) -> AnsCsrBuilder;

/// Builds a host of exactly `total` octets from three 63-octet labels plus a
/// remainder label.
fn host_of_octets(total: usize) -> String {
    let head = format!("{}.{}.{}.", "a".repeat(63), "b".repeat(63), "c".repeat(63));
    format!("{head}{}", "d".repeat(total - head.len()))
}

/// `Fqdn` derives `Deserialize`, so this reaches the builder without ever
/// running `Fqdn::new`.
fn deserialized_fqdn(host: &str) -> Fqdn {
    let json = serde_json::to_string(host).expect("str serializes");
    serde_json::from_str::<Fqdn>(&json).expect("Fqdn derives Deserialize")
}

#[rstest]
#[case::server(AnsCsrBuilder::server as Ctor)]
#[case::identity(AnsCsrBuilder::identity as Ctor)]
fn host_over_253_octets_is_rejected(#[case] ctor: Ctor) {
    let host = host_of_octets(255);
    assert!(
        Fqdn::new(&host).is_ok(),
        "the shared type permits this; the builder is the gate"
    );

    let err = ctor(fqdn(&host), version("1.0.0"))
        .build()
        .expect_err("over-long host must be rejected");
    assert!(matches!(
        err,
        ans_client::CsrError::HostTooLong { octets: 255 }
    ));
}

#[rstest]
#[case::server(AnsCsrBuilder::server as Ctor)]
#[case::identity(AnsCsrBuilder::identity as Ctor)]
fn host_of_exactly_253_octets_is_accepted(#[case] ctor: Ctor) {
    let host = host_of_octets(253);
    let out = ctor(fqdn(&host), version("1.0.0"))
        .build()
        .expect("253 octets is within the limit");
    assert!(subject_alt_names(&out.csr_pem).contains(&format!("DNS:{host}")));
}

#[rstest]
#[case::server(AnsCsrBuilder::server as Ctor)]
#[case::identity(AnsCsrBuilder::identity as Ctor)]
fn single_label_host_is_rejected(#[case] ctor: Ctor) {
    assert!(Fqdn::new("localhost").is_ok(), "pinned by ans-types");

    let err = ctor(fqdn("localhost"), version("1.0.0"))
        .build()
        .expect_err("a single-label host must be rejected");
    assert!(matches!(err, ans_client::CsrError::HostNotFullyQualified));
}

/// `Fqdn::new` accepts a dotted quad as four numeric labels; the RA rejects it
/// so a registrant cannot aim the challenge at an internal address.
#[rstest]
#[case("127.0.0.1")]
#[case("192.168.0.1")]
#[case("169.254.169.254")]
fn ip_literal_host_is_rejected(#[case] host: &str) {
    assert!(Fqdn::new(host).is_ok());

    let err = AnsCsrBuilder::server(fqdn(host), version("1.0.0"))
        .build()
        .expect_err("IP literal must be rejected");
    assert!(matches!(err, ans_client::CsrError::HostIsIpLiteral));
}

#[rstest]
#[case("bad host.example.com")]
#[case("bad_host.example.com")]
#[case("-bad.example.com")]
#[case("a..b")]
#[case("")]
fn deserialized_invalid_host_is_rejected(#[case] host: &str) {
    let err = AnsCsrBuilder::server(deserialized_fqdn(host), version("1.0.0"))
        .build()
        .expect_err("deserialization must not bypass validation");
    assert!(matches!(err, ans_client::CsrError::InvalidName(_)));
}

/// Validation must also canonicalize: a deserialized value keeps its casing and
/// trailing dot, which would otherwise be encoded verbatim.
#[test]
fn deserialized_host_is_canonicalized_before_encoding() {
    let out = AnsCsrBuilder::identity(deserialized_fqdn("Agent.Example.COM."), version("1.0.0"))
        .build()
        .expect("canonicalizable host should build");

    assert_eq!(
        common_name(&out.csr_pem),
        Some("agent.example.com".to_string())
    );
    assert_eq!(
        subject_alt_names(&out.csr_pem),
        vec![
            "DNS:agent.example.com".to_string(),
            "URI:ans://v1.0.0.agent.example.com".to_string(),
        ]
    );
}

/// Makes the "before any key work" ordering observable rather than implicit.
#[test]
fn host_is_validated_before_the_supplied_key() {
    let err = AnsCsrBuilder::server(fqdn("localhost"), version("1.0.0"))
        .with_key_pair_pem(SecretString::from("-----BEGIN PRIVATE KEY-----\nnope\n"))
        .build()
        .expect_err("must fail");
    assert!(matches!(err, ans_client::CsrError::HostNotFullyQualified));
}

// ── Key encoding ──────────────────────────────────────────────────────────────

const RSA_ENCRYPTION: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// Decodes a PKCS#8 PEM strictly, returning its algorithm OID and inner key DER.
fn strict_pkcs8(pem: &str) -> (pkcs8::ObjectIdentifier, Vec<u8>) {
    let (label, doc) = pkcs8::SecretDocument::from_pem(pem).expect("must be valid PEM");
    assert_eq!(label, "PRIVATE KEY", "PKCS#8 uses the PRIVATE KEY label");
    let info =
        pkcs8::PrivateKeyInfoRef::try_from(doc.as_bytes()).expect("body must decode as PKCS#8");
    (info.algorithm.oid, info.private_key.as_bytes().to_vec())
}

/// The PKCS#8 `privateKey` octet string is itself the PKCS#1/SEC1 DER, so
/// re-wrapping it under `label` yields a genuine legacy key.
fn inner_key_pem(pkcs8_pem: &str, label: &'static str) -> SecretString {
    let (_, inner) = strict_pkcs8(pkcs8_pem);
    let doc = pkcs8::SecretDocument::try_from(inner.as_slice()).expect("inner DER is a sequence");
    let pem = doc
        .to_pem(label, pkcs8::LineEnding::LF)
        .expect("PEM re-encode");
    SecretString::from(pem.to_string())
}

#[test]
fn pkcs1_key_is_rejected() {
    let rsa = server_csr("agent.example.com", "1.0.0");
    let pkcs1 = inner_key_pem(rsa.private_key_pem.expose_secret(), "RSA PRIVATE KEY");

    let err = AnsCsrBuilder::server(fqdn("agent.example.com"), version("1.0.0"))
        .with_key_pair_pem(pkcs1)
        .build()
        .expect_err("PKCS#1 must be rejected");
    assert!(matches!(err, ans_client::CsrError::KeyNotPkcs8));
}

#[test]
fn sec1_key_is_rejected() {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("P-256 keygen");
    let sec1 = inner_key_pem(&key.serialize_pem(), "EC PRIVATE KEY");

    let err = AnsCsrBuilder::identity(fqdn("agent.example.com"), version("1.0.0"))
        .with_key_pair_pem(sec1)
        .build()
        .expect_err("SEC1 must be rejected");
    assert!(matches!(err, ans_client::CsrError::KeyNotPkcs8));
}

/// Byte-for-byte what the unfixed builder emitted, and the reason the gate has
/// to decode the body rather than trust the PEM label.
#[test]
fn pkcs1_body_mislabelled_as_pkcs8_is_rejected() {
    let rsa = server_csr("agent.example.com", "1.0.0");
    let mislabelled = inner_key_pem(rsa.private_key_pem.expose_secret(), "PRIVATE KEY");

    let err = AnsCsrBuilder::server(fqdn("agent.example.com"), version("1.0.0"))
        .with_key_pair_pem(mislabelled)
        .build()
        .expect_err("a PKCS#1 body under a PKCS#8 label must be rejected");
    assert!(matches!(err, ans_client::CsrError::KeyNotPkcs8));
}

#[test]
fn supplied_key_round_trip_stays_pkcs8() {
    let first = server_csr("agent.example.com", "1.0.0");
    let again = AnsCsrBuilder::server(fqdn("agent.example.com"), version("1.0.1"))
        .with_key_pair_pem(SecretString::from(
            first.private_key_pem.expose_secret().to_string(),
        ))
        .build()
        .expect("renewal should build");

    let (oid, _) = strict_pkcs8(again.private_key_pem.expose_secret());
    assert_eq!(oid, RSA_ENCRYPTION);
}

#[test]
fn supplied_ecdsa_key_output_is_pkcs8() {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("P-256 keygen");
    let out = AnsCsrBuilder::identity(fqdn("agent.example.com"), version("1.0.0"))
        .with_key_pair_pem(SecretString::from(key.serialize_pem()))
        .build()
        .expect("P-256 CSR should build");

    let (oid, _) = strict_pkcs8(out.private_key_pem.expose_secret());
    assert_eq!(oid, EC_PUBLIC_KEY);
}
