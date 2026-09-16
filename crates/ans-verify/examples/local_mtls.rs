#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Example: Full local mTLS flow with ANS verification
//!
//! Self-contained example that generates certificates in-memory, then runs a
//! TLS server and client demonstrating both sides of ANS verification:
//! - Client verifies server certificate against badge (during TLS handshake)
//! - Server verifies client identity certificate against badge (post-handshake)
//!
//! ```bash
//! cargo run --example local_mtls --features "rustls,test-support"
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use ans_types::{Badge, Version};
use ans_verify::{
    AnsClientCertVerifier, AnsServerCertVerifier, AnsVerifier, BadgeRecord, CertFingerprint,
    CertIdentity, DanePolicy, MockDnsResolver, MockTransparencyLogClient, VerificationOutcome,
};
use chrono::Utc;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use uuid::Uuid;

const TEST_HOST: &str = "test.agent.local";
const TEST_VERSION: &str = "v1.0.0";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "local_mtls=info,ans_verify=debug".into()),
        )
        .init();

    // --- Generate certificates in-memory ---

    println!("Generating test certificates in-memory...");
    let certs = generate_test_pki(TEST_HOST, TEST_VERSION)?;
    println!("  Server fingerprint: {}", certs.server_fingerprint);
    println!("  Client fingerprint: {}", certs.client_fingerprint);

    // --- Set up mock ANS infrastructure ---

    let badge_url = "https://tlog.test.local/v1/badges/test-agent";
    let badge = create_test_badge(
        TEST_HOST,
        TEST_VERSION,
        &certs.server_fingerprint,
        &certs.client_fingerprint,
    );

    let dns_record = BadgeRecord::new("ans-badge1", Some(Version::new(1, 0, 0)), badge_url);

    let dns = Arc::new(MockDnsResolver::new().with_records(TEST_HOST, vec![dns_record]));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

    let verifier = Arc::new(
        AnsVerifier::builder()
            .trusted_ra_domains(["tlog.test.local"])
            .dns_resolver(dns)
            .tlog_client(tlog)
            .dane_policy(DanePolicy::Disabled)
            .with_caching()
            .build()
            .await?,
    );

    // Pre-fetch badge so the client knows the expected server fingerprint
    let prefetched = verifier.prefetch(TEST_HOST).await?;
    let expected_server_fp = CertFingerprint::parse(prefetched.server_cert_fingerprint())?;

    // --- Configure TLS server (verifies client certs against ANS badge) ---

    let _ = rustls::crypto::ring::default_provider().install_default();

    let client_verifier = AnsClientCertVerifier::from_pem(certs.ca_pem.as_bytes())?;
    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(client_verifier))
        .with_single_cert(
            parse_certs(&certs.server_cert_pem),
            parse_key(&certs.server_key_pem).unwrap(),
        )?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = listener.local_addr()?;
    println!("Server listening on {server_addr}");

    // --- Configure TLS client (verifies server cert against ANS badge) ---

    let mut root_store = rustls::RootCertStore::empty();
    for cert in parse_certs(&certs.ca_pem) {
        root_store.add(cert)?;
    }

    let server_verifier =
        AnsServerCertVerifier::with_root_store(expected_server_fp, Arc::new(root_store))?;

    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(server_verifier))
        .with_client_auth_cert(
            parse_certs(&certs.client_cert_pem),
            parse_key(&certs.client_key_pem).unwrap(),
        )?;

    let connector = TlsConnector::from(Arc::new(client_config));

    // --- Run server and client ---

    let server_verifier = verifier.clone();
    let server_handle =
        tokio::spawn(async move { run_server(listener, acceptor, server_verifier).await });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    let client_result = run_client(server_addr, connector).await;
    let server_result = server_handle.await?;

    match (&client_result, &server_result) {
        (Ok(()), Ok(())) => println!("\nSUCCESS: Full mTLS with ANS verification completed"),
        _ => {
            println!("\nFAILURE:");
            if let Err(e) = &client_result {
                println!("  Client error: {e}");
            }
            if let Err(e) = &server_result {
                println!("  Server error: {e}");
            }
        }
    }

    Ok(())
}

async fn run_server(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    verifier: Arc<AnsVerifier>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (stream, peer_addr) = listener.accept().await?;
    println!("[server] TCP connection from {peer_addr}");

    // TLS handshake — AnsClientCertVerifier validates client cert chains to our CA
    let mut tls_stream = acceptor.accept(stream).await?;
    println!("[server] TLS handshake complete");

    // Post-handshake: verify client cert against ANS badge
    let (_, conn) = tls_stream.get_ref();
    let peer_certs = conn.peer_certificates().ok_or("No client certificate")?;
    let cert_identity = CertIdentity::from_der(peer_certs[0].as_ref())?;

    println!(
        "[server] Client identity: CN={:?}, ANS={:?}",
        cert_identity.common_name(),
        cert_identity.ans_name()
    );

    match verifier.verify_client(&cert_identity).await {
        VerificationOutcome::Verified { badge, .. } => {
            println!("[server] Client verified: {}", badge.agent_name());
        }
        other => {
            println!("[server] Client verification failed: {other:?}");
            return Err("Client ANS verification failed".into());
        }
    }

    // Exchange application data
    let mut buf = [0u8; 1024];
    let n = tls_stream.read(&mut buf).await?;
    println!("[server] Received: {}", String::from_utf8_lossy(&buf[..n]));
    tls_stream.write_all(b"Hello from verified server!").await?;

    Ok(())
}

async fn run_client(
    server_addr: SocketAddr,
    connector: TlsConnector,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let stream = TcpStream::connect(server_addr).await?;
    let server_name = ServerName::try_from(TEST_HOST.to_string())?;

    // TLS handshake — AnsServerCertVerifier validates server cert fingerprint against badge
    let mut tls_stream = connector.connect(server_name, stream).await?;
    println!("[client] TLS handshake complete — server cert verified against badge");

    tls_stream.write_all(b"Hello from verified client!").await?;
    let mut buf = [0u8; 1024];
    let n = tls_stream.read(&mut buf).await?;
    println!("[client] Received: {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}

// ---------------------------------------------------------------------------
// Certificate generation (in-memory, no filesystem)
// ---------------------------------------------------------------------------

struct TestPki {
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    server_fingerprint: String,
    client_cert_pem: String,
    client_key_pem: String,
    client_fingerprint: String,
}

fn generate_test_pki(host: &str, version: &str) -> Result<TestPki, rcgen::Error> {
    // CA
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "ANS Test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // Server cert
    let server_key = KeyPair::generate()?;
    let mut server_params = CertificateParams::default();
    server_params
        .distinguished_name
        .push(DnType::CommonName, host);
    server_params
        .subject_alt_names
        .push(SanType::DnsName(host.to_string().try_into().unwrap()));
    server_params.subject_alt_names.push(SanType::URI(
        format!("ans://{version}.{host}").try_into().unwrap(),
    ));
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let server_cert = server_params.signed_by(&server_key, &issuer)?;

    // Client cert
    let client_key = KeyPair::generate()?;
    let mut client_params = CertificateParams::default();
    client_params
        .distinguished_name
        .push(DnType::CommonName, host);
    client_params
        .subject_alt_names
        .push(SanType::DnsName(host.to_string().try_into().unwrap()));
    client_params.subject_alt_names.push(SanType::URI(
        format!("ans://{version}.{host}").try_into().unwrap(),
    ));
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let client_cert = client_params.signed_by(&client_key, &issuer)?;

    Ok(TestPki {
        ca_pem: ca_cert.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        server_fingerprint: fingerprint(server_cert.der()),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
        client_fingerprint: fingerprint(client_cert.der()),
    })
}

fn fingerprint(der: &[u8]) -> String {
    format!("SHA256:{}", hex::encode(Sha256::digest(der)))
}

// ---------------------------------------------------------------------------
// Badge construction
// ---------------------------------------------------------------------------

fn create_test_badge(host: &str, version: &str, server_fp: &str, identity_fp: &str) -> Badge {
    serde_json::from_value(serde_json::json!({
        "status": "ACTIVE",
        "schemaVersion": "V1",
        "payload": {
            "logId": Uuid::new_v4().to_string(),
            "producer": {
                "event": {
                    "ansId": Uuid::new_v4().to_string(),
                    "ansName": format!("ans://{version}.{host}"),
                    "eventType": "AGENT_REGISTERED",
                    "agent": { "host": host, "name": format!("Test Agent at {host}"), "version": version },
                    "attestations": {
                        "domainValidation": "ACME-DNS-01",
                        "identityCert": { "fingerprint": identity_fp, "type": "X509-OV-CLIENT" },
                        "serverCert": { "fingerprint": server_fp, "type": "X509-DV-SERVER" }
                    },
                    "expiresAt": (Utc::now() + chrono::Duration::days(365)).to_rfc3339(),
                    "issuedAt": Utc::now().to_rfc3339(),
                    "raId": "test-ra",
                    "timestamp": Utc::now().to_rfc3339()
                },
                "keyId": "test-key",
                "signature": "test-signature"
            }
        }
    })).expect("test badge JSON should be valid")
}

// ---------------------------------------------------------------------------
// PEM parsing helpers
// ---------------------------------------------------------------------------

fn parse_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject;

    CertificateDer::pem_slice_iter(pem.as_bytes())
        .map(|r| r.unwrap())
        .collect()
}

fn parse_key(pem: &str) -> Option<PrivateKeyDer<'static>> {
    use rustls::pki_types::pem::PemObject;

    PrivateKeyDer::from_pem_slice(pem.as_bytes()).ok()
}
