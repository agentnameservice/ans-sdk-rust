#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Example: MCP client with mTLS and ANS verification
//!
//! Connects to a real MCP server using:
//! 1. ANS badge verification of the server's TLS certificate
//! 2. mTLS client authentication with an ANS identity certificate
//!
//! # Environment Variables
//!
//! - `ANS_CERT_PATH` (required): Path to identity certificate (PEM)
//! - `ANS_KEY_PATH` (required): Path to identity private key (PEM)
//! - `ANS_TRUSTED_TL_DOMAINS` (required): Comma-separated trusted TL hosts
//! - `ANS_SERVER_URL`: MCP server URL (default: `https://agent.example.com/mcp`)
//! - `ANS_SERVER_HOST`: Server hostname for badge lookup (default: `agent.example.com`)
//!
//! # Run
//!
//! ```bash
//! ANS_TRUSTED_TL_DOMAINS=transparency.ans.godaddy.com \
//! ANS_CERT_PATH=./identity.crt ANS_KEY_PATH=./identity.key \
//!   cargo run --example mcp_mtls_client --features rustls
//! ```
//!
//! For local testing with mock infrastructure, use the `local_mtls` example instead.

use std::fs;
use std::sync::Arc;

use ans_verify::{AnsServerCertVerifier, AnsVerifier, CertFingerprint, DanePolicy};
use anyhow::{Context, Result};
use rmcp::{
    ServiceExt,
    model::ClientInfo,
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mcp_mtls_client=info,ans_verify=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let server_url =
        std::env::var("ANS_SERVER_URL").unwrap_or_else(|_| "https://agent.example.com/mcp".into());
    let server_host =
        std::env::var("ANS_SERVER_HOST").unwrap_or_else(|_| "agent.example.com".into());
    let cert_path = std::env::var("ANS_CERT_PATH")
        .expect("ANS_CERT_PATH required: path to identity certificate");
    let key_path =
        std::env::var("ANS_KEY_PATH").expect("ANS_KEY_PATH required: path to identity private key");
    let trusted_domains = std::env::var("ANS_TRUSTED_TL_DOMAINS")
        .context("ANS_TRUSTED_TL_DOMAINS required: configure trusted TL hosts out of band")?;

    // Step 1: Fetch the ANS badge and get expected server fingerprint
    println!("Fetching ANS badge for {server_host}...");
    let verifier = AnsVerifier::builder()
        .trusted_ra_domains(
            trusted_domains
                .split(',')
                .map(str::trim)
                .filter(|host| !host.is_empty()),
        )
        .dane_policy(DanePolicy::ValidateIfPresent)
        .dns_google()
        .with_caching()
        .build()
        .await?;

    let badge = verifier.prefetch(&server_host).await?;
    println!("  Agent: {} ({:?})", badge.agent_name(), badge.status);

    let expected_fp = CertFingerprint::parse(badge.server_cert_fingerprint())
        .context("Failed to parse badge fingerprint")?;
    println!("  Expected server fingerprint: {expected_fp}");

    // Step 2: Build TLS config with ANS verification + mTLS client auth
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ans_verifier = AnsServerCertVerifier::new(expected_fp)?;
    let certs = load_certs(&cert_path)?;
    let key = load_private_key(&key_path)?;

    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ans_verifier))
        .with_client_auth_cert(certs, key)
        .context("Failed to configure client certificate")?;

    let http_client = reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .build()?;

    // Step 3: Connect to MCP server — ANS verification happens during TLS handshake
    println!("Connecting to {server_url}...");
    let transport = StreamableHttpClientTransport::with_client(
        http_client,
        StreamableHttpClientTransportConfig::with_uri(server_url),
    );

    let mut client_info = ClientInfo::default();
    client_info.client_info.name = "ans-mcp-example".to_string();
    client_info.client_info.version = env!("CARGO_PKG_VERSION").to_string();

    let client = client_info.serve(transport).await?;
    println!("Connected — server certificate verified against ANS badge");

    if let Some(info) = client.peer_info() {
        println!(
            "  Server: {} v{}",
            info.server_info.name, info.server_info.version
        );
    }

    // Step 4: List available tools
    if let Ok(tools) = client.list_tools(Default::default()).await {
        println!("  Tools ({}):", tools.tools.len());
        for tool in &tools.tools {
            println!(
                "    - {}: {}",
                tool.name,
                tool.description.as_deref().unwrap_or("")
            );
        }
    }

    client.cancel().await?;
    println!("Disconnected");

    Ok(())
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;

    let pem = fs::read(path).context("Failed to read certificate file")?;
    CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificates")
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    use rustls::pki_types::pem::PemObject;

    PrivateKeyDer::from_pem_file(path).context("Failed to parse private key")
}
