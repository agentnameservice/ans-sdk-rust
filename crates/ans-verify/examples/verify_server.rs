#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Example: Verify a server's ANS agent registration
//!
//! Demonstrates client-side verification of a server's TLS certificate
//! against the ANS transparency log.
//!
//! ```bash
//! RUST_LOG=ans_verify=debug cargo run --example verify_server
//! ```

use ans_verify::{AnsVerifier, CertFingerprint, CertIdentity, VerificationOutcome};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ans_verify=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let verifier = AnsVerifier::builder()
        .trusted_ra_domains(["transparency.ans.godaddy.com"])
        .dns_google()
        .with_caching()
        .build()
        .await?;

    // In practice, you'd extract this from the TLS handshake.
    // Here we simulate with a test FQDN and fingerprint.
    let server_fqdn = "agent.example.com";
    let server_cert = CertIdentity::new(
        Some(server_fqdn.to_string()),
        vec![server_fqdn.to_string()],
        vec![],
        CertFingerprint::parse(
            "SHA256:E7B64D16F42055D6FAF382A43DC35B98BE76ABA0DB145A904B590A034B33B904",
        )?,
    );

    println!("Verifying server: {server_fqdn}");
    let outcome = verifier.verify_server(server_fqdn, &server_cert).await;

    match outcome {
        VerificationOutcome::Verified { badge, .. } => {
            println!("Verified: {} ({})", badge.agent_name(), badge.agent_host());
        }
        VerificationOutcome::NotAnsAgent { fqdn } => {
            println!("Not an ANS agent (no _ans-badge record for {fqdn})");
        }
        VerificationOutcome::FingerprintMismatch {
            expected, actual, ..
        } => {
            println!("Fingerprint mismatch: expected {expected}, got {actual}");
        }
        other => {
            println!("Verification failed: {other:?}");
        }
    }

    Ok(())
}
