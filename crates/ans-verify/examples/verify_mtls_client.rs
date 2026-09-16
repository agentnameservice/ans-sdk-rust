#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Example: Verify an mTLS client's ANS agent registration (server-side)
//!
//! Demonstrates how a server verifies that a connecting mTLS client
//! is a registered ANS agent.
//!
//! ```bash
//! RUST_LOG=ans_verify=debug cargo run --example verify_mtls_client
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
        .with_caching()
        .build()
        .await?;

    // In practice, you'd extract this from the mTLS handshake.
    // The identity cert must have a URI SAN with the ANS name.
    let client_cert = CertIdentity::new(
        Some("agent.example.com".to_string()),
        vec!["agent.example.com".to_string()],
        vec!["ans://v1.0.0.agent.example.com".to_string()],
        CertFingerprint::parse(
            "SHA256:55E58DB3858D069B479B61EBFA394E0F3A5104517E9A078B05A1870D1889C79F",
        )?,
    );

    println!(
        "Verifying client: CN={:?}, version={:?}",
        client_cert.common_name(),
        client_cert.version()
    );
    let outcome = verifier.verify_client(&client_cert).await;

    match outcome {
        VerificationOutcome::Verified { badge, .. } => {
            println!(
                "Verified: {} v{}",
                badge.agent_name(),
                badge.agent_version()
            );
        }
        VerificationOutcome::NotAnsAgent { fqdn } => {
            println!("Not an ANS agent (no _ans-badge record for {fqdn})");
        }
        VerificationOutcome::AnsNameMismatch {
            expected, actual, ..
        } => {
            println!("ANS name mismatch: expected {expected}, got {actual}");
        }
        other => {
            println!("Verification failed: {other:?}");
        }
    }

    Ok(())
}
