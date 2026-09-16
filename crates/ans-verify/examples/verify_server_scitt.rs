#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Example: SCITT-enhanced server verification
//!
//! Demonstrates verifying a server's TLS certificate using SCITT status tokens
//! for stronger, offline-capable trust verification.
//!
//! ```bash
//! RUST_LOG=ans_verify=debug cargo run -p ans-verify --features scitt --example verify_server_scitt
//! ```

use std::sync::Arc;

use ans_verify::{
    AnsVerifier, CertFingerprint, CertIdentity, ScittConfig, ScittHeaders, ScittKeyStore,
    ScittTierPolicy, VerificationOutcome,
};
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

    // 1. Configure SCITT root keys (production transparency log)
    let root_keys = vec![
        // C2SP key format: {issuer}+{key_id_hex}+{spki_base64}
        "transparency.ans.godaddy.com+c9e2f584+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJiE0eriKUOYbYrXerJlCJv6TZGEglLkPOHo+bEieNtPsL2FjuXfRCZbYF3RCwqF/99iDVxIUHJWTcW3KXqbiCU=".to_string(),
    ];
    let key_store =
        Arc::new(ScittKeyStore::from_c2sp_keys(&root_keys).expect("root keys should parse"));

    // 2. Build verifier with SCITT enabled
    let verifier = AnsVerifier::builder()
        .trusted_ra_domains(["transparency.ans.godaddy.com"])
        .dns_google()
        .with_caching()
        .scitt_config(ScittConfig::new().with_tier_policy(ScittTierPolicy::ScittWithBadgeFallback))
        .scitt_key_store(key_store)
        .build()
        .await?;

    // 3. Simulate extracting server cert from TLS handshake
    let server_fqdn = "agent.example.com";
    let server_cert = CertIdentity::new(
        Some(server_fqdn.to_string()),
        vec![server_fqdn.to_string()],
        vec![],
        CertFingerprint::parse(
            "SHA256:E7B64D16F42055D6FAF382A43DC35B98BE76ABA0DB145A904B590A034B33B904",
        )?,
    );

    // 4. Simulate SCITT headers from the HTTP response
    //    In production, extract from `X-SCITT-Receipt` and `X-ANS-Status-Token` headers.
    let headers = ScittHeaders::new(None, None); // No headers → badge fallback

    println!("Verifying server with SCITT: {server_fqdn}");
    let outcome = verifier
        .verify_server_with_scitt(server_fqdn, &server_cert, &headers)
        .await;

    match outcome {
        VerificationOutcome::ScittVerified {
            tier,
            status_token,
            badge,
            ..
        } => {
            println!("SCITT Verified (tier: {tier:?})");
            println!("  Status: {:?}", status_token.payload.status);
            if let Some(b) = badge {
                println!("  Badge: {} ({})", b.agent_name(), b.agent_host());
            }
        }
        VerificationOutcome::Verified { badge, .. } => {
            println!(
                "Badge-only verified: {} ({})",
                badge.agent_name(),
                badge.agent_host()
            );
        }
        VerificationOutcome::NotAnsAgent { fqdn } => {
            println!("Not an ANS agent (no _ans-badge record for {fqdn})");
        }
        other => {
            println!("Verification failed: {other:?}");
        }
    }

    Ok(())
}
