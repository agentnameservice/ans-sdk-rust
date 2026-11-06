#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Interactive SCITT artifact inspector.
//!
//! Fetches root keys, status token, and receipt from a live transparency log,
//! then walks through each verification step printing what it finds.
//!
//! # Usage
//!
//! ```bash
//! # With root-keys endpoint available:
//! cargo run -p ans-verify --features scitt --example inspect_scitt -- \
//!   --tlog https://transparency.ans.godaddy.com \
//!   --agent-id b8a46f57-5599-4b4d-9a53-0313e5529694
//!
//! # With explicit root keys (when /root-keys is not available):
//! cargo run -p ans-verify --features scitt --example inspect_scitt -- \
//!   --tlog https://transparency.ans.godaddy.com \
//!   --agent-id b8a46f57-5599-4b4d-9a53-0313e5529694 \
//!   --key 'transparency.ans.godaddy.com+cba390ac+AjBZMBMG...' \
//!   --key 'transparency.ans.godaddy.com+bb7ed8cf+AjBZMBMG...'
//! ```

use std::sync::Arc;
use std::time::Duration;

use ans_verify::{
    HttpScittClient, ScittClient as _, ScittKeyStore, parse_cose_sign1, verify_receipt,
    verify_status_token,
};
use chrono::{DateTime, Utc};

fn section(title: &str) {
    println!();
    println!("=== {title} ===");
    println!();
}

fn step(n: u32, label: &str) {
    println!("  [{n}] {label}");
}

fn detail(label: &str, value: &str) {
    println!("      {label}: {value}");
}

fn ok(msg: &str) {
    println!("      -> {msg}");
}

fn fail(msg: &str) {
    println!("      !! {msg}");
}

fn ts(unix: i64) -> String {
    DateTime::<Utc>::from_timestamp(unix, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| format!("{unix} (invalid)"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let parsed = parse_args(&args).unwrap_or_else(|| {
        eprintln!(
            "Usage: inspect_scitt --tlog <URL> --agent-id <UUID> [--key <C2SP_KEY>]...\n\n\
             Example:\n  cargo run -p ans-verify --features scitt --example inspect_scitt -- \\\n    \
             --tlog https://transparency.ans.godaddy.com \\\n    \
             --agent-id b8a46f57-5599-4b4d-9a53-0313e5529694\n\n\
             Root keys are fetched from /root-keys. Pass --key to provide them\n\
             explicitly (useful when the endpoint is not available)."
        );
        std::process::exit(1);
    });
    let tlog_url = parsed.tlog;
    let agent_id_str = parsed.agent_id;
    let cli_keys = parsed.keys;

    let agent_id: uuid::Uuid = agent_id_str.parse().unwrap_or_else(|e| {
        eprintln!("Invalid agent ID '{agent_id_str}': {e}");
        std::process::exit(1);
    });

    println!("SCITT Artifact Inspector");
    println!("========================");
    detail("Transparency Log", &tlog_url);
    detail("Agent ID", &agent_id.to_string());

    let client = HttpScittClient::new(&tlog_url)
        .unwrap_or_else(|e| {
            eprintln!("Invalid TL URL: {e}");
            std::process::exit(1);
        })
        .with_timeout(Duration::from_secs(15));

    // ── Step 1: Root keys ──────────────────────────────────────────────

    section("Root Keys");

    let root_keys = if cli_keys.is_empty() {
        step(1, "Fetching root keys from /root-keys ...");
        client.fetch_root_keys().await.unwrap_or_else(|e| {
            fail(&format!("Failed to fetch root keys: {e}"));
            eprintln!("\n  Hint: pass --key <C2SP_KEY> to provide root keys explicitly.");
            std::process::exit(1);
        })
    } else {
        step(
            1,
            &format!("Using {} root key(s) from --key args", cli_keys.len()),
        );
        cli_keys
    };

    ok(&format!("Got {} key(s)", root_keys.len()));
    for (i, key) in root_keys.iter().enumerate() {
        let parts: Vec<&str> = key.splitn(3, '+').collect();
        if parts.len() == 3 {
            detail(
                &format!("  Key {}", i + 1),
                &format!("{} (kid: {})", parts[0], parts[1]),
            );
        } else {
            detail(
                &format!("  Key {}", i + 1),
                &format!("(malformed: {})", &key[..key.len().min(60)]),
            );
        }
    }

    step(2, "Parsing C2SP keys into key store ...");
    let key_store = Arc::new(
        ScittKeyStore::from_c2sp_keys(&root_keys).unwrap_or_else(|e| {
            fail(&format!("Failed to parse any root keys: {e}"));
            std::process::exit(1);
        }),
    );
    ok(&format!("{} valid key(s) in store", key_store.len()));

    // ── Step 2: Status Token ───────────────────────────────────────────

    section("Status Token");
    step(
        3,
        &format!("Fetching status token for agent {agent_id} ..."),
    );

    let token_bytes = match client.fetch_status_token(agent_id).await {
        Ok(bytes) => {
            ok(&format!("{} bytes", bytes.len()));
            bytes
        }
        Err(e) => {
            fail(&format!("Failed: {e}"));
            println!("\n  Skipping status token verification.\n");
            Vec::new()
        }
    };

    if !token_bytes.is_empty() {
        step(4, "Parsing COSE_Sign1 structure ...");
        match parse_cose_sign1(&token_bytes) {
            Ok(parsed) => {
                detail("Algorithm", &format!("{} (ES256)", parsed.protected.alg));
                detail("Key ID", &hex::encode(parsed.protected.kid));
                if let Some(ct) = &parsed.protected.content_type {
                    detail("Content-Type", ct);
                }
                detail(
                    "Signature",
                    &format!("{} bytes (P1363)", parsed.signature.len()),
                );
                detail("Payload", &format!("{} bytes", parsed.payload.len()));
            }
            Err(e) => {
                fail(&format!("COSE parse error: {e}"));
            }
        }

        step(5, "Verifying signature + expiry + status ...");
        match verify_status_token(&token_bytes, &key_store, Duration::from_secs(60)) {
            Ok(verified) => {
                let p = &verified.payload;
                ok("Signature valid, token verified!");
                detail("Agent ID", &p.agent_id.to_string());
                detail("Status", &format!("{:?}", p.status));
                detail("ANS Name", &p.ans_name.to_string());
                detail("Issued At", &ts(p.iat));
                detail("Expires At", &ts(p.exp));
                let ttl = p.exp - chrono::Utc::now().timestamp();
                if ttl > 0 {
                    detail(
                        "TTL",
                        &format!("{ttl}s ({:.1}h remaining)", ttl as f64 / 3600.0),
                    );
                } else {
                    detail("TTL", &format!("EXPIRED {}s ago", -ttl));
                }
                detail(
                    "Server Certs",
                    &format!("{} entries", p.valid_server_certs.len()),
                );
                for (i, entry) in p.valid_server_certs.iter().enumerate() {
                    detail(
                        &format!("    [{i}]"),
                        &format!("{} ({})", entry.fingerprint, entry.cert_type),
                    );
                }
                detail(
                    "Identity Certs",
                    &format!("{} entries", p.valid_identity_certs.len()),
                );
                for (i, entry) in p.valid_identity_certs.iter().enumerate() {
                    detail(
                        &format!("    [{i}]"),
                        &format!("{} ({})", entry.fingerprint, entry.cert_type),
                    );
                }
                if !p.metadata_hashes.is_empty() {
                    detail(
                        "Metadata Hashes",
                        &format!("{} entries", p.metadata_hashes.len()),
                    );
                    for (k, v) in &p.metadata_hashes {
                        detail(&format!("    {k}"), v);
                    }
                }
            }
            Err(e) => {
                fail(&format!("{e}"));
                if matches!(e, ans_verify::ScittError::TokenExpired { .. }) {
                    println!("      (Token expired — this is normal for captured artifacts.)");
                    println!("      (Retrying with relaxed tolerance to show payload ...)");
                    if let Ok(verified) = verify_status_token(
                        &token_bytes,
                        &key_store,
                        Duration::from_secs(u64::MAX / 2),
                    ) {
                        let p = &verified.payload;
                        ok("Signature valid (expiry bypassed for inspection)");
                        detail("Agent ID", &p.agent_id.to_string());
                        detail("Status", &format!("{:?}", p.status));
                        detail("ANS Name", &p.ans_name.to_string());
                        detail("Issued At", &ts(p.iat));
                        detail("Expired At", &ts(p.exp));
                        detail(
                            "Server Certs",
                            &format!("{} entries", p.valid_server_certs.len()),
                        );
                        detail(
                            "Identity Certs",
                            &format!("{} entries", p.valid_identity_certs.len()),
                        );
                    }
                }
            }
        }
    }

    // ── Step 3: Receipt ────────────────────────────────────────────────

    section("Receipt (Merkle Inclusion Proof)");
    step(6, &format!("Fetching receipt for agent {agent_id} ..."));

    let receipt_bytes = match client.fetch_receipt(agent_id).await {
        Ok(bytes) => {
            ok(&format!("{} bytes", bytes.len()));
            bytes
        }
        Err(e) => {
            fail(&format!("Failed: {e}"));
            println!("\n  Skipping receipt verification.\n");
            Vec::new()
        }
    };

    if !receipt_bytes.is_empty() {
        step(7, "Parsing COSE_Sign1 structure ...");
        match parse_cose_sign1(&receipt_bytes) {
            Ok(parsed) => {
                detail("Algorithm", &format!("{} (ES256)", parsed.protected.alg));
                detail("Key ID", &hex::encode(parsed.protected.kid));
                if let Some(vds) = parsed.protected.vds {
                    detail(
                        "VDS",
                        &format!(
                            "{vds} ({})",
                            if vds == 1 {
                                "RFC9162_SHA256"
                            } else {
                                "unknown"
                            }
                        ),
                    );
                }
                detail(
                    "Payload",
                    &format!("{} bytes (event)", parsed.payload.len()),
                );
                if let Ok(json_str) = std::str::from_utf8(&parsed.payload) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) {
                        if let Some(schema) = json.get("schemaVersion").and_then(|v| v.as_str()) {
                            detail("Schema Version", schema);
                        }
                        if let Some(payload) = json.get("payload") {
                            if let Some(log_id) = payload.get("logId").and_then(|v| v.as_str()) {
                                detail("Log ID", log_id);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                fail(&format!("COSE parse error: {e}"));
            }
        }

        step(8, "Verifying signature + Merkle inclusion proof ...");
        match verify_receipt(&receipt_bytes, &key_store) {
            Ok(verified) => {
                ok("Receipt verified! Agent is included in the transparency log.");
                detail("Tree Size", &format!("{}", verified.tree_size));
                detail("Leaf Index", &format!("{}", verified.leaf_index));
                detail("Root Hash", &hex::encode(verified.root_hash));
                if let Some(iss) = &verified.iss {
                    detail("Issuer", iss);
                }
                if let Some(iat) = verified.iat {
                    detail("Issued At", &ts(iat));
                }
                detail(
                    "Event Payload",
                    &format!("{} bytes", verified.event_bytes.len()),
                );
            }
            Err(e) => {
                fail(&format!("{e}"));
            }
        }
    }

    // ── Summary ────────────────────────────────────────────────────────

    section("Summary");

    let token_ok = !token_bytes.is_empty()
        && verify_status_token(&token_bytes, &key_store, Duration::from_secs(60)).is_ok();
    let receipt_ok =
        !receipt_bytes.is_empty() && verify_receipt(&receipt_bytes, &key_store).is_ok();

    if token_ok && receipt_ok {
        println!("  Status Token : VALID");
        println!("  Receipt      : VALID");
        println!("  Tier         : FullScitt");
    } else if token_ok {
        println!("  Status Token : VALID");
        println!(
            "  Receipt      : {}",
            if receipt_bytes.is_empty() {
                "NOT FETCHED"
            } else {
                "INVALID"
            }
        );
        println!("  Tier         : StatusTokenVerified");
    } else if receipt_ok {
        println!(
            "  Status Token : {}",
            if token_bytes.is_empty() {
                "NOT FETCHED"
            } else {
                "INVALID/EXPIRED"
            }
        );
        println!("  Receipt      : VALID");
        println!("  Tier         : BadgeOnly (token required for SCITT tier)");
    } else {
        println!(
            "  Status Token : {}",
            if token_bytes.is_empty() {
                "NOT FETCHED"
            } else {
                "INVALID/EXPIRED"
            }
        );
        println!(
            "  Receipt      : {}",
            if receipt_bytes.is_empty() {
                "NOT FETCHED"
            } else {
                "INVALID"
            }
        );
        println!("  Tier         : BadgeOnly (fallback)");
    }

    println!();

    Ok(())
}

struct ParsedArgs {
    tlog: String,
    agent_id: String,
    keys: Vec<String>,
}

fn parse_args(args: &[String]) -> Option<ParsedArgs> {
    let mut tlog = None;
    let mut agent_id = None;
    let mut keys = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--tlog" | "--url" | "-u" => {
                tlog = args.get(i + 1).cloned();
                i += 2;
            }
            "--agent-id" | "--agent" | "-a" => {
                agent_id = args.get(i + 1).cloned();
                i += 2;
            }
            "--key" | "-k" => {
                if let Some(k) = args.get(i + 1) {
                    keys.push(k.clone());
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    Some(ParsedArgs {
        tlog: tlog?,
        agent_id: agent_id?,
        keys,
    })
}
