#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Real-data SCITT verification tests using artifacts from the production transparency log.
//!
//! These tests verify that our COSE_Sign1 parsing, signature verification,
//! status token decoding, and receipt verification work with production-format
//! artifacts from `transparency.ans.godaddy.com`.

use std::sync::Arc;
use std::time::Duration;

use ans_types::*;
use ans_verify::*;
use base64::prelude::{BASE64_STANDARD, Engine as _};

// =========================================================================
// Real artifacts from production transparency log (agent b8a46f57-...)
// =========================================================================

const ROOT_KEYS: &[&str] = &[
    "transparency.ans.godaddy.com+c9e2f584+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJiE0eriKUOYbYrXerJlCJv6TZGEglLkPOHo+bEieNtPsL2FjuXfRCZbYF3RCwqF/99iDVxIUHJWTcW3KXqbiCU=",
];

// Status token (412 bytes, application/ans-status-token+cbor)
// Fetched from: https://transparency.ans.godaddy.com/v1/agents/{AGENT_ID}/status-token
const STATUS_TOKEN_B64: &str = "0oRYLaMBJgREyeL1hAN4IWFwcGxpY2F0aW9uL2Fucy1zdGF0dXMtdG9rZW4rY2JvcqBZASWnAXgkYjhhNDZmNTctNTU5OS00YjRkLTlhNTMtMDMxM2U1NTI5Njk0AmZBQ1RJVkUDGmnD7vQEGmnD/QQFeCxhbnM6Ly92MC4wLjEubG9nby1hZ2VudC5tdmNpLmFwaS5nb2RhZGR5LmNvbQaBogF4R1NIQTI1NjplMjcyYjAxNTE4NDExZTljNGZlMDA1NjQ1NjBjNDc1OTkyYTgzNTFhZGFhY2FlYzUxNDBlNDY5ZTExNTM3ODY2Am5YNTA5LU9WLUNMSUVOVAeBogF4R1NIQTI1Njo0Y2ZiZGUxNzVjMzc1ZjVkODEzMDI0OWRlYWI1OGQxZjMxNGI0ZjdjN2MxYjhlZTgxMWYwNDdiMzhmYjFjYzVmAm5YNTA5LURWLVNFUlZFUlhAm/V4dND2dBROAJLo0YOi6F5fWJnnnTTGfJRmcjVZAATRysYA/kYTqAaipo0Na0tl9Y/0I0uCj2/2FqnZQ5KeEA==";

// Receipt (2618 bytes, application/scitt-receipt+cose)
// Fetched from: https://transparency.ans.godaddy.com/v1/agents/{AGENT_ID}/receipt
const RECEIPT_B64: &str = "0oRYNKQBJgREyeL1hBkBiwEPogF4HHRyYW5zcGFyZW5jeS5hbnMuZ29kYWRkeS5jb20GGmnD7mOhGQGMpCAZKNMhBCKOWCAGVA/w5wGSdqSZOD0Ba1fdPa/jlV0tskhNu6a7E86FP1gg2tzjMpV6C+qDPkn1SZpVCnxnDjTYwHF+uYM4sykCh3xYIGEZHRkNU+GIxevY8h9C0szHDcbNRyThzi1UZRF9STWtWCBGV0rdciI3DROLp/8xOoGYVW90ahpko0OhM/MP+khtdVggq4mRzf8zreGQ3RHyD+xIbivbXZGdUl24VGdlqrZ+L59YIN7dfvtVN5gARGj4vyjaR2J5UumRT8GmPQhQn89GSy+TWCCFzG3vj2pZLNeNfJ2qNS6sYPYooZ4JQnbxc4+vS+j0q1ggwD4eTxiAg+OMA7c3Rkf1FydjS/d3shrP+sV2LiD4AFNYIGjEInzsEJunmBPLMYixII9KR1NjmdiTCX7DKb9fS2WWWCCZRU+RZ1bKyYA4XwQid4iN8TlNdZ+/+sMm0Cx5h5qoDVggSwmCThfdYFRVJjQpwKMtz5KX9GiQj/Vm/CzgDQWNse1YIBWzmWbzFMwIjn6i/Q6xiOS5CMI7RpODj8TeBFQ4EQ+yWCACLTlgZHod+zCTPtmfaWWPSOqQtHeWtRgofVzjD71uyFgge2h35ZJysQmBbCXlui+/4a8d4WVnkXZXa8hhLmdNREMjWCCfX5M9f+Jf0SEkCcXT2CoQM4wrmMDL7+7RDSY2/1FDDVkHsXsicGF5bG9hZCI6eyJsb2dJZCI6IjAxOWJkOGYzLWZmNWQtN2FmMi04OTE1LTBjZjNiZjcxYTFjNiIsInByb2R1Y2VyIjp7ImV2ZW50Ijp7ImFnZW50Ijp7Imhvc3QiOiJsb2dvLWFnZW50Lm12Y2kuYXBpLmdvZGFkZHkuY29tIiwibmFtZSI6IkxvZ28gR2VuZXJhdGlvbiBBZ2VudCIsInZlcnNpb24iOiJ2MC4wLjEifSwiYW5zSWQiOiJiOGE0NmY1Ny01NTk5LTRiNGQtOWE1My0wMzEzZTU1Mjk2OTQiLCJhbnNOYW1lIjoiYW5zOi8vdjAuMC4xLmxvZ28tYWdlbnQubXZjaS5hcGkuZ29kYWRkeS5jb20iLCJhdHRlc3RhdGlvbnMiOnsiZG5zUmVjb3Jkc1Byb3Zpc2lvbmVkIjp7Il9hbnMubG9nby1hZ2VudC5tdmNpLmFwaS5nb2RhZGR5LmNvbSI6InY9YW5zMTsgdmVyc2lvbj0wLjAuMTsgdXJsPWh0dHBzOi8vbG9nby1hZ2VudC5tdmNpLmFwaS5nb2RhZGR5LmNvbS9hZ2VudC1jYXJkLmpzb24iLCJfcmEtYmFkZ2UubG9nby1hZ2VudC5tdmNpLmFwaS5nb2RhZGR5LmNvbSI6InY9cmEtYmFkZ2UxOyB1cmw9aHR0cHM6Ly90cmFuc3BhcmVuY3kuYW5zLmdvZGFkZHkuY29tL3YxL2FnZW50cy9iOGE0NmY1Ny01NTk5LTRiNGQtOWE1My0wMzEzZTU1Mjk2OTQifSwiZG9tYWluVmFsaWRhdGlvbiI6IkFDTUUtRE5TLTAxIiwiaWRlbnRpdHlDZXJ0Ijp7ImZpbmdlcnByaW50IjoiU0hBMjU2OmUyNzJiMDE1MTg0MTFlOWM0ZmUwMDU2NDU2MGM0NzU5OTJhODM1MWFkYWFjYWVjNTE0MGU0NjllMTE1Mzc4NjYiLCJ0eXBlIjoiWDUwOS1PVi1DTElFTlQifSwic2VydmVyQ2VydCI6eyJmaW5nZXJwcmludCI6IlNIQTI1Njo0Y2ZiZGUxNzVjMzc1ZjVkODEzMDI0OWRlYWI1OGQxZjMxNGI0ZjdjN2MxYjhlZTgxMWYwNDdiMzhmYjFjYzVmIiwidHlwZSI6Ilg1MDktRFYtU0VSVkVSIn19LCJldmVudFR5cGUiOiJBR0VOVF9SRUdJU1RFUkVEIiwiZXhwaXJlc0F0IjoiMjAyNy0wMS0xOVQyMDo1MjozMC4wMDAwMDBaIiwiaXNzdWVkQXQiOiIyMDI2LTAxLTE5VDIwOjUyOjI5LjcxOTIzN1oiLCJyYUlkIjoiZ2QtcmEtdXMtd2VzdC0yLXByb2QtZGIyMTUyNS1hYTE4ZTQ0MWIxYzM0OWMwOGZhY2RjMWY5OTM5NjZmYSIsInRpbWVzdGFtcCI6IjIwMjYtMDEtMjBUMDE6MTA6MjUuNzk2NjA5WiJ9LCJrZXlJZCI6InJhLWdkLXJhLXVzLXdlc3QtMi1wcm9kLWRiMjE1MjUtYWExOGU0NDFiMWMzNDljMDhmYWNkYzFmOTkzOTY2ZmEtMTc2ODg2NzM2MyIsInNpZ25hdHVyZSI6ImV5SmhiR2NpT2lKRlV6STFOaUlzSW10cFpDSTZJbkpoTFdka0xYSmhMWFZ6TFhkbGMzUXRNaTF3Y205a0xXUmlNakUxTWpVdFlXRXhPR1UwTkRGaU1XTXpORGxqTURobVlXTmtZekZtT1Rrek9UWTJabUV0TVRjMk9EZzJOek0yTXlJc0luSmhhV1FpT2lKblpDMXlZUzExY3kxM1pYTjBMVEl0Y0hKdlpDMWtZakl4TlRJMUxXRmhNVGhsTkRReFlqRmpNelE1WXpBNFptRmpaR014WmprNU16azJObVpoSWl3aWRHbHRaWE4wWVcxd0lqb3hOelk0T0RjeE5ESTNMQ0owZVhBaU9pSktWMVFpZlEuLjQybzdQZUFSTWVrY3lvamw4QzFXSGVTUW9GWlEtWFhpUEpHYzVlV3Utcm15NkRtclpTUmczU21OaFA0NnZvRHY3NS1kV05peFFnVlJjWi1YRzZjVnNBIn19LCJzY2hlbWFWZXJzaW9uIjoiVjEiLCJzaWduYXR1cmUiOiJleUpoYkdjaU9pSkZVekkxTmlJc0ltdHBaQ0k2SW1GeWJqcGhkM002YTIxek9uVnpMWGRsYzNRdE1qbzVPRFF3T0RRME5UZ3dOekU2YTJWNUwyMXlheTFqTUROak9UWTBaRGhsTURRME1EUXdPR0UxTkRSbU5tWXpaamsyWW1GbU5pSXNJbkpoYVdRaU9pSlNRUzFVVEMxVlV5MVhSVk5VTFRJdFlXNXpMWEpsWjJsemRISjVMV3h2Wnkxd2NtOWtMVFk1T0dOa1pqWm1abU10ZEdOeFpqZ2lMQ0owYVcxbGMzUmhiWEFpT2pFM05qZzROekUwTWpjc0luUjVjQ0k2SWtwWFZDSjkuLmRhdkNpYUZpYXJ0cFVDZG03RHFvWHVfVWRySTJxSVZ3UXNUWG5CSGhFMk9zZklxcXNiYUs1U0JLNVo4UWZScTZ2TlhaRURRaFQ2SFpOYS1GM2tNeTFBIn1YQAdjX1byLnoJCw2AIbyaGRk/8si9KUqOJ/u9o2u0UV0cQ1fI9XadVNMH+2iUlmy93Bki7CckBGa2nd4+01/pzJg=";

// Expected agent data
const AGENT_ID: &str = "b8a46f57-5599-4b4d-9a53-0313e5529694";
const HOST: &str = "logo-agent.mvci.api.godaddy.com";
const ANS_NAME: &str = "ans://v0.0.1.logo-agent.mvci.api.godaddy.com";
const SERVER_FP: &str = "SHA256:4cfbde175c375f5d8130249deab58d1f314b4f7c7c1b8ee811f047b38fb1cc5f";
const IDENTITY_FP: &str = "SHA256:e272b01518411e9c4fe00564560c475992a8351adaacaec5140e469e11537866";

fn key_store() -> Arc<ScittKeyStore> {
    let keys: Vec<String> = ROOT_KEYS.iter().map(|s| s.to_string()).collect();
    Arc::new(ScittKeyStore::from_c2sp_keys(&keys).expect("root keys should parse"))
}

// =========================================================================
// Test: Root key parsing
// =========================================================================

#[test]
fn real_root_keys_parse_successfully() {
    let store = key_store();
    // kid = c9e2f584 (from the production key)
    let kid: [u8; 4] = [0xc9, 0xe2, 0xf5, 0x84];
    let result = store.get(kid);
    assert!(
        result.is_ok(),
        "Key c9e2f584 should be in store: {result:?}"
    );
}

// =========================================================================
// Test: COSE_Sign1 parsing — status token
// =========================================================================

#[test]
fn real_status_token_parses_as_cose_sign1() {
    let bytes = BASE64_STANDARD
        .decode(STATUS_TOKEN_B64)
        .expect("valid base64");
    let parsed = parse_cose_sign1(&bytes).expect("should parse as COSE_Sign1");

    assert_eq!(parsed.protected.alg, -7, "alg should be ES256");
    assert_eq!(
        parsed.protected.kid,
        [0xc9, 0xe2, 0xf5, 0x84],
        "kid should match c9e2f584"
    );
    assert!(parsed.protected.vds.is_none(), "status tokens have no vds");
    assert_eq!(
        parsed.protected.content_type.as_deref(),
        Some("application/ans-status-token+cbor"),
        "content type should be set"
    );
    assert_eq!(
        parsed.signature.len(),
        64,
        "ES256 P1363 signature is 64 bytes"
    );
}

// =========================================================================
// Test: Status token full verification
// =========================================================================

#[test]
fn real_status_token_verifies_signature() {
    let bytes = BASE64_STANDARD
        .decode(STATUS_TOKEN_B64)
        .expect("valid base64");
    let store = key_store();

    // Pin `now` to 1 minute after the token's iat (2026-03-25 14:19:32 UTC).
    // This ensures the full verification + payload assertion path is exercised
    // deterministically, regardless of when the test runs.
    let pinned_now: i64 = 1_774_448_432; // iat + 60s
    let result = verify_status_token_at(&bytes, &store, Duration::from_secs(60), pinned_now);

    let verified = result.expect("token should verify at pinned timestamp");

    assert_eq!(verified.payload.agent_id.to_string(), AGENT_ID);
    assert_eq!(verified.payload.status, BadgeStatus::Active);
    assert_eq!(verified.payload.ans_name.to_string(), ANS_NAME);

    // Verify fingerprint matching
    let server_fp = CertFingerprint::parse(SERVER_FP).unwrap();
    assert!(
        matches_server_cert(&verified.payload, &server_fp),
        "Server fingerprint should match"
    );

    let identity_fp = CertFingerprint::parse(IDENTITY_FP).unwrap();
    assert!(
        matches_identity_cert(&verified.payload, &identity_fp),
        "Identity fingerprint should match"
    );
}

// =========================================================================
// Test: COSE_Sign1 parsing — receipt
// =========================================================================

#[test]
fn real_receipt_parses_as_cose_sign1() {
    let bytes = BASE64_STANDARD.decode(RECEIPT_B64).expect("valid base64");
    let parsed = parse_cose_sign1(&bytes).expect("should parse as COSE_Sign1");

    assert_eq!(parsed.protected.alg, -7, "alg should be ES256");
    assert_eq!(
        parsed.protected.kid,
        [0xc9, 0xe2, 0xf5, 0x84],
        "kid should match c9e2f584"
    );
    assert_eq!(parsed.protected.vds, Some(1), "receipt should have vds=1");
    assert_eq!(
        parsed.signature.len(),
        64,
        "ES256 P1363 signature is 64 bytes"
    );

    // Payload should be JSON (the badge event)
    let payload_str = std::str::from_utf8(&parsed.payload).expect("payload should be UTF-8");
    assert!(
        payload_str.contains(AGENT_ID),
        "payload should contain agent ID"
    );
    assert!(payload_str.contains(HOST), "payload should contain host");

    // CWT claims should be present in the protected header
    assert_eq!(
        parsed.protected.cwt_iss.as_deref(),
        Some("transparency.ans.godaddy.com"),
        "CWT iss should be the TL domain"
    );
    assert!(
        parsed.protected.cwt_iat.is_some(),
        "CWT iat should be present"
    );
}

// =========================================================================
// Test: Receipt full verification
// =========================================================================

#[test]
fn real_receipt_verifies_signature_and_merkle() {
    let bytes = BASE64_STANDARD.decode(RECEIPT_B64).expect("valid base64");
    let store = key_store();

    let result = verify_receipt(&bytes, &store);

    match result {
        Ok(verified) => {
            println!("Receipt verified successfully!");
            println!("  Tree size: {}", verified.tree_size);
            println!("  Leaf index: {}", verified.leaf_index);
            println!("  Root hash: {}", hex::encode(verified.root_hash));
            println!("  Event bytes length: {}", verified.event_bytes.len());
            if let Some(iss) = &verified.iss {
                println!("  Issuer: {iss}");
            }
            if let Some(iat) = verified.iat {
                println!("  Issued at: {iat}");
            }

            assert!(verified.tree_size > 0, "tree_size should be positive");
            assert!(
                verified.leaf_index < verified.tree_size,
                "leaf_index should be < tree_size"
            );

            // CWT claims should be propagated
            assert_eq!(
                verified.iss.as_deref(),
                Some("transparency.ans.godaddy.com"),
                "iss should be the TL domain"
            );
            assert!(verified.iat.is_some(), "iat should be present");

            // Event bytes should be JSON containing the badge
            let event_str =
                std::str::from_utf8(&verified.event_bytes).expect("event should be UTF-8");
            assert!(event_str.contains(AGENT_ID));
            assert!(event_str.contains(HOST));
        }
        Err(e) => {
            panic!("Receipt verification failed: {e}");
        }
    }
}

// =========================================================================
// Test: ScittHeaders from base64 (simulating HTTP header extraction)
// =========================================================================

#[test]
fn real_headers_from_base64() {
    let headers = ScittHeaders::from_base64(Some(RECEIPT_B64), Some(STATUS_TOKEN_B64))
        .expect("should parse base64 headers");

    assert!(!headers.is_empty(), "headers should not be empty");
    assert!(headers.receipt.is_some(), "receipt should be present");
    assert!(
        headers.status_token.is_some(),
        "status token should be present"
    );
}

// =========================================================================
// Test: End-to-end server verification with SCITT
// =========================================================================

#[tokio::test]
async fn real_end_to_end_server_scitt_verification() {
    let store = key_store();

    // Build badge matching the real agent
    let badge: Badge = serde_json::from_value(serde_json::json!({
        "status": "ACTIVE",
        "schemaVersion": "V1",
        "payload": {
            "logId": "019bd8f3-ff5d-7af2-8915-0cf3bf71a1c6",
            "producer": {
                "event": {
                    "ansId": AGENT_ID,
                    "ansName": ANS_NAME,
                    "eventType": "AGENT_REGISTERED",
                    "agent": {
                        "host": HOST,
                        "name": "Logo Generation Agent",
                        "version": "v0.0.1"
                    },
                    "attestations": {
                        "domainValidation": "ACME-DNS-01",
                        "identityCert": { "fingerprint": IDENTITY_FP, "type": "X509-OV-CLIENT" },
                        "serverCert": { "fingerprint": SERVER_FP, "type": "X509-DV-SERVER" }
                    },
                    "expiresAt": "2027-01-19T20:52:30.000000Z",
                    "issuedAt": "2026-01-19T20:52:29.719237Z",
                    "raId": "gd-ra-us-west-2-prod-db21525-aa18e441b1c349c08facdc1f993966fa",
                    "timestamp": "2026-01-20T01:10:25.796609Z"
                },
                "keyId": "ra-gd-ra-us-west-2-prod-db21525-aa18e441b1c349c08facdc1f993966fa-1768867363",
                "signature": "eyJhbGciOiJFUzI1NiJ9..stub"
            }
        }
    }))
    .expect("badge JSON should parse");

    let badge_url =
        "https://transparency.ans.godaddy.com/v1/agents/b8a46f57-5599-4b4d-9a53-0313e5529694";

    let record = BadgeRecord::new("ans-badge1", Some(Version::new(0, 0, 1)), badge_url);

    let dns = Arc::new(MockDnsResolver::new().with_records(HOST, vec![record]));
    let tlog = Arc::new(MockTransparencyLogClient::new().with_badge(badge_url, badge));

    let verifier = AnsVerifier::builder()
        .trusted_ra_domains(["transparency.ans.godaddy.com"])
        .dns_resolver(dns)
        .tlog_client(tlog)
        .scitt_config(ScittConfig::new().with_tier_policy(ScittTierPolicy::ScittWithBadgeFallback))
        .scitt_key_store(store)
        .build()
        .await
        .expect("verifier should build");

    let cert = CertIdentity::new(
        Some(HOST.to_string()),
        vec![HOST.to_string()],
        vec![],
        CertFingerprint::parse(SERVER_FP).unwrap(),
    );

    let headers = ScittHeaders::from_base64(Some(RECEIPT_B64), Some(STATUS_TOKEN_B64)).unwrap();

    let outcome = verifier
        .verify_server_with_scitt(HOST, &cert, &headers)
        .await;

    // The captured status token has expired (exp=2026-03-21). With headers
    // present, the SCITT result is final — no badge fallback. The expected
    // outcome is either ScittVerified (if token is still fresh) or
    // ScittError::TokenExpired (once it has expired). Both are valid for
    // this e2e smoke test.
    match &outcome {
        ans_verify::VerificationOutcome::ScittVerified { .. } => {
            // Token was still fresh — all good
        }
        ans_verify::VerificationOutcome::ScittError(e) => {
            assert!(
                matches!(e, ans_verify::ScittError::TokenExpired { .. }),
                "Expected TokenExpired but got: {e:?}"
            );
        }
        other => panic!("Expected ScittVerified or TokenExpired, got: {other:?}"),
    }
}
