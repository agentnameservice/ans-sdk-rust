//! Verify an identity from an explicitly trusted HTTPS transparency log.
//!
//! Usage: cargo run -p ans-verify --features scitt --example verify_identity -- \
//!   https://tl.example.com 0193f0c5-7b2e-7a41-9c3d-aaaaaaaaaaaa
//!
//! The fetch channel authenticates the envelopes; operator signatures are
//! verified locally against sealed methods. Only the named proof event is
//! required from the audit. This does not prove complete log history.
#![allow(clippy::print_stdout)]
use ans_verify::{
    HttpTransparencyLogClient, IdentityLogClient, IdentityVerificationError, IdentityVerifier,
    VerifiedIdentityProof,
};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [url, id] = args.as_slice() else {
        return Err("expected <trusted HTTPS TL URL> <identity UUID>".into());
    };
    let id: Uuid = id.parse()?;
    let log = HttpTransparencyLogClient::with_base_url(url)?;
    let mut verifier = IdentityVerifier::new(id.to_string())?;
    let proof = verify_current(&log, id, &mut verifier).await?;
    println!(
        "VERIFIED {} ({}) with {} proven key(s)",
        proof.value(),
        proof.identity_id(),
        proof.verification_methods().len()
    );
    Ok(())
}

async fn verify_current(
    log: &impl IdentityLogClient,
    id: Uuid,
    verifier: &mut IdentityVerifier,
) -> Result<VerifiedIdentityProof> {
    let badge = log.fetch_identity_badge(id).await?;
    match verifier.verify_badge(&badge) {
        Ok(proof) => return Ok(proof.clone()),
        Err(
            IdentityVerificationError::IncompleteEvidence(_)
            | IdentityVerificationError::BindingMismatch(_),
        ) => {}
        Err(error) => return Err(error.into()),
    }
    let proof_id = badge
        .keys_log_id
        .as_ref()
        .ok_or("current badge has no keysLogId")?;
    if badge.payload.log_id == *proof_id {
        verifier.observe_trusted_entry(&badge)?;
    } else {
        const PAGE_SIZE: u32 = 200;
        let mut offset = 0;
        loop {
            let page = log
                .fetch_identity_audit(id, Some(PAGE_SIZE), Some(offset))
                .await?;
            let found = page
                .records
                .iter()
                .find(|entry| entry.payload.log_id == *proof_id);
            // Preserve terminal revocations seen alongside the requested proof.
            for entry in &page.records {
                if entry.payload.producer.event.event_type
                    == ans_verify::IdentityEventType::IdentityRevoked
                {
                    verifier.observe_trusted_entry(entry)?;
                }
            }
            if let Some(entry) = found {
                verifier.observe_trusted_entry(entry)?;
                break;
            }
            if page.records.len() < PAGE_SIZE as usize {
                return Err("proof event at keysLogId is unavailable".into());
            }
            offset = offset
                .checked_add(PAGE_SIZE)
                .ok_or("audit offset overflow")?;
        }
    }
    Ok(verifier.verify_badge(&badge)?.clone())
}

#[cfg(all(test, feature = "test-support"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ans_verify::{IdentityBadge, MockIdentityLogClient};
    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use serde_json::json;

    fn proof_entry(id: Uuid) -> IdentityBadge {
        let did = "did:web:operator.example.com";
        let kid = format!("{did}#one");
        let key = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
        let input = ans_types::IdentityProofInput::new(
            did,
            id.to_string(),
            BASE64_URL_SAFE_NO_PAD.encode([2; 32]),
            "https://ra.example.com",
            ans_types::IdentityKind::DidWeb,
        );
        let header = BASE64_URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"alg":"EdDSA","kid":kid})).unwrap());
        let payload =
            BASE64_URL_SAFE_NO_PAD.encode(serde_json_canonicalizer::to_vec(&input).unwrap());
        let message = format!("{header}.{payload}");
        let proof = format!(
            "{message}.{}",
            BASE64_URL_SAFE_NO_PAD.encode(key.sign(message.as_bytes()).as_ref())
        );
        let method = json!({"id":kid,"type":"JsonWebKey2020","controller":did,"publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":BASE64_URL_SAFE_NO_PAD.encode(key.public_key().as_ref())}});
        serde_json::from_value(json!({"status":"VERIFIED","schemaVersion":"V2","signature":"trusted TL","keysLogId":"proof","keys":[method],"payload":{"logId":"proof","producer":{"keyId":"ra","signature":"trusted producer","event":{"eventType":"IDENTITY_VERIFIED","identityId":id,"kind":"did:web","value":did,"timestamp":"2026-06-23T18:30:00Z","verifiedAt":"2026-06-23T18:30:00Z","providerId":"owner","proofMethod":"did-web-sig","raId":"https://ra.example.com","keys":[{"verificationMethod":method,"signedProof":proof}]}}}})).unwrap()
    }
    fn linked(mut badge: IdentityBadge) -> IdentityBadge {
        badge.payload.log_id = "link".into();
        badge.payload.producer.event.event_type = ans_verify::IdentityEventType::IdentityLinked;
        badge.payload.producer.event.keys.clear();
        badge.payload.producer.event.ans_ids = vec![Uuid::nil().to_string()];
        badge
    }
    #[tokio::test]
    async fn public_workflow_verifies_current_proof_and_reuses_bound_evidence() {
        let id = Uuid::new_v4();
        let badge = proof_entry(id);
        let log = MockIdentityLogClient::new().with_badge(id, badge);
        let mut verifier = IdentityVerifier::new(id.to_string()).unwrap();
        for _ in 0..2 {
            assert_eq!(
                verify_current(&log, id, &mut verifier)
                    .await
                    .unwrap()
                    .verification_methods()
                    .len(),
                1
            );
        }
    }
    #[tokio::test]
    async fn public_workflow_finds_historical_proof_after_link_pages() {
        let id = Uuid::new_v4();
        let proof = proof_entry(id);
        let current = linked(proof.clone());
        let mut records = vec![current.clone(); 200];
        records.push(proof);
        let audit = serde_json::from_value(json!({"records":records})).unwrap();
        let log = MockIdentityLogClient::new()
            .with_badge(id, current)
            .with_audit(id, audit);
        let mut verifier = IdentityVerifier::new(id.to_string()).unwrap();
        assert_eq!(
            verify_current(&log, id, &mut verifier)
                .await
                .unwrap()
                .log_id(),
            "proof"
        );
    }
    #[tokio::test]
    async fn public_workflow_rejects_missing_bad_signatures_and_revocation() {
        let id = Uuid::new_v4();
        let proof = proof_entry(id);
        let mut bad = proof.clone();
        bad.payload.producer.event.keys[0].signed_proof.push('x');
        let log = MockIdentityLogClient::new().with_badge(id, bad);
        assert!(
            verify_current(
                &log,
                id,
                &mut IdentityVerifier::new(id.to_string()).unwrap()
            )
            .await
            .is_err()
        );
        let current = linked(proof.clone());
        let log = MockIdentityLogClient::new()
            .with_badge(id, current.clone())
            .with_audit(id, serde_json::from_value(json!({"records":[]})).unwrap());
        assert!(
            verify_current(
                &log,
                id,
                &mut IdentityVerifier::new(id.to_string()).unwrap()
            )
            .await
            .is_err()
        );
        let mut revoked = proof.clone();
        revoked.payload.producer.event.event_type = ans_verify::IdentityEventType::IdentityRevoked;
        let mut verifier = IdentityVerifier::new(id.to_string()).unwrap();
        verifier.observe_trusted_entry(&revoked).unwrap();
        let log = MockIdentityLogClient::new().with_badge(id, proof);
        assert!(matches!(
            verify_current(&log, id, &mut verifier)
                .await
                .unwrap_err()
                .downcast_ref::<IdentityVerificationError>(),
            Some(IdentityVerificationError::Revoked)
        ));
    }
}
