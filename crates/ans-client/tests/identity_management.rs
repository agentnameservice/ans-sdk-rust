#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use ans_client::{AnsClient, ApiVersion, models::*};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, method, path, query_param},
};
const AGENT: &str = "019a1234-5678-7000-8000-000000000002";
const FUTURE: &str = "2100-01-01T00:00:00Z";
fn client(server: &MockServer, version: ApiVersion) -> AnsClient {
    AnsClient::builder()
        .base_url(server.uri())
        .api_version(version)
        .jwt("test-token")
        .allow_insecure()
        .build()
        .unwrap()
}
use ans_client::IdentityProofAlgorithm;
use ans_types::{IdentityKind, IdentityProofInput};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
const ID: &str = "019a1234-5678-7000-8000-000000000001";
const DID: &str = "did:web:operator.example.com";
const RA: &str = "https://ra.example.com";
fn challenge() -> Value {
    let nonce = BASE64_URL_SAFE_NO_PAD.encode([7u8; 32]);
    let input = IdentityProofInput::new(DID, ID, &nonce, RA, IdentityKind::DidWeb);
    json!({"identityId":ID,"kind":"did:web","value":DID,"status":"PENDING_CONTROL","nonce":nonce,"expiresAt":FUTURE,
        "challenges":[{"kid":format!("{DID}#key-1"),"signingInput":BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&input).unwrap())}]})
}
fn detail(status: &str) -> Value {
    json!({"identityId":ID,"kind":"did:web","value":DID,"status":status,"createdAt":"2026-01-01T00:00:00Z","linkedAgents":[{"agentId":AGENT}]})
}

#[tokio::test]
async fn identity_management_covers_the_complete_lifecycle() {
    let server = MockServer::start().await;
    let client = client(&server, ApiVersion::V2);
    let route = format!("/v2/ans/identities/{ID}");
    Mock::given(method("POST"))
        .and(path("/v2/ans/identities"))
        .and(body_json(json!({"value":DID})))
        .respond_with(ResponseTemplate::new(202).set_body_json(challenge()))
        .expect(1)
        .mount(&server)
        .await;
    let round = client
        .register_identity(&IdentityRegistrationRequest::new(DID))
        .await
        .unwrap();
    assert_eq!(round.identity_id, ID);
    Mock::given(method("GET")).and(path("/v2/ans/identities")).and(query_param("cursor","opaque+/cursor")).and(query_param("limit","10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items":[detail("VERIFIED")],"returnedCount":1,"limit":10,"nextCursor":null,"hasMore":false}))).expect(1).mount(&server).await;
    let page = client
        .list_identities(Some(10), Some("opaque+/cursor"))
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert!(!page.has_more);
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(detail("VERIFIED")))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        client.get_identity(ID).await.unwrap().linked_agents[0].agent_id,
        AGENT
    );
    Mock::given(method("PUT"))
        .and(path(&route))
        .and(body_json(json!({"value":DID})))
        .respond_with(ResponseTemplate::new(202).set_body_json(challenge()))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        client
            .rotate_identity(ID, &IdentityRegistrationRequest::new(DID))
            .await
            .unwrap()
            .identity_id,
        ID
    );
    Mock::given(method("POST"))
        .and(path(format!("{route}/verify-control")))
        .and(body_json(json!({"signedProofs":["a.b.c"]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(detail("VERIFIED")))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        client
            .verify_identity_control(ID, &VerifyIdentityControlRequest::new(vec!["a.b.c".into()]))
            .await
            .unwrap()
            .status,
        IdentityStatus::Verified
    );
    Mock::given(method("POST"))
        .and(path(format!("{route}/links")))
        .and(body_json(json!({"agentIds":[AGENT]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"linked":1})))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        client
            .link_identity_agents(ID, &IdentityLinkRequest::new(vec![AGENT.into()]))
            .await
            .unwrap()
            .linked,
        1
    );
    Mock::given(method("DELETE"))
        .and(path(format!("{route}/links/{AGENT}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    client.unlink_identity_agent(ID, AGENT).await.unwrap();
    Mock::given(method("POST"))
        .and(path(format!("{route}/revoke")))
        .respond_with(ResponseTemplate::new(200).set_body_json(detail("REVOKED")))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        client.revoke_identity(ID).await.unwrap().status,
        IdentityStatus::Revoked
    );
    assert!(
        server.received_requests().await.unwrap().iter().all(|r| r
            .headers
            .get("authorization")
            .unwrap()
            == "sso-jwt test-token")
    );
}

#[test]
fn proof_preparation_preserves_payload_and_supports_external_signers() {
    let round: IdentityChallengeResponse = serde_json::from_value(challenge()).unwrap();
    for algorithm in [
        IdentityProofAlgorithm::Es256,
        IdentityProofAlgorithm::EdDsa,
        IdentityProofAlgorithm::Rs256,
    ] {
        let prepared = round
            .prepare_proof(RA, algorithm, &format!("{DID}#key-1"), None)
            .unwrap();
        let text = std::str::from_utf8(prepared.signing_bytes()).unwrap();
        assert_eq!(
            text.split('.').nth(1).unwrap(),
            round.challenges[0].signing_input
        );
        let length = if algorithm == IdentityProofAlgorithm::Rs256 {
            256
        } else {
            64
        };
        assert_eq!(
            prepared
                .finish(&vec![3; length])
                .unwrap()
                .split('.')
                .count(),
            3
        );
        assert!(prepared.finish(&[3; 1]).is_err());
    }
    let mut unkeyed = round.clone();
    unkeyed.challenges[0].kid = None;
    let public = json!({"kty":"EC","crv":"P-256","x":"public","y":"public"});
    let prepared = unkeyed
        .prepare_proof(
            RA,
            IdentityProofAlgorithm::Es256,
            &format!("{DID}#different"),
            Some(public.clone()),
        )
        .unwrap();
    let header = std::str::from_utf8(prepared.signing_bytes())
        .unwrap()
        .split('.')
        .next()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&BASE64_URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap()["jwk"],
        public
    );
}

#[test]
fn proof_preparation_rejects_context_confusion_and_private_keys() {
    let round: IdentityChallengeResponse = serde_json::from_value(challenge()).unwrap();
    let kid = format!("{DID}#key-1");
    assert!(
        round
            .prepare_proof(
                "https://other-ra.example",
                IdentityProofAlgorithm::Es256,
                &kid,
                None
            )
            .is_err()
    );
    assert!(
        round
            .prepare_proof("", IdentityProofAlgorithm::Es256, &kid, None)
            .is_err()
    );
    assert!(
        round
            .prepare_proof(RA, IdentityProofAlgorithm::Es256, "", None)
            .is_err()
    );
    assert!(
        round
            .prepare_proof(
                RA,
                IdentityProofAlgorithm::Es256,
                "did:web:other.example#key-1",
                None
            )
            .is_err()
    );
    assert!(
        round
            .prepare_proof(
                RA,
                IdentityProofAlgorithm::Es256,
                &format!("{DID}#missing"),
                None
            )
            .is_err()
    );
    for private in [
        json!({"d":"secret"}),
        json!({"p":"secret"}),
        json!({"k":"secret"}),
        json!("not-an-object"),
    ] {
        assert!(
            round
                .prepare_proof(RA, IdentityProofAlgorithm::Es256, &kid, Some(private))
                .is_err()
        );
    }
    for field in [
        "identity_id",
        "value",
        "nonce",
        "signing_input",
        "expires",
        "kind",
        "status",
        "different_round",
        "payload",
    ] {
        let mut bad = round.clone();
        match field {
            "identity_id" => bad.identity_id = "other".into(),
            "value" => bad.value = "did:key:other".into(),
            "nonce" => bad.nonce = "AA".into(),
            "signing_input" => bad.challenges[0].signing_input = "!".into(),
            "expires" => bad.expires_at = chrono::DateTime::from_timestamp(0, 0).unwrap(),
            "kind" => bad.kind = IdentityKind::Lei,
            "status" => bad.status = IdentityStatus::Revoked,
            "different_round" => {
                let mut c = bad.challenges[0].clone();
                c.signing_input.push('A');
                bad.challenges.push(c);
            }
            "payload" => bad.challenges[0].signing_input = BASE64_URL_SAFE_NO_PAD.encode(b"{}"),
            _ => unreachable!(),
        }
        assert!(
            bad.prepare_proof(RA, IdentityProofAlgorithm::Es256, &kid, None)
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn did_key_preparation_uses_the_single_derived_method() {
    let did = "did:key:z6MknExample";
    let kid = format!("{did}#z6MknExample");
    let mut value = challenge();
    let input = ans_types::IdentityProofInput::new(
        did,
        value["identityId"].as_str().unwrap(),
        value["nonce"].as_str().unwrap(),
        RA,
        IdentityKind::DidKey,
    );
    value["kind"] = json!("did:key");
    value["value"] = json!(did);
    value["challenges"] = json!([{"kid":kid,"signingInput":BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&input).unwrap())}]);
    let round: IdentityChallengeResponse = serde_json::from_value(value).unwrap();
    assert!(
        round
            .prepare_proof(RA, IdentityProofAlgorithm::EdDsa, &kid, None)
            .is_ok()
    );
    assert!(
        round
            .prepare_proof(
                RA,
                IdentityProofAlgorithm::EdDsa,
                &format!("{did}#other"),
                None
            )
            .is_err()
    );
}

#[tokio::test]
async fn identity_guards_and_batch_bounds_do_not_send_requests() {
    let server = MockServer::start().await;
    let legacy = client(&server, ApiVersion::V1);
    let v2 = client(&server, ApiVersion::V2);
    assert!(
        legacy
            .register_identity(&IdentityRegistrationRequest::new(DID))
            .await
            .is_err()
    );
    assert!(legacy.list_identities(None, None).await.is_err());
    assert!(legacy.get_identity(ID).await.is_err());
    assert!(
        legacy
            .rotate_identity(ID, &IdentityRegistrationRequest::new(DID))
            .await
            .is_err()
    );
    assert!(
        legacy
            .verify_identity_control(ID, &VerifyIdentityControlRequest::new(vec!["proof".into()]))
            .await
            .is_err()
    );
    assert!(
        legacy
            .link_identity_agents(ID, &IdentityLinkRequest::new(vec![AGENT.into()]))
            .await
            .is_err()
    );
    assert!(legacy.unlink_identity_agent(ID, AGENT).await.is_err());
    assert!(legacy.revoke_identity(ID).await.is_err());
    for limit in [0, 101] {
        assert!(v2.list_identities(Some(limit), None).await.is_err());
    }
    for count in [0, 17] {
        assert!(
            v2.verify_identity_control(
                ID,
                &VerifyIdentityControlRequest::new(vec!["proof".into(); count])
            )
            .await
            .is_err()
        );
    }
    for count in [0, 257] {
        assert!(
            v2.link_identity_agents(ID, &IdentityLinkRequest::new(vec![AGENT.into(); count]))
                .await
                .is_err()
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}
#[test]
fn linked_identities_preserve_terminal_status() {
    let linked:ans_types::LinkedIdentity=serde_json::from_value(json!({"identityId":"identity","kind":"did:web","value":"did:web:example.com","identityStatus":"REVOKED"})).unwrap();
    assert_eq!(linked.identity_status, Some(IdentityStatus::Revoked));
    assert!(linked.keys.is_empty());
}
