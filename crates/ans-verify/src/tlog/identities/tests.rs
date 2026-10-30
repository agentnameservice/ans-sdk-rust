#![allow(clippy::unwrap_used)]
use super::*;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path, query_param},
};

fn client(base: &str) -> HttpTransparencyLogClient {
    HttpTransparencyLogClient {
        client: HttpTransparencyLogClient::client_builder()
            .https_only(false)
            .no_proxy()
            .build()
            .unwrap(),
        base_url: Some(url::Url::parse(base).unwrap()),
        timeout: std::time::Duration::from_secs(5),
        extra_headers: vec![("X-Test".into(), "identity".into())],
    }
}
fn badge_json(id: Uuid) -> serde_json::Value {
    json!({"schemaVersion":"V2","signature":"sealed","status":"VERIFIED","keys":[],"keysLogId":"proof-1", "payload":{"logId":"link-2","producer":{"keyId":"ra-key","signature":"attestation","event":{"eventType":"IDENTITY_LINKED","identityId":id,"kind":"did:web","value":"did:web:example.com","timestamp":"2026-06-23T18:30:00Z","ansIds":["0193f0c5-7b2e-7a41-9c3d-bbbbbbbbbbbb"]}}}})
}
#[tokio::test]
async fn all_six_public_reads_preserve_paths_pagination_and_wire_shapes() {
    let server = MockServer::start().await;
    let id = Uuid::new_v4();
    let agent = Uuid::new_v4();
    let client = client(&server.uri());
    let badge = badge_json(id);
    Mock::given(method("GET"))
        .and(path(format!("/v1/identities/{id}")))
        .and(header("Accept", "application/json"))
        .and(header("X-Test", "identity"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&badge))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        client
            .fetch_identity_badge(id)
            .await
            .unwrap()
            .keys_log_id
            .as_deref(),
        Some("proof-1")
    );
    Mock::given(path(format!("/v1/identities/{id}/receipt")))
        .and(header("Accept", "application/scitt-receipt+cose"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0x84, 1, 2, 3]))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        client.fetch_identity_receipt(id).await.unwrap(),
        vec![0x84, 1, 2, 3]
    );
    for endpoint in [
        format!("/v1/identities/{id}/audit"),
        format!("/v1/agents/{agent}/identities/history"),
    ] {
        Mock::given(path(endpoint))
            .and(query_param("limit", "200"))
            .and(query_param("offset", "12"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"records":[badge]})))
            .expect(1)
            .mount(&server)
            .await;
    }
    assert_eq!(
        client
            .fetch_identity_audit(id, Some(200), Some(12))
            .await
            .unwrap()
            .records
            .len(),
        1
    );
    assert_eq!(
        client
            .fetch_agent_identity_history(agent, Some(200), Some(12))
            .await
            .unwrap()
            .records
            .len(),
        1
    );
    Mock::given(path(format!("/v1/identities/{id}/agents"))).and(query_param("limit","1")).and(query_param("offset","0")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"total":1,"agents":[{"ansId":agent,"agentStatus":"ACTIVE","linkedAt":"2026-06-23T18:30:00Z"}]}))).expect(1).mount(&server).await;
    assert_eq!(
        client
            .fetch_identity_agents(id, Some(1), Some(0))
            .await
            .unwrap()
            .agents[0]
            .ans_id,
        agent.to_string()
    );
    Mock::given(path(format!("/v1/agents/{agent}/identities"))).respond_with(ResponseTemplate::new(200).set_body_json(json!({"total":1,"identities":[{"identityId":id,"kind":"did:web","value":"did:web:example.com","identityStatus":"REVOKED"}]}))).expect(1).mount(&server).await;
    let response = client
        .fetch_agent_identities(agent, None, None)
        .await
        .unwrap();
    assert_eq!(
        response.identities[0].identity_status,
        Some(ans_types::IdentityStatus::Revoked)
    );
    assert!(response.identities[0].keys.is_empty());
}

#[tokio::test]
async fn receipt_checkpoint_pending_retains_retry_after() {
    let server = MockServer::start().await;
    let id = Uuid::new_v4();
    let client = client(&server.uri());
    for retry in ["30", "not-a-duration"] {
        server.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503).insert_header("Retry-After", retry))
            .expect(1)
            .mount(&server)
            .await;
        let error = client.fetch_identity_receipt(id).await.unwrap_err();
        assert!(error.is_unavailable());
        assert!(
            matches!(error,TlogError::CheckpointPending{retry_after_seconds} if retry_after_seconds==retry.parse::<u64>().ok())
        );
    }
}

#[tokio::test]
async fn invalid_status_json_bounds_and_missing_base_fail_explicitly() {
    let server = MockServer::start().await;
    let id = Uuid::new_v4();
    let client = client(&server.uri());
    for status in [404, 429, 500, 403] {
        server.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(status))
            .expect(1)
            .mount(&server)
            .await;
        let error = client.fetch_identity_badge(id).await.unwrap_err();
        assert!(match status {
            404 => matches!(error, TlogError::NotFound { .. }),
            429 | 500 => error.is_unavailable(),
            _ => matches!(error, TlogError::InvalidResponse(_)),
        });
    }
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("malformed"))
        .expect(1)
        .mount(&server)
        .await;
    assert!(matches!(
        client.fetch_identity_badge(id).await,
        Err(TlogError::InvalidResponse(_))
    ));
    server.reset().await;
    for limit in [0, 201] {
        assert!(matches!(
            client.fetch_identity_audit(id, Some(limit), None).await,
            Err(TlogError::InvalidUrl(_))
        ));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(matches!(
        HttpTransparencyLogClient::new()
            .fetch_identity_badge(id)
            .await,
        Err(TlogError::InvalidUrl(_))
    ));
    assert!(matches!(
        client
            .with_header("bad header", "value")
            .fetch_identity_badge(id)
            .await,
        Err(TlogError::InvalidHeader(_))
    ));
}

#[tokio::test]
async fn responses_are_bounded_and_redirects_never_reach_the_target() {
    let server = MockServer::start().await;
    let target = MockServer::start().await;
    let id = Uuid::new_v4();
    let client = client(&server.uri());
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0; 2 * 1024 * 1024 + 1]))
        .expect(1)
        .mount(&server)
        .await;
    assert!(matches!(
        client.fetch_identity_receipt(id).await,
        Err(TlogError::InvalidResponse(_))
    ));
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", target.uri()))
        .expect(1)
        .mount(&server)
        .await;
    assert!(matches!(
        client.fetch_identity_badge(id).await,
        Err(TlogError::InvalidResponse(_))
    ));
    assert!(target.received_requests().await.unwrap().is_empty());
    let production = HttpTransparencyLogClient::with_base_url("https://example.com").unwrap();
    let production = HttpTransparencyLogClient {
        base_url: Some(url::Url::parse(&server.uri()).unwrap()),
        ..production
    };
    assert!(production.fetch_identity_badge(id).await.is_err());
}

#[tokio::test]
async fn mock_identity_log_preserves_all_reads_and_pagination() {
    let id = Uuid::new_v4();
    let agent = Uuid::new_v4();
    let badge: IdentityBadge = serde_json::from_value(badge_json(id)).unwrap();
    let audit: IdentityAuditResponse =
        serde_json::from_value(json!({"records":[badge,badge]})).unwrap();
    let default_page = MockIdentityLogClient::new().with_audit(
        id,
        serde_json::from_value(json!({"records":vec![badge.clone();60]})).unwrap(),
    );
    assert_eq!(
        default_page
            .fetch_identity_audit(id, None, None)
            .await
            .unwrap()
            .records
            .len(),
        50
    );
    let log=MockIdentityLogClient::new().with_badge(id,badge).with_receipt(id,vec![1,2,3]).with_audit(id,audit.clone()).with_agent_history(agent,audit)
        .with_agents(id,serde_json::from_value(json!({"agents":[{"ansId":agent},{"ansId":Uuid::nil()}],"total":2})).unwrap())
        .with_agent_identities(agent,serde_json::from_value(json!({"identities":[{"identityId":id,"kind":"did:web","value":"did:web:example.com"}],"total":1})).unwrap());
    assert_eq!(
        log.fetch_identity_badge(id).await.unwrap().payload.log_id,
        "link-2"
    );
    assert_eq!(log.fetch_identity_receipt(id).await.unwrap(), vec![1, 2, 3]);
    assert_eq!(
        log.fetch_identity_audit(id, Some(1), Some(1))
            .await
            .unwrap()
            .records
            .len(),
        1
    );
    assert!(
        log.fetch_identity_audit(id, None, Some(2))
            .await
            .unwrap()
            .records
            .is_empty()
    );
    assert_eq!(
        log.fetch_agent_identity_history(agent, Some(1), None)
            .await
            .unwrap()
            .records
            .len(),
        1
    );
    let agents = log
        .fetch_identity_agents(id, Some(1), Some(1))
        .await
        .unwrap();
    assert_eq!(agents.total, 2);
    assert_eq!(agents.agents[0].ans_id, Uuid::nil().to_string());
    let identities = log.fetch_agent_identities(agent, None, None).await.unwrap();
    assert_eq!(identities.total, 1);
    assert_eq!(identities.identities.len(), 1);
    assert!(matches!(
        log.fetch_identity_badge(Uuid::nil()).await,
        Err(TlogError::NotFound { .. })
    ));
    for limit in [0, 201] {
        assert!(matches!(
            log.fetch_identity_audit(id, Some(limit), None).await,
            Err(TlogError::InvalidUrl(_))
        ));
    }
}
