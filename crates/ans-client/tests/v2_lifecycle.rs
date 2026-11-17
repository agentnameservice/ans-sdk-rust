#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use ans_client::{AnsClient, ApiVersion, models::*};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
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

use ans_client::ClientError;
#[tokio::test]
async fn owner_listing_preserves_repeated_filters_and_opaque_cursors() {
    let server = MockServer::start().await;
    let client = client(&server, ApiVersion::V2);
    let cursor = "owner+page/2?x=1";
    let digest = format!("SHA256:{}", "a".repeat(64));
    let body = json!({"items":[{"ansName":"ans://v1.0.0.agent.example.com","agentId":AGENT,"agentDisplayName":"test","version":"1.0.0","agentHost":"agent.example.com","status":"DEPRECATED","endpoints":[{"agentUrl":"https://agent.example.com","protocol":"MCP","metaDataHash":digest}],"links":[]}],"returnedCount":1,"limit":1,"nextCursor":cursor,"hasMore":true});
    Mock::given(method("GET"))
        .and(path("/v2/ans/agents"))
        .and(header("authorization", "sso-jwt test-token"))
        .and(query_param("cursor", cursor))
        .and(query_param("agentHost", "agent.example.com"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .mount(&server)
        .await;
    let mut options = AgentListOptions::default();
    options.statuses = vec![
        AgentLifecycleStatusFilter::PendingDns,
        AgentLifecycleStatusFilter::Active,
        AgentLifecycleStatusFilter::Deprecated,
        AgentLifecycleStatusFilter::Revoked,
        AgentLifecycleStatusFilter::All,
    ];
    options.agent_host = Some("agent.example.com".into());
    options.limit = Some(1);
    options.cursor = Some(cursor.into());
    let page = client.list_agents(&options).await.unwrap();
    assert_eq!(page.items[0].status, AgentLifecycleStatus::Deprecated);
    assert_eq!(
        page.items[0].endpoints[0].meta_data_hash.as_deref(),
        Some(digest.as_str())
    );
    assert_eq!(page.next_cursor.as_deref(), Some(cursor));
    let requests = server.received_requests().await.unwrap();
    let statuses: Vec<_> = requests[0]
        .url
        .query_pairs()
        .filter(|(k, _)| k == "status")
        .map(|(_, v)| v.into_owned())
        .collect();
    assert_eq!(
        statuses,
        ["PENDING_DNS", "ACTIVE", "DEPRECATED", "REVOKED", "ALL"]
    );
}

#[test]
fn registration_can_omit_identity_without_conflating_explicit_empty_input() {
    let mut endpoint = AgentEndpoint::new("https://agent.example.com", Protocol::Mcp);
    endpoint.meta_data_hash = Some(format!("SHA256:{}", "b".repeat(64)));
    let without = AgentRegistrationRequest::without_identity(
        "test",
        "agent.example.com",
        "1.0.0",
        vec![endpoint.clone()],
    )
    .with_server_csr_pem("server-csr");
    let wire = serde_json::to_value(without).unwrap();
    assert!(wire.get("identityCsrPEM").is_none());
    assert!(wire["endpoints"][0].get("metaDataHash").is_some());
    let explicit =
        AgentRegistrationRequest::new("test", "agent.example.com", "1.0.0", "", vec![endpoint]);
    assert_eq!(
        serde_json::to_value(explicit).unwrap()["identityCsrPEM"],
        ""
    );
}

#[tokio::test]
async fn renewal_supports_csr_byoc_poll_verification_and_empty_cancel() {
    let server = MockServer::start().await;
    let client = client(&server, ApiVersion::V2);
    let route = format!("/v2/ans/agents/{AGENT}/certificates/server/renewal");
    for (request, wire, kind) in [
        (
            ServerCertificateRenewalRequest::csr("csr"),
            json!({"serverCsrPEM":"csr"}),
            "SERVER_CSR",
        ),
        (
            ServerCertificateRenewalRequest::byoc("cert", Some("chain".into())),
            json!({"serverCertificatePEM":"cert","serverCertificateChainPEM":"chain"}),
            "SERVER_BYOC",
        ),
    ] {
        server.reset().await;
        Mock::given(method("POST")).and(path(&route)).and(body_json(wire)).and(header("authorization","sso-jwt test-token"))
            .respond_with(ResponseTemplate::new(202).set_body_json(json!({"renewalType":kind,"status":"PENDING_VALIDATION","csrId":null,"challenges":{"dns01":{"token":"dns-token"},"http01":{"type":"HTTP_01","httpPath":"/.well-known/acme-challenge/token"}},"expiresAt":FUTURE,"nextStep":{"action":"VALIDATE_DOMAIN"},"links":null}))).expect(1).mount(&server).await;
        let pending = client
            .submit_server_cert_renewal(AGENT, &request)
            .await
            .unwrap();
        assert_eq!(pending.status, RenewalStatus::PendingValidation);
        assert_eq!(
            pending.challenges.unwrap().dns01.unwrap().token.as_deref(),
            Some("dns-token")
        );
    }
    server.reset().await;
    Mock::given(method("GET")).and(path(&route)).respond_with(ResponseTemplate::new(200).set_body_json(json!({"renewalType":"SERVER_BYOC","status":"COMPLETED","challenges":null,"failureReason":null,"expiresAt":FUTURE,"nextStep":{},"tlsaDnsRecord":{"name":"_443._tcp.agent.example.com","type":"TLSA","value":"3 0 1 hash"}}))).mount(&server).await;
    let status = client.get_server_cert_renewal_status(AGENT).await.unwrap();
    assert_eq!(status.status, RenewalStatus::Completed);
    assert!(status.next_step.action.is_none());
    assert!(status.tlsa_dns_record.is_some());
    for code in [200, 202] {
        server.reset().await;
        Mock::given(method("POST"))
            .and(path(format!("{route}/verify-acme")))
            .respond_with(ResponseTemplate::new(code).set_body_json(
                json!({"status":"ISSUING_CERTIFICATE","csrId":AGENT,"nextStep":{"action":"WAIT"}}),
            ))
            .mount(&server)
            .await;
        assert_eq!(
            client.verify_renewal_acme(AGENT).await.unwrap().status,
            RenewalStatus::IssuingCertificate
        );
    }
    server.reset().await;
    Mock::given(method("DELETE"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    client.cancel_server_cert_renewal(AGENT).await.unwrap();
    server.reset().await;
    Mock::given(method("DELETE"))
        .and(path(&route))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"code":"NOT_FOUND","message":"no renewal"})),
        )
        .mount(&server)
        .await;
    assert!(matches!(
        client.cancel_server_cert_renewal(AGENT).await,
        Err(ClientError::NotFound { .. })
    ));
}

#[test]
fn renewal_nested_optional_members_follow_the_v2_contract() {
    let submission: RenewalSubmissionResponse = serde_json::from_value(json!({
        "renewalType":"SERVER_CSR", "status":"PENDING_VALIDATION", "expiresAt":"2026-12-01T00:00:00Z",
        "nextStep":{}, "challenges":{"dns01":{"dnsRecord":{}},"http01":{}}
    })).unwrap();
    let challenge = submission.challenges.unwrap().dns01.unwrap();
    assert!(challenge.challenge_type.is_none());
    assert!(challenge.dns_record.unwrap().name.is_none());
    assert!(submission.next_step.action.is_none());
}

#[tokio::test]
async fn management_v2_guards_and_bounds_do_not_send_requests() {
    let server = MockServer::start().await;
    let legacy = client(&server, ApiVersion::V1);
    let v2 = client(&server, ApiVersion::V2);
    assert!(
        legacy
            .list_agents(&AgentListOptions::default())
            .await
            .is_err()
    );
    assert!(
        legacy
            .submit_server_cert_renewal(AGENT, &ServerCertificateRenewalRequest::csr("csr"))
            .await
            .is_err()
    );
    assert!(legacy.get_server_cert_renewal_status(AGENT).await.is_err());
    assert!(legacy.cancel_server_cert_renewal(AGENT).await.is_err());
    assert!(legacy.verify_renewal_acme(AGENT).await.is_err());
    for limit in [0, 101] {
        let mut options = AgentListOptions::default();
        options.limit = Some(limit);
        assert!(v2.list_agents(&options).await.is_err());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}
#[test]
fn sealed_metadata_hashes_are_preserved() {
    let attestations: ans_types::Attestations =
        serde_json::from_value(json!({"metadataHashes":{"A2A":"SHA256:abc"}})).unwrap();
    assert_eq!(
        attestations.metadata_hashes.get("A2A").unwrap(),
        "SHA256:abc"
    );
    assert_eq!(
        serde_json::to_value(attestations).unwrap()["metadataHashes"]["A2A"],
        "SHA256:abc"
    );
}
