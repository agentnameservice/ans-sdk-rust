#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Integration tests for the ANS client using wiremock.

use ans_client::{AnsClient, ApiVersion, ClientError, models::*};
use rstest::rstest;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

/// Create a test client pointing to the mock server.
fn test_client(server: &MockServer) -> AnsClient {
    AnsClient::builder()
        .base_url(server.uri())
        .jwt("test-token")
        .allow_insecure() // mock server uses http://
        .build()
        .expect("client build failed")
}

/// Sample registration request for testing.
fn sample_registration_request() -> AgentRegistrationRequest {
    let endpoint = AgentEndpoint::new("https://agent.example.com/mcp", Protocol::Mcp)
        .with_transports(vec![Transport::StreamableHttp])
        .with_functions(vec![AgentFunction::new(
            "test-func",
            "Test Function",
            vec!["test".into()],
        )]);

    AgentRegistrationRequest::new(
        "test-agent",
        "agent.example.com",
        "1.0.0",
        "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----",
        vec![endpoint],
    )
    .with_description("A test agent")
    .with_server_csr_pem(
        "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----",
    )
}

#[tokio::test]
async fn test_register_agent_success() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "status": "PENDING_VALIDATION",
        "ansName": "ans://v1.0.0.agent.example.com",
        "agentId": "550e8400-e29b-41d4-a716-446655440000",
        "nextSteps": [
            {
                "action": "CONFIGURE_DNS",
                "description": "Configure the ACME challenge DNS record"
            }
        ],
        "challenges": [
            {
                "type": "DNS_01",
                "token": "abc123",
                "keyAuthorization": "abc123.xyz789",
                "dnsRecord": {
                    "name": "_acme-challenge.agent.example.com",
                    "type": "TXT",
                    "value": "xyz789"
                }
            }
        ],
        "dnsRecords": [
            {
                "name": "_ans-badge.agent.example.com",
                "type": "TXT",
                "value": "https://tlog.example.com/badge/123",
                "purpose": "BADGE",
                "required": true
            }
        ],
        "links": [
            {
                "rel": "self",
                "href": "https://api.example.com/v1/agents/550e8400-e29b-41d4-a716-446655440000"
            }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/v1/agents/register"))
        .and(header("Authorization", "sso-jwt test-token"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(202).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let request = sample_registration_request();
    let result = client.register_agent(&request).await.unwrap();

    assert_eq!(result.status, RegistrationStatus::PendingValidation);
    assert_eq!(result.ans_name, "ans://v1.0.0.agent.example.com");
    assert_eq!(
        result.agent_id,
        Some("550e8400-e29b-41d4-a716-446655440000".into())
    );
    assert!(!result.next_steps.is_empty());
    assert!(!result.challenges.is_empty());
    assert_eq!(result.challenges[0].challenge_type, ChallengeType::Dns01);
}

#[tokio::test]
async fn test_register_agent_conflict() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let error_body = serde_json::json!({
        "status": "ERROR",
        "code": "409",
        "message": "Agent already registered"
    });

    Mock::given(method("POST"))
        .and(path("/v1/agents/register"))
        .respond_with(ResponseTemplate::new(409).set_body_json(&error_body))
        .expect(1)
        .mount(&server)
        .await;

    let request = sample_registration_request();
    let result = client.register_agent(&request).await;

    assert!(matches!(result, Err(ClientError::Conflict { .. })));
}

#[tokio::test]
async fn test_get_agent_success() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "agentId": "550e8400-e29b-41d4-a716-446655440000",
        "agentDisplayName": "test-agent",
        "agentHost": "agent.example.com",
        "agentDescription": "A test agent",
        "ansName": "ans://v1.0.0.agent.example.com",
        "version": "1.0.0",
        "agentStatus": "ACTIVE",
        "endpoints": [
            {
                "agentUrl": "https://agent.example.com/mcp",
                "protocol": "MCP",
                "transports": ["STREAMABLE-HTTP"]
            }
        ],
        "links": []
    });

    Mock::given(method("GET"))
        .and(path("/v1/agents/550e8400-e29b-41d4-a716-446655440000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .get_agent("550e8400-e29b-41d4-a716-446655440000")
        .await
        .unwrap();

    assert_eq!(result.agent_id, "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(result.agent_display_name, "test-agent");
    assert_eq!(result.agent_status, AgentLifecycleStatus::Active);
}

#[tokio::test]
async fn test_get_agent_not_found() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let error_body = serde_json::json!({
        "status": "ERROR",
        "code": "404",
        "message": "Agent not found"
    });

    Mock::given(method("GET"))
        .and(path("/v1/agents/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(&error_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.get_agent("nonexistent").await;

    assert!(matches!(result, Err(ClientError::NotFound { .. })));
}

#[tokio::test]
async fn test_search_agents() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "agents": [
            {
                "ansName": "ans://v1.0.0.agent1.example.com",
                "agentId": "id-1",
                "agentDisplayName": "Agent 1",
                "version": "1.0.0",
                "agentHost": "agent1.example.com",
                "endpoints": [],
                "links": []
            },
            {
                "ansName": "ans://v2.0.0.agent2.example.com",
                "agentId": "id-2",
                "agentDisplayName": "Agent 2",
                "version": "2.0.0",
                "agentHost": "agent2.example.com",
                "endpoints": [],
                "links": []
            }
        ],
        "totalCount": 2,
        "returnedCount": 2,
        "limit": 20,
        "offset": 0,
        "hasMore": false
    });

    Mock::given(method("GET"))
        .and(path("/v1/agents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let criteria = SearchCriteria::default();
    let result = client.search_agents(&criteria, None, None).await.unwrap();

    assert_eq!(result.total_count, 2);
    assert_eq!(result.agents.len(), 2);
    assert!(!result.has_more);
}

#[tokio::test]
async fn test_verify_acme() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "status": "PENDING_DNS",
        "phase": "DNS_PROVISIONING",
        "completedSteps": ["DOMAIN_VALIDATION"],
        "pendingSteps": ["DNS_CONFIGURATION"]
    });

    Mock::given(method("POST"))
        .and(path("/v1/agents/agent-123/verify-acme"))
        .respond_with(ResponseTemplate::new(202).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.verify_acme("agent-123").await.unwrap();

    assert_eq!(result.status, AgentLifecycleStatus::PendingDns);
    assert_eq!(result.phase, Some(RegistrationPhase::DnsProvisioning));
}

#[tokio::test]
async fn test_verify_dns() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "status": "ACTIVE",
        "phase": "COMPLETED",
        "completedSteps": ["DOMAIN_VALIDATION", "DNS_CONFIGURATION"],
        "pendingSteps": []
    });

    Mock::given(method("POST"))
        .and(path("/v1/agents/agent-123/verify-dns"))
        .respond_with(ResponseTemplate::new(202).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.verify_dns("agent-123").await.unwrap();

    assert_eq!(result.status, AgentLifecycleStatus::Active);
    assert_eq!(result.phase, Some(RegistrationPhase::Completed));
}

#[tokio::test]
async fn test_get_certificates() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!([
        {
            "csrId": "550e8400-e29b-41d4-a716-446655440000",
            "certificatePEM": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "certificateValidFrom": "2024-01-01T00:00:00Z",
            "certificateValidTo": "2025-01-01T00:00:00Z",
            "certificateSubject": "CN=agent.example.com",
            "certificateIssuer": "CN=ANS CA"
        }
    ]);

    Mock::given(method("GET"))
        .and(path("/v1/agents/agent-123/certificates/server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.get_server_certificates("agent-123").await.unwrap();

    assert_eq!(result.len(), 1);
    assert!(result[0].certificate_pem.contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn test_submit_csr() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "csrId": "550e8400-e29b-41d4-a716-446655440001",
        "message": "CSR submitted successfully"
    });

    Mock::given(method("POST"))
        .and(path("/v1/agents/agent-123/certificates/identity"))
        .respond_with(ResponseTemplate::new(202).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----";
    let result = client.submit_identity_csr("agent-123", csr).await.unwrap();

    assert_eq!(
        result.csr_id.to_string(),
        "550e8400-e29b-41d4-a716-446655440001"
    );
}

#[tokio::test]
async fn test_revoke_agent() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "agentId": "550e8400-e29b-41d4-a716-446655440000",
        "ansName": "ans://v1.0.0.agent.example.com",
        "status": "REVOKED",
        "revokedAt": "2024-01-15T12:00:00Z",
        "reason": "KEY_COMPROMISE",
        "links": []
    });

    Mock::given(method("POST"))
        .and(path("/v1/agents/agent-123/revoke"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .revoke_agent(
            "agent-123",
            RevocationReason::KeyCompromise,
            Some("Key was exposed"),
        )
        .await
        .unwrap();

    assert_eq!(result.status, AgentLifecycleStatus::Revoked);
    assert_eq!(result.reason, RevocationReason::KeyCompromise);
}

#[tokio::test]
async fn test_unauthorized_error() {
    let server = MockServer::start().await;
    let client = AnsClient::builder()
        .base_url(server.uri())
        .allow_insecure() // mock server uses http://
        // No auth
        .build()
        .unwrap();

    let error_body = serde_json::json!({
        "status": "ERROR",
        "code": "401",
        "message": "Missing or invalid authorization header"
    });

    Mock::given(method("GET"))
        .and(path("/v1/agents/test"))
        .respond_with(ResponseTemplate::new(401).set_body_json(&error_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.get_agent("test").await;

    assert!(matches!(result, Err(ClientError::Unauthorized { .. })));
}

#[tokio::test]
async fn test_resolve_agent() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "ansName": "ans://v1.2.0.agent.example.com",
        "links": [
            {
                "rel": "agent-details",
                "href": "https://api.example.com/v1/agents/123"
            }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/v1/agents/resolution"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .resolve_agent("agent.example.com", "^1.0.0")
        .await
        .unwrap();

    assert_eq!(result.ans_name, "ans://v1.2.0.agent.example.com");
    assert!(!result.links.is_empty());
}

#[rstest]
#[case(400)]
#[case(401)]
#[case(403)]
#[case(404)]
#[case(409)]
#[case(500)]
#[tokio::test]
async fn test_error_status_codes(#[case] status_code: u16) {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let error_body = serde_json::json!({
        "status": "ERROR",
        "code": status_code.to_string(),
        "message": "Test error"
    });

    Mock::given(method("GET"))
        .and(path("/v1/agents/test"))
        .respond_with(ResponseTemplate::new(status_code).set_body_json(&error_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.get_agent("test").await;
    assert!(result.is_err());

    // Verify the error type matches and status code is preserved
    let err = result.unwrap_err();
    assert_eq!(err.status_code(), Some(status_code));
    match (status_code, &err) {
        (400, ClientError::InvalidRequest { .. }) => {}
        (401, ClientError::Unauthorized { .. }) => {}
        (403, ClientError::Forbidden { .. }) => {}
        (404, ClientError::NotFound { .. }) => {}
        (409, ClientError::Conflict { .. }) => {}
        (500, ClientError::ServerError { .. }) => {}
        _ => panic!(
            "Unexpected error type for status {}: {:?}",
            status_code, err
        ),
    }
}

// =========================================================================
// Event Tests
// =========================================================================

#[tokio::test]
async fn test_get_events_success() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "items": [
            {
                "logId": "log-001",
                "eventType": "AGENT_REGISTERED",
                "createdAt": "2024-01-15T12:00:00Z",
                "agentId": "550e8400-e29b-41d4-a716-446655440000",
                "ansName": "ans://v1.0.0.agent.example.com",
                "agentHost": "agent.example.com",
                "agentDisplayName": "Test Agent",
                "version": "1.0.0",
                "endpoints": []
            },
            {
                "logId": "log-002",
                "eventType": "AGENT_RENEWED",
                "createdAt": "2024-01-16T12:00:00Z",
                "agentId": "550e8400-e29b-41d4-a716-446655440001",
                "ansName": "ans://v2.0.0.other.example.com",
                "agentHost": "other.example.com",
                "version": "2.0.0",
                "endpoints": []
            }
        ],
        "lastLogId": "log-002"
    });

    Mock::given(method("GET"))
        .and(path("/v1/agents/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.get_events(None, None, None).await.unwrap();

    assert_eq!(result.items.len(), 2);
    assert_eq!(result.items[0].event_type, EventType::AgentRegistered);
    assert_eq!(result.items[1].event_type, EventType::AgentRenewed);
    assert_eq!(result.last_log_id, Some("log-002".to_string()));
}

#[tokio::test]
async fn test_get_events_with_params() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "items": [],
        "lastLogId": null
    });

    Mock::given(method("GET"))
        .and(path("/v1/agents/events"))
        .and(wiremock::matchers::query_param("limit", "10"))
        .and(wiremock::matchers::query_param(
            "providerId",
            "test-provider",
        ))
        .and(wiremock::matchers::query_param("lastLogId", "log-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .get_events(Some(10), Some("test-provider"), Some("log-123"))
        .await
        .unwrap();

    assert!(result.items.is_empty());
    assert!(result.last_log_id.is_none());
}

#[tokio::test]
async fn test_get_events_empty() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "items": []
    });

    Mock::given(method("GET"))
        .and(path("/v1/agents/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.get_events(Some(50), None, None).await.unwrap();

    assert!(result.items.is_empty());
    assert!(result.last_log_id.is_none());
}

// =========================================================================
// Identity Certificate Tests
// =========================================================================

#[tokio::test]
async fn test_get_identity_certificates() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!([
        {
            "csrId": "550e8400-e29b-41d4-a716-446655440000",
            "certificatePEM": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
            "certificateValidFrom": "2024-01-01T00:00:00Z",
            "certificateValidTo": "2025-01-01T00:00:00Z",
            "certificateSubject": "CN=agent.example.com",
            "certificateIssuer": "CN=ANS Private CA"
        }
    ]);

    Mock::given(method("GET"))
        .and(path("/v1/agents/agent-123/certificates/identity"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.get_identity_certificates("agent-123").await.unwrap();

    assert_eq!(result.len(), 1);
    assert!(result[0].certificate_pem.contains("BEGIN CERTIFICATE"));
    assert_eq!(
        result[0].certificate_issuer,
        Some("CN=ANS Private CA".to_string())
    );
}

#[tokio::test]
async fn test_submit_server_csr() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "csrId": "550e8400-e29b-41d4-a716-446655440002",
        "message": "Server CSR submitted successfully"
    });

    Mock::given(method("POST"))
        .and(path("/v1/agents/agent-123/certificates/server"))
        .respond_with(ResponseTemplate::new(202).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----";
    let result = client.submit_server_csr("agent-123", csr).await.unwrap();

    assert_eq!(
        result.csr_id.to_string(),
        "550e8400-e29b-41d4-a716-446655440002"
    );
}

// =========================================================================
// CSR Status Tests
// =========================================================================

#[tokio::test]
async fn test_get_csr_status_signed() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "csrId": "550e8400-e29b-41d4-a716-446655440001",
        "type": "IDENTITY",
        "status": "SIGNED",
        "submittedAt": "2024-01-15T12:00:00Z",
        "updatedAt": "2024-01-15T12:05:00Z"
    });

    Mock::given(method("GET"))
        .and(path(
            "/v1/agents/agent-123/csrs/550e8400-e29b-41d4-a716-446655440001/status",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .get_csr_status("agent-123", "550e8400-e29b-41d4-a716-446655440001")
        .await
        .unwrap();

    assert_eq!(
        result.csr_id.to_string(),
        "550e8400-e29b-41d4-a716-446655440001"
    );
    assert_eq!(result.csr_type, CsrType::Identity);
    assert_eq!(result.status, CsrStatus::Signed);
    assert!(result.failure_reason.is_none());
}

#[tokio::test]
async fn test_get_csr_status_rejected() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "csrId": "550e8400-e29b-41d4-a716-446655440002",
        "type": "SERVER",
        "status": "REJECTED",
        "submittedAt": "2024-01-15T12:00:00Z",
        "updatedAt": "2024-01-15T12:05:00Z",
        "failureReason": "Invalid key size: must be at least 2048 bits"
    });

    Mock::given(method("GET"))
        .and(path(
            "/v1/agents/agent-123/csrs/550e8400-e29b-41d4-a716-446655440002/status",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .get_csr_status("agent-123", "550e8400-e29b-41d4-a716-446655440002")
        .await
        .unwrap();

    assert_eq!(result.csr_type, CsrType::Server);
    assert_eq!(result.status, CsrStatus::Rejected);
    assert_eq!(
        result.failure_reason.as_deref(),
        Some("Invalid key size: must be at least 2048 bits")
    );
}

// =========================================================================
// URL Encoding Edge Case Tests
// =========================================================================

#[tokio::test]
async fn test_get_agent_url_encodes_slashes() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    // Agent ID containing slashes — must be percent-encoded in the URL path
    let response_body = serde_json::json!({
        "agentId": "org/agent/v1",
        "agentDisplayName": "test",
        "agentHost": "agent.example.com",
        "ansName": "ans://v1.0.0.agent.example.com",
        "version": "1.0.0",
        "agentStatus": "ACTIVE",
        "endpoints": [],
        "links": []
    });

    // wiremock matches the raw encoded path
    Mock::given(method("GET"))
        .and(path("/v1/agents/org%2Fagent%2Fv1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.get_agent("org/agent/v1").await.unwrap();
    assert_eq!(result.agent_id, "org/agent/v1");
}

#[tokio::test]
async fn test_get_agent_url_encodes_special_characters() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "agentId": "agent?id=1&v=2",
        "agentDisplayName": "test",
        "agentHost": "agent.example.com",
        "ansName": "ans://v1.0.0.agent.example.com",
        "version": "1.0.0",
        "agentStatus": "ACTIVE",
        "endpoints": [],
        "links": []
    });

    // ? and & and = must be encoded to avoid becoming query parameters
    Mock::given(method("GET"))
        .and(path("/v1/agents/agent%3Fid%3D1%26v%3D2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client.get_agent("agent?id=1&v=2").await.unwrap();
    assert_eq!(result.agent_id, "agent?id=1&v=2");
}

#[tokio::test]
async fn test_revoke_agent_url_encodes_id() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "agentId": "550e8400-e29b-41d4-a716-446655440000",
        "ansName": "ans://v1.0.0.agent.example.com",
        "status": "REVOKED",
        "revokedAt": "2024-01-15T12:00:00Z",
        "reason": "KEY_COMPROMISE",
        "links": []
    });

    // Percent-encoded percent sign in agent ID
    Mock::given(method("POST"))
        .and(path("/v1/agents/agent%25123/revoke"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let result = client
        .revoke_agent("agent%123", RevocationReason::KeyCompromise, None)
        .await
        .unwrap();

    assert_eq!(result.status, AgentLifecycleStatus::Revoked);
}

// =========================================================================
// API version lane routing (ApiVersion::V2) and discovery profiles
// =========================================================================

/// Create a test client targeting the V2 lane.
fn v2_test_client(server: &MockServer) -> AnsClient {
    AnsClient::builder()
        .base_url(server.uri())
        .jwt("test-token")
        .allow_insecure() // mock server uses http://
        .api_version(ApiVersion::V2)
        .build()
        .expect("client build failed")
}

/// A V2-lane client must register at the collection itself
/// (`POST /v2/ans/agents`), not the V1 `/v1/agents/register` route.
#[tokio::test]
async fn test_v2_lane_register_path() {
    let server = MockServer::start().await;
    let client = v2_test_client(&server);

    let response_body = serde_json::json!({
        "status": "PENDING_VALIDATION",
        "ansName": "ans://v1.0.0.agent.example.com",
        "agentId": "550e8400-e29b-41d4-a716-446655440000",
        "nextSteps": []
    });

    Mock::given(method("POST"))
        .and(path("/v2/ans/agents"))
        .respond_with(ResponseTemplate::new(202).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let pending = client
        .register_agent(&sample_registration_request())
        .await
        .unwrap();
    assert_eq!(pending.ans_name, "ans://v1.0.0.agent.example.com");
}

/// Every lane-routed agent method must target its `/v2/ans/agents`
/// twin when the client was built with [`ApiVersion::V2`]. The two
/// lanes serve identical shapes, so the path is the entire behavioral
/// difference under test.
#[tokio::test]
async fn test_v2_lane_agent_lifecycle_paths() {
    let server = MockServer::start().await;
    let client = v2_test_client(&server);

    let details = serde_json::json!({
        "agentId": "agent-123",
        "agentDisplayName": "test-agent",
        "agentHost": "agent.example.com",
        "ansName": "ans://v1.0.0.agent.example.com",
        "version": "1.0.0",
        "agentStatus": "PENDING_DNS",
        "endpoints": []
    });
    Mock::given(method("GET"))
        .and(path("/v2/ans/agents/agent-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&details))
        .expect(1)
        .mount(&server)
        .await;

    let status = serde_json::json!({ "status": "PENDING_DNS" });
    Mock::given(method("POST"))
        .and(path("/v2/ans/agents/agent-123/verify-acme"))
        .respond_with(ResponseTemplate::new(202).set_body_json(&status))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/ans/agents/agent-123/verify-dns"))
        .respond_with(ResponseTemplate::new(202).set_body_json(&status))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v2/ans/agents/agent-123/certificates/server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/ans/agents/agent-123/certificates/identity"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&server)
        .await;

    let submission = serde_json::json!({
        "csrId": "550e8400-e29b-41d4-a716-446655440001"
    });
    Mock::given(method("POST"))
        .and(path("/v2/ans/agents/agent-123/certificates/server"))
        .respond_with(ResponseTemplate::new(202).set_body_json(&submission))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v2/ans/agents/agent-123/certificates/identity"))
        .respond_with(ResponseTemplate::new(202).set_body_json(&submission))
        .expect(1)
        .mount(&server)
        .await;

    let csr_status = serde_json::json!({
        "csrId": "550e8400-e29b-41d4-a716-446655440001",
        "type": "SERVER",
        "status": "PENDING",
        "submittedAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-01T00:00:00Z"
    });
    Mock::given(method("GET"))
        .and(path(
            "/v2/ans/agents/agent-123/csrs/550e8400-e29b-41d4-a716-446655440001/status",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(&csr_status))
        .expect(1)
        .mount(&server)
        .await;

    let revocation = serde_json::json!({
        "agentId": "550e8400-e29b-41d4-a716-446655440000",
        "ansName": "ans://v1.0.0.agent.example.com",
        "status": "REVOKED",
        "revokedAt": "2024-01-15T12:00:00Z",
        "reason": "KEY_COMPROMISE",
        "links": []
    });
    Mock::given(method("POST"))
        .and(path("/v2/ans/agents/agent-123/revoke"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&revocation))
        .expect(1)
        .mount(&server)
        .await;

    let csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----";
    client.get_agent("agent-123").await.unwrap();
    client.verify_acme("agent-123").await.unwrap();
    client.verify_dns("agent-123").await.unwrap();
    client.get_server_certificates("agent-123").await.unwrap();
    client.get_identity_certificates("agent-123").await.unwrap();
    client.submit_server_csr("agent-123", csr).await.unwrap();
    client.submit_identity_csr("agent-123", csr).await.unwrap();
    client
        .get_csr_status("agent-123", "550e8400-e29b-41d4-a716-446655440001")
        .await
        .unwrap();
    client
        .revoke_agent("agent-123", RevocationReason::KeyCompromise, None)
        .await
        .unwrap();
}

/// Routes without a V2 twin on the server (search, resolution, events)
/// must keep their V1 paths even on a V2-lane client, so selecting V2
/// never changes the behavior of a route that only exists on V1.
#[tokio::test]
async fn test_v2_lane_keeps_v1_only_routes() {
    let server = MockServer::start().await;
    let client = v2_test_client(&server);

    let search_body = serde_json::json!({
        "agents": [],
        "totalCount": 0,
        "returnedCount": 0,
        "limit": 20,
        "offset": 0,
        "hasMore": false
    });
    Mock::given(method("GET"))
        .and(path("/v1/agents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&search_body))
        .expect(1)
        .mount(&server)
        .await;

    let resolution_body = serde_json::json!({
        "ansName": "ans://v1.0.0.agent.example.com",
        "links": []
    });
    Mock::given(method("POST"))
        .and(path("/v1/agents/resolution"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&resolution_body))
        .expect(1)
        .mount(&server)
        .await;

    let events_body = serde_json::json!({ "items": [] });
    Mock::given(method("GET"))
        .and(path("/v1/agents/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&events_body))
        .expect(1)
        .mount(&server)
        .await;

    client
        .search_agents(&SearchCriteria::default(), None, None)
        .await
        .unwrap();
    client
        .resolve_agent("agent.example.com", "*")
        .await
        .unwrap();
    client.get_events(None, None, None).await.unwrap();
}

/// Discovery profiles must serialize verbatim (in order) when set...
#[tokio::test]
async fn test_register_discovery_profiles_serialized() {
    let server = MockServer::start().await;
    let client = v2_test_client(&server);

    let response_body = serde_json::json!({
        "status": "PENDING_VALIDATION",
        "ansName": "ans://v1.0.0.agent.example.com",
        "nextSteps": []
    });
    Mock::given(method("POST"))
        .and(path("/v2/ans/agents"))
        .respond_with(ResponseTemplate::new(202).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let request = sample_registration_request()
        .with_discovery_profiles(vec![DiscoveryProfile::AnsDnsaid, DiscoveryProfile::AnsTxt]);
    client.register_agent(&request).await.unwrap();

    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        body["discoveryProfiles"],
        serde_json::json!(["ANS_DNSAID", "ANS_TXT"])
    );
}

/// ...and the key must be absent (not null, not []) when unset: an
/// omitted field means "apply the server default", and the request must
/// not look like an explicit choice.
#[tokio::test]
async fn test_register_discovery_profiles_omitted_when_empty() {
    let server = MockServer::start().await;
    let client = v2_test_client(&server);

    let response_body = serde_json::json!({
        "status": "PENDING_VALIDATION",
        "ansName": "ans://v1.0.0.agent.example.com",
        "nextSteps": []
    });
    Mock::given(method("POST"))
        .and(path("/v2/ans/agents"))
        .respond_with(ResponseTemplate::new(202).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    client
        .register_agent(&sample_registration_request())
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert!(
        body.get("discoveryProfiles").is_none(),
        "discoveryProfiles must be omitted when empty; got {body}"
    );
}

/// The Go reference RA marshals nil slices as JSON `null` (not `[]`,
/// not absent) — e.g. `"pendingSteps": null` on the verify-dns response
/// once every step is complete. List fields on response models must
/// tolerate all three spellings.
#[tokio::test]
async fn test_agent_status_null_step_lists_deserialize() {
    let server = MockServer::start().await;
    let client = test_client(&server);

    let response_body = serde_json::json!({
        "status": "ACTIVE",
        "phase": "COMPLETED",
        "completedSteps": null,
        "pendingSteps": null,
        "createdAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-02T00:00:00Z"
    });

    Mock::given(method("POST"))
        .and(path("/v1/agents/agent-123/verify-dns"))
        .respond_with(ResponseTemplate::new(202).set_body_json(&response_body))
        .expect(1)
        .mount(&server)
        .await;

    let status = client.verify_dns("agent-123").await.unwrap();
    assert_eq!(status.status, AgentLifecycleStatus::Active);
    assert!(status.completed_steps.is_empty());
    assert!(status.pending_steps.is_empty());
}
