# ans-client

HTTP client for the ANS (Agent Name Service) Registry API.

## Overview

This crate provides `AnsClient` for agent registration, certificate management, and discovery operations against the ANS Registration Authority API.

## Quick Start

```rust
use ans_client::{AnsClient, models::*};

#[tokio::main]
async fn main() -> ans_client::Result<()> {
    let client = AnsClient::builder()
        .base_url("https://api.godaddy.com")
        .jwt("your-jwt-token")
        .build()?;

    // Search for agents
    let mut criteria = SearchCriteria::default();
    criteria.agent_host = Some("example.com".into());
    let results = client.search_agents(&criteria, Some(10), None).await?;

    for agent in results.agents {
        println!("{}: {}", agent.ans_name, agent.agent_display_name);
    }

    Ok(())
}
```

## Authentication

Two authentication methods are supported:

```rust
// JWT for internal endpoints (ra.int.{env}.godaddy.com)
let client = AnsClient::builder()
    .jwt("your-jwt-token")
    .build()?;

// API key for public gateway (api.{env}.godaddy.com)
let client = AnsClient::builder()
    .api_key("your-key", "your-secret")
    .build()?;
```

## API Operations

### Registration

```rust
let endpoint = AgentEndpoint::new("https://agent.example.com/mcp", Protocol::Mcp)
    .with_transports(vec![Transport::StreamableHttp]);

let request = AgentRegistrationRequest::new(
    "my-agent",
    "agent.example.com",
    "1.0.0",
    identity_csr,
    vec![endpoint],
)
.with_description("My AI agent")
.with_server_csr_pem(server_csr);

let response = client.register_agent(&request).await?;
```

#### DNS discovery profiles (V2 API lane)

Discovery profiles select which DNS record families the Registration
Authority asks the operator to publish. They are a V2-lane feature:
build the client with `.api_version(ApiVersion::V2)` and (optionally)
set profiles on the request — omitted profiles mean the server default,
`ANS_DNSAID` (RFC 9460 SVCB records). The V1 lane (default) ignores the
field and always emits the legacy `_ans` TXT family.

```rust
use ans_client::{AnsClient, ApiVersion, models::DiscoveryProfile};

let client = AnsClient::builder()
    .base_url("https://api.godaddy.com")
    .api_key("your-key", "your-secret")
    .api_version(ApiVersion::V2)
    .build()?;

// Publish the union of SVCB + legacy TXT during a transition:
let request = request.with_discovery_profiles(vec![
    DiscoveryProfile::AnsDnsaid,
    DiscoveryProfile::AnsTxt,
]);
```

### Discovery

```rust
// Get agent by ID
let agent = client.get_agent("agent-id").await?;

// Search agents
let mut criteria = SearchCriteria::default();
criteria.agent_host = Some("example.com".into());
let results = client.search_agents(&criteria, Some(10), None).await?;

// Resolve by host and version
let agent = client.resolve_agent("agent.example.com", "1.0.0").await?;
```

### Certificates

```rust
let certs = client.get_server_certificates("agent-id").await?;
let identity_certs = client.get_identity_certificates("agent-id").await?;
```

### Revocation

```rust
use ans_client::models::RevocationReason;

client.revoke_agent("agent-id", RevocationReason::KeyCompromise, None).await?;
```

### Events

```rust
let events = client.get_events(Some(100), None, None).await?;
```

## Builder Options

```rust
use std::time::Duration;

let client = AnsClient::builder()
    .base_url("https://api.godaddy.com")
    .jwt("token")
    .timeout(Duration::from_secs(30))
    .header("x-request-id", "abc-123")  // custom headers
    .api_version(ApiVersion::V2)        // RA API lane (default: V1)
    .build()?;
```

## Error Handling

All methods return `Result<T, ClientError>`. HTTP errors are mapped to typed variants:

| Status | Error Variant |
|---|---|
| 400 | `ClientError::InvalidRequest` |
| 401 | `ClientError::Unauthorized` |
| 403 | `ClientError::Forbidden` |
| 404 | `ClientError::NotFound` |
| 409 | `ClientError::Conflict` |
| 422 | `ClientError::UnprocessableEntity` |
| 429 | `ClientError::RateLimited` |
| 5xx | `ClientError::ServerError` |

## License

MIT
