//! API request and response models for the ANS Registry.
//!
//! These types map to the `OpenAPI` specification for the ANS API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Deserialize a JSON `null` as the type's default value.
///
/// The reference Registration Authority is written in Go, whose
/// `encoding/json` marshals a nil slice as `null` rather than omitting
/// the key or emitting `[]` (e.g. `"pendingSteps": null` on an ACTIVE
/// agent's verify response). `#[serde(default)]` alone only covers an
/// absent key, so defaulted list fields on response models pair it with
/// this helper to accept all three spellings: absent, `null`, and `[]`.
fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// Communication protocol used by agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Protocol {
    /// Agent-to-Agent protocol.
    #[serde(rename = "A2A")]
    A2A,
    /// Model Context Protocol.
    #[serde(rename = "MCP")]
    Mcp,
    /// HTTP-based API.
    #[serde(rename = "HTTP-API", alias = "HTTP_API")]
    HttpApi,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A2A => write!(f, "A2A"),
            Self::Mcp => write!(f, "MCP"),
            Self::HttpApi => write!(f, "HTTP-API"),
        }
    }
}

/// Transport mechanism for agent communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Transport {
    /// Streamable HTTP transport.
    #[serde(rename = "STREAMABLE-HTTP", alias = "STREAMABLE_HTTP")]
    StreamableHttp,
    /// Server-Sent Events.
    #[serde(rename = "SSE")]
    Sse,
    /// JSON-RPC transport.
    #[serde(rename = "JSON-RPC", alias = "JSON_RPC")]
    JsonRpc,
    /// gRPC transport.
    #[serde(rename = "GRPC")]
    Grpc,
    /// REST transport.
    #[serde(rename = "REST")]
    Rest,
    /// Generic HTTP transport.
    #[serde(rename = "HTTP")]
    Http,
}

/// A function/capability provided by an agent endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AgentFunction {
    /// Unique identifier for the function.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Tags for categorization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl AgentFunction {
    /// Create a new agent function.
    pub fn new(id: impl Into<String>, name: impl Into<String>, tags: Vec<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            tags,
        }
    }
}

/// An agent endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AgentEndpoint {
    /// URL where the agent accepts requests.
    pub agent_url: String,
    /// URL for agent metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta_data_url: Option<String>,
    /// URL for agent documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    /// Communication protocol.
    pub protocol: Protocol,
    /// Supported transport mechanisms.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<Transport>,
    /// Functions provided by this endpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<AgentFunction>,
}

impl AgentEndpoint {
    /// Create a new endpoint with required fields.
    pub fn new(agent_url: impl Into<String>, protocol: Protocol) -> Self {
        Self {
            agent_url: agent_url.into(),
            meta_data_url: None,
            documentation_url: None,
            protocol,
            transports: Vec::new(),
            functions: Vec::new(),
        }
    }

    /// Set the transport mechanisms.
    pub fn with_transports(mut self, transports: Vec<Transport>) -> Self {
        self.transports = transports;
        self
    }

    /// Set the functions.
    pub fn with_functions(mut self, functions: Vec<AgentFunction>) -> Self {
        self.functions = functions;
        self
    }
}

/// DNS record family the Registration Authority tells the operator to
/// publish for an agent registration.
///
/// Selected via
/// [`AgentRegistrationRequest::with_discovery_profiles`]. Discovery
/// profiles are a V2-lane feature
/// ([`ApiVersion::V2`](crate::ApiVersion)): the V1 lane ignores the
/// field server-side and always emits the [`AnsTxt`](Self::AnsTxt)
/// family, so [`register_agent`](crate::AnsClient::register_agent)
/// rejects a non-empty set on a V1-lane client. Wire values are the V2
/// register schema's `CONSTANT_CASE` enum.
///
/// `Serialize`-only by design: the enum appears only in the
/// `Serialize`-only registration request today, and deriving
/// `Deserialize` on a `#[non_exhaustive]` enum would make one unknown
/// future value fail a whole response parse — the failure mode the
/// deliberately-`String` [`DnsRecord::record_type`] exists to avoid.
/// Add a `#[serde(other)]` catch-all if this ever becomes
/// response-visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum DiscoveryProfile {
    /// DNS-AID-aligned Consolidated Approach (RFC 9460): one SVCB row
    /// per protocol endpoint at the bare FQDN plus the `_ans-badge` TXT
    /// and TLSA trust records. The server default when the request
    /// omits discovery profiles.
    #[serde(rename = "ANS_DNSAID")]
    AnsDnsaid,
    /// Original `_ans` TXT shape (one row per protocol at
    /// `_ans.{fqdn}`) plus an HTTPS RR at the bare FQDN and the same
    /// trust records. Opt-in for operators with zone-edit tooling that
    /// targets `_ans.{fqdn}`.
    #[serde(rename = "ANS_TXT")]
    AnsTxt,
}

/// Request to register a new agent.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AgentRegistrationRequest {
    /// Human-readable agent name.
    pub agent_display_name: String,
    /// FQDN where the agent is hosted.
    pub agent_host: String,
    /// Semantic version (e.g., "1.0.0").
    pub version: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_description: Option<String>,
    /// CSR for identity certificate (required).
    #[serde(rename = "identityCsrPEM")]
    pub identity_csr_pem: String,
    /// CSR for server certificate (mutually exclusive with `server_certificate_pem`).
    #[serde(rename = "serverCsrPEM", skip_serializing_if = "Option::is_none")]
    pub server_csr_pem: Option<String>,
    /// BYOC server certificate (mutually exclusive with `server_csr_pem`).
    #[serde(
        rename = "serverCertificatePEM",
        skip_serializing_if = "Option::is_none"
    )]
    pub server_certificate_pem: Option<String>,
    /// Certificate chain for BYOC server certificate.
    #[serde(
        rename = "serverCertificateChainPEM",
        skip_serializing_if = "Option::is_none"
    )]
    pub server_certificate_chain_pem: Option<String>,
    /// Agent endpoints.
    pub endpoints: Vec<AgentEndpoint>,
    /// DNS record families the RA asks the operator to publish (V2
    /// lane only — see [`DiscoveryProfile`]). Empty means the field is
    /// omitted on the wire and the server applies its default
    /// ([`DiscoveryProfile::AnsDnsaid`]); send both values to publish
    /// the union during a transition.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub discovery_profiles: Vec<DiscoveryProfile>,
}

impl AgentRegistrationRequest {
    /// Create a new registration request with required fields.
    pub fn new(
        agent_display_name: impl Into<String>,
        agent_host: impl Into<String>,
        version: impl Into<String>,
        identity_csr_pem: impl Into<String>,
        endpoints: Vec<AgentEndpoint>,
    ) -> Self {
        Self {
            agent_display_name: agent_display_name.into(),
            agent_host: agent_host.into(),
            version: version.into(),
            agent_description: None,
            identity_csr_pem: identity_csr_pem.into(),
            server_csr_pem: None,
            server_certificate_pem: None,
            server_certificate_chain_pem: None,
            endpoints,
            discovery_profiles: Vec::new(),
        }
    }

    /// Set the DNS discovery profiles (V2 lane only — see
    /// [`DiscoveryProfile`]).
    pub fn with_discovery_profiles(mut self, profiles: Vec<DiscoveryProfile>) -> Self {
        self.discovery_profiles = profiles;
        self
    }

    /// Set the agent description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.agent_description = Some(description.into());
        self
    }

    /// Set the server CSR PEM.
    pub fn with_server_csr_pem(mut self, csr: impl Into<String>) -> Self {
        self.server_csr_pem = Some(csr.into());
        self
    }

    /// Set the server certificate PEM (BYOC).
    pub fn with_server_certificate_pem(mut self, cert: impl Into<String>) -> Self {
        self.server_certificate_pem = Some(cert.into());
        self
    }

    /// Set the server certificate chain PEM (BYOC).
    pub fn with_server_certificate_chain_pem(mut self, chain: impl Into<String>) -> Self {
        self.server_certificate_chain_pem = Some(chain.into());
        self
    }
}

/// Registration status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum RegistrationStatus {
    /// Waiting for domain validation.
    PendingValidation,
    /// Waiting for certificates.
    PendingCerts,
    /// Waiting for DNS configuration.
    PendingDns,
}

/// Agent lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum AgentLifecycleStatus {
    /// Waiting for validation.
    PendingValidation,
    /// Waiting for DNS.
    PendingDns,
    /// Agent is active.
    Active,
    /// Registration failed.
    Failed,
    /// Registration expired.
    Expired,
    /// Agent was revoked.
    Revoked,
}

/// HATEOAS link.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Link {
    /// Link relation type.
    pub rel: String,
    /// Link URL.
    pub href: String,
}

/// DNS record to be configured.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DnsRecord {
    /// Full DNS record name.
    pub name: String,
    /// Record type (SVCB, HTTPS, TLSA, TXT).
    ///
    /// Kept as a string rather than an enum so record families added by
    /// the server (e.g. the RFC 9460 SVCB rows the `ANS_DNSAID` discovery
    /// profile emits) deserialize without an SDK update.
    #[serde(rename = "type")]
    pub record_type: String,
    /// Record value.
    pub value: String,
    /// Purpose of this record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// TTL in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<i32>,
    /// Priority for HTTPS records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    /// Whether this record is required.
    #[serde(default = "default_true")]
    pub required: bool,
}

fn default_true() -> bool {
    true
}

/// ACME challenge type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ChallengeType {
    /// DNS-01 challenge.
    #[serde(rename = "DNS_01")]
    Dns01,
    /// HTTP-01 challenge.
    #[serde(rename = "HTTP_01")]
    Http01,
}

/// DNS record details for ACME challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DnsRecordDetails {
    /// Record name.
    pub name: String,
    /// Record type.
    #[serde(rename = "type")]
    pub record_type: String,
    /// Record value.
    pub value: String,
}

/// ACME challenge information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ChallengeInfo {
    /// Challenge type.
    #[serde(rename = "type")]
    pub challenge_type: ChallengeType,
    /// Challenge token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Key authorization string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_authorization: Option<String>,
    /// HTTP path for HTTP-01 challenge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_path: Option<String>,
    /// DNS record for DNS-01 challenge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_record: Option<DnsRecordDetails>,
    /// Challenge expiration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Action to take in next step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum NextStepAction {
    /// Configure DNS records.
    ConfigureDns,
    /// Configure HTTP challenge.
    ConfigureHttp,
    /// Verify DNS records.
    VerifyDns,
    /// Validate domain ownership.
    ValidateDomain,
    /// Wait for processing.
    Wait,
}

/// A required action to continue registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct NextStep {
    /// Action to take.
    pub action: NextStepAction,
    /// Description of the step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// API endpoint for the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Estimated time in minutes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_time_minutes: Option<i32>,
}

/// Response for pending registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RegistrationPending {
    /// Current registration status.
    pub status: RegistrationStatus,
    /// ANS name being registered.
    pub ans_name: String,
    /// Agent ID (when available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Required actions.
    pub next_steps: Vec<NextStep>,
    /// ACME challenges.
    #[serde(default, deserialize_with = "null_as_default")]
    pub challenges: Vec<ChallengeInfo>,
    /// DNS records to configure.
    #[serde(default, deserialize_with = "null_as_default")]
    pub dns_records: Vec<DnsRecord>,
    /// Registration expiration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// HATEOAS links.
    #[serde(default, deserialize_with = "null_as_default")]
    pub links: Vec<Link>,
}

impl RegistrationPending {
    /// Gets the agent ID, either from the field or by parsing the self link.
    ///
    /// The API may not include `agent_id` in the response body, but it's
    /// available in the `self` link (e.g., `/v1/agents/{agent_id}`).
    pub fn get_agent_id(&self) -> Option<String> {
        // First try the direct field
        if let Some(ref id) = self.agent_id {
            return Some(id.clone());
        }

        // Fall back to parsing from self link
        self.links
            .iter()
            .find(|link| link.rel == "self")
            .and_then(|link| {
                // Parse agent ID from href like "/v1/agents/{agent_id}" or full URL
                link.href
                    .trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .filter(|s| !s.is_empty() && *s != "agents")
                    .map(String::from)
            })
    }
}

/// Registration phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum RegistrationPhase {
    /// Initial setup.
    Initialization,
    /// Validating domain ownership.
    DomainValidation,
    /// Issuing certificates.
    CertificateIssuance,
    /// Provisioning DNS.
    DnsProvisioning,
    /// Registration complete.
    Completed,
}

/// Agent status information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AgentStatus {
    /// Lifecycle status.
    pub status: AgentLifecycleStatus,
    /// Current phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<RegistrationPhase>,
    /// Completed steps.
    #[serde(default, deserialize_with = "null_as_default")]
    pub completed_steps: Vec<String>,
    /// Pending steps.
    #[serde(default, deserialize_with = "null_as_default")]
    pub pending_steps: Vec<String>,
    /// When created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    /// Last updated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    /// Registration expiration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Detailed agent information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AgentDetails {
    /// Unique agent identifier.
    pub agent_id: String,
    /// Display name.
    pub agent_display_name: String,
    /// Hosting domain.
    pub agent_host: String,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_description: Option<String>,
    /// Full ANS name.
    pub ans_name: String,
    /// Version.
    pub version: String,
    /// Lifecycle status.
    pub agent_status: AgentLifecycleStatus,
    /// Endpoints.
    pub endpoints: Vec<AgentEndpoint>,
    /// Registration timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_timestamp: Option<DateTime<Utc>>,
    /// Last renewal timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_renewal_timestamp: Option<DateTime<Utc>>,
    /// Pending registration details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_pending: Option<RegistrationPending>,
    /// HATEOAS links.
    #[serde(default, deserialize_with = "null_as_default")]
    pub links: Vec<Link>,
}

/// Search criteria.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SearchCriteria {
    /// Filter by protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    /// Filter by display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_display_name: Option<String>,
    /// Filter by version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Filter by host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_host: Option<String>,
}

/// Agent search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AgentSearchResult {
    /// ANS name.
    pub ans_name: String,
    /// Agent ID.
    pub agent_id: String,
    /// Display name.
    pub agent_display_name: String,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_description: Option<String>,
    /// Version.
    pub version: String,
    /// Hosting domain.
    pub agent_host: String,
    /// TTL in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<i32>,
    /// Registration timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_timestamp: Option<DateTime<Utc>>,
    /// Endpoints.
    pub endpoints: Vec<AgentEndpoint>,
    /// HATEOAS links.
    #[serde(default, deserialize_with = "null_as_default")]
    pub links: Vec<Link>,
}

/// Search results response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AgentSearchResponse {
    /// Matching agents.
    pub agents: Vec<AgentSearchResult>,
    /// Total matching count.
    pub total_count: i32,
    /// Count returned in this response.
    pub returned_count: i32,
    /// Pagination limit.
    pub limit: i32,
    /// Pagination offset.
    pub offset: i32,
    /// Whether more results are available.
    pub has_more: bool,
    /// Search criteria used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_criteria: Option<SearchCriteria>,
}

/// Revocation reason (RFC 5280).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum RevocationReason {
    /// Private key compromised.
    KeyCompromise,
    /// Agent decommissioned.
    CessationOfOperation,
    /// Affiliation changed.
    AffiliationChanged,
    /// Superseded by new certificate.
    Superseded,
    /// Temporarily on hold.
    CertificateHold,
    /// Privileges withdrawn.
    PrivilegeWithdrawn,
    /// AA compromised.
    AaCompromise,
}

/// Request to revoke an agent.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct AgentRevocationRequest {
    /// Reason for revocation.
    pub reason: RevocationReason,
    /// Additional comments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,
}

/// Revocation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AgentRevocationResponse {
    /// Agent ID.
    pub agent_id: Uuid,
    /// ANS name.
    pub ans_name: String,
    /// Status (will be REVOKED).
    pub status: AgentLifecycleStatus,
    /// When revocation occurred.
    pub revoked_at: DateTime<Utc>,
    /// Revocation reason.
    pub reason: RevocationReason,
    /// HATEOAS links.
    pub links: Vec<Link>,
}

/// Certificate information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CertificateResponse {
    /// CSR ID that generated this certificate.
    pub csr_id: Uuid,
    /// Certificate subject DN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_subject: Option<String>,
    /// Certificate issuer DN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_issuer: Option<String>,
    /// Serial number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_serial_number: Option<String>,
    /// Validity start.
    pub certificate_valid_from: DateTime<Utc>,
    /// Validity end.
    pub certificate_valid_to: DateTime<Utc>,
    /// PEM-encoded certificate.
    #[serde(rename = "certificatePEM")]
    pub certificate_pem: String,
    /// PEM-encoded certificate chain.
    #[serde(rename = "chainPEM", skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<String>,
    /// Public key algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_public_key_algorithm: Option<String>,
    /// Signature algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_signature_algorithm: Option<String>,
}

/// CSR submission request.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CsrSubmissionRequest {
    /// PEM-encoded CSR.
    #[serde(rename = "csrPEM")]
    pub csr_pem: String,
}

/// CSR submission response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CsrSubmissionResponse {
    /// Assigned CSR ID.
    pub csr_id: Uuid,
    /// Optional message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// CSR type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum CsrType {
    /// Server certificate CSR.
    Server,
    /// Identity certificate CSR.
    Identity,
}

/// CSR status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum CsrStatus {
    /// Pending processing.
    Pending,
    /// Signed and ready.
    Signed,
    /// Rejected.
    Rejected,
}

/// CSR status response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CsrStatusResponse {
    /// CSR ID.
    pub csr_id: Uuid,
    /// CSR type.
    #[serde(rename = "type")]
    pub csr_type: CsrType,
    /// Current status.
    pub status: CsrStatus,
    /// Submission time.
    pub submitted_at: DateTime<Utc>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
    /// Rejection reason (when rejected).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

/// Resolution request.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AgentResolutionRequest {
    /// Agent host domain.
    pub agent_host: String,
    /// Version pattern (e.g., "*", "^1.0.0").
    pub version: String,
}

/// Resolution response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AgentResolutionResponse {
    /// Resolved ANS name.
    pub ans_name: String,
    /// HATEOAS links.
    pub links: Vec<Link>,
}

// =========================================================================
// Event Types
// =========================================================================

/// Event type for agent lifecycle events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum EventType {
    /// Agent was registered.
    AgentRegistered,
    /// Agent registration was renewed.
    AgentRenewed,
    /// Agent was revoked.
    AgentRevoked,
    /// Agent version was updated.
    AgentVersionUpdated,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AgentRegistered => write!(f, "AGENT_REGISTERED"),
            Self::AgentRenewed => write!(f, "AGENT_RENEWED"),
            Self::AgentRevoked => write!(f, "AGENT_REVOKED"),
            Self::AgentVersionUpdated => write!(f, "AGENT_VERSION_UPDATED"),
        }
    }
}

/// An individual agent event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct EventItem {
    /// Log entry ID (used for pagination continuation).
    pub log_id: String,
    /// Type of event.
    pub event_type: EventType,
    /// When the event occurred.
    pub created_at: DateTime<Utc>,
    /// When the agent expires (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Agent ID.
    pub agent_id: Uuid,
    /// ANS name (e.g., `ans://v1.0.0.agent.example.com`).
    pub ans_name: String,
    /// Agent host domain.
    pub agent_host: String,
    /// Human-readable agent name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_display_name: Option<String>,
    /// Agent description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_description: Option<String>,
    /// Agent version.
    pub version: String,
    /// Provider ID (for AHP filtering).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    /// Agent endpoints at time of event.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<AgentEndpoint>,
}

/// Paginated events response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct EventPageResponse {
    /// List of events in this page.
    pub items: Vec<EventItem>,
    /// Last log ID for pagination (pass as `last_log_id` to get next page).
    /// None if this is the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_log_id: Option<String>,
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    fn make_pending_with_links(
        agent_id: Option<&str>,
        links: Vec<(&str, &str)>,
    ) -> RegistrationPending {
        RegistrationPending {
            status: RegistrationStatus::PendingValidation,
            ans_name: "ans://v1.0.0.agent.example.com".to_string(),
            agent_id: agent_id.map(String::from),
            next_steps: vec![],
            challenges: vec![],
            dns_records: vec![],
            expires_at: None,
            links: links
                .into_iter()
                .map(|(rel, href)| Link {
                    rel: rel.to_string(),
                    href: href.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn test_get_agent_id_from_field() {
        let pending = make_pending_with_links(Some("direct-id"), vec![]);
        assert_eq!(pending.get_agent_id(), Some("direct-id".to_string()));
    }

    #[test]
    fn test_get_agent_id_from_self_link_path() {
        let pending = make_pending_with_links(None, vec![("self", "/v1/agents/uuid-from-link")]);
        assert_eq!(pending.get_agent_id(), Some("uuid-from-link".to_string()));
    }

    #[test]
    fn test_get_agent_id_from_self_link_full_url() {
        let pending = make_pending_with_links(
            None,
            vec![("self", "https://api.example.com/v1/agents/uuid-full-url")],
        );
        assert_eq!(pending.get_agent_id(), Some("uuid-full-url".to_string()));
    }

    #[test]
    fn test_get_agent_id_from_self_link_trailing_slash() {
        let pending = make_pending_with_links(None, vec![("self", "/v1/agents/uuid-trailing/")]);
        assert_eq!(pending.get_agent_id(), Some("uuid-trailing".to_string()));
    }

    #[test]
    fn test_get_agent_id_prefers_field_over_link() {
        let pending =
            make_pending_with_links(Some("field-id"), vec![("self", "/v1/agents/link-id")]);
        assert_eq!(pending.get_agent_id(), Some("field-id".to_string()));
    }

    #[test]
    fn test_get_agent_id_no_self_link() {
        let pending = make_pending_with_links(None, vec![("other", "/v1/something/else")]);
        assert_eq!(pending.get_agent_id(), None);
    }

    #[test]
    fn test_get_agent_id_empty_links() {
        let pending = make_pending_with_links(None, vec![]);
        assert_eq!(pending.get_agent_id(), None);
    }
}
