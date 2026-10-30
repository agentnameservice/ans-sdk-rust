//! V2 owner listing and server-certificate renewal contracts.

use super::{
    AgentEndpoint, AgentLifecycleStatus, ChallengeType, DnsRecord, Link, NextStepAction,
    null_as_default,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Filters accepted by the owner-scoped V2 agent collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum AgentLifecycleStatusFilter {
    /// Registrations awaiting DNS activation.
    PendingDns,
    /// Active registrations (the server default).
    Active,
    /// Deprecated registrations.
    Deprecated,
    /// Revoked registrations.
    Revoked,
    /// Every lifecycle status.
    All,
}
impl AgentLifecycleStatusFilter {
    /// The wire value used by the status query parameter.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PendingDns => "PENDING_DNS",
            Self::Active => "ACTIVE",
            Self::Deprecated => "DEPRECATED",
            Self::Revoked => "REVOKED",
            Self::All => "ALL",
        }
    }
}

/// Options for listing the authenticated caller's agents, not public discovery.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AgentListOptions {
    /// Repeated `status` filters; empty lets the server use ACTIVE.
    pub statuses: Vec<AgentLifecycleStatusFilter>,
    /// Exact host filter.
    pub agent_host: Option<String>,
    /// Page size, from 1 through 100.
    pub limit: Option<u32>,
    /// Opaque cursor from the preceding page.
    pub cursor: Option<String>,
}

/// One agent in an owner-scoped management page.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AgentListItem {
    /// Full versioned ANS name.
    pub ans_name: String,
    /// Registration identifier.
    pub agent_id: String,
    /// Display name.
    pub agent_display_name: String,
    /// Optional description.
    pub agent_description: Option<String>,
    /// Registration version.
    pub version: String,
    /// Agent host.
    pub agent_host: String,
    /// Current lifecycle status.
    pub status: AgentLifecycleStatus,
    /// Suggested cache lifetime in seconds.
    pub ttl: Option<u32>,
    /// Registration time, when supplied.
    pub registration_timestamp: Option<DateTime<Utc>>,
    /// Registered endpoints.
    pub endpoints: Vec<AgentEndpoint>,
    /// Management links.
    #[serde(default, deserialize_with = "null_as_default")]
    pub links: Vec<Link>,
}

/// Cursor-paginated owner collection returned by `GET /v2/ans/agents`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AgentListResponse {
    /// Agents in this page.
    pub items: Vec<AgentListItem>,
    /// Number returned in this page.
    pub returned_count: u32,
    /// Applied page size.
    pub limit: u32,
    /// Cursor for the next request, absent/null on the final page.
    pub next_cursor: Option<String>,
    /// Whether another page exists.
    pub has_more: bool,
}

/// Exactly one server certificate source for renewal.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum ServerCertificateRenewalRequest {
    /// Ask the RA to issue a certificate for this CSR.
    Csr {
        /// PEM CSR.
        #[serde(rename = "serverCsrPEM")]
        csr_pem: String,
    },
    /// Register a supplied server certificate.
    Byoc {
        /// PEM certificate.
        #[serde(rename = "serverCertificatePEM")]
        certificate_pem: String,
        /// Optional PEM chain.
        #[serde(
            rename = "serverCertificateChainPEM",
            skip_serializing_if = "Option::is_none"
        )]
        chain_pem: Option<String>,
    },
}
impl ServerCertificateRenewalRequest {
    /// Renew using a CSR.
    pub fn csr(csr_pem: impl Into<String>) -> Self {
        Self::Csr {
            csr_pem: csr_pem.into(),
        }
    }
    /// Renew using a supplied certificate and optional chain.
    pub fn byoc(certificate_pem: impl Into<String>, chain_pem: Option<String>) -> Self {
        Self::Byoc {
            certificate_pem: certificate_pem.into(),
            chain_pem,
        }
    }
}

/// Certificate source used by a renewal order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum RenewalType {
    /// Certificate issuance from a CSR.
    ServerCsr,
    /// Operator-supplied certificate.
    ServerByoc,
}

/// States returned by renewal submission, polling, and ACME verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum RenewalStatus {
    /// Awaiting domain validation.
    PendingValidation,
    /// Certificate issuance in progress.
    IssuingCertificate,
    /// ACME validation succeeded.
    Verified,
    /// Renewal completed.
    Completed,
    /// Renewal failed.
    Failed,
    /// Renewal window expired.
    Expired,
}

/// Renewal challenges are keyed by ACME method, unlike registration's array.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RenewalChallenges {
    /// DNS-01 challenge, if required.
    pub dns01: Option<RenewalChallengeInfo>,
    /// HTTP-01 challenge, if required.
    pub http01: Option<RenewalChallengeInfo>,
}

/// Accepted renewal order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RenewalSubmissionResponse {
    /// CSR or BYOC source.
    pub renewal_type: RenewalType,
    /// Initial order state.
    pub status: RenewalStatus,
    /// CSR identifier, if applicable.
    pub csr_id: Option<String>,
    /// Domain-control challenges, if required.
    pub challenges: Option<RenewalChallenges>,
    /// Deadline for this order.
    pub expires_at: DateTime<Utc>,
    /// Next action required from the caller.
    pub next_step: RenewalNextStep,
    /// Management links.
    #[serde(default, deserialize_with = "null_as_default")]
    pub links: Vec<Link>,
}

/// Current renewal order, including certificate-binding instructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RenewalStatusResponse {
    /// CSR or BYOC source.
    pub renewal_type: RenewalType,
    /// Order state.
    pub status: RenewalStatus,
    /// CSR identifier, if applicable.
    pub csr_id: Option<String>,
    /// Domain-control challenges, if required.
    pub challenges: Option<RenewalChallenges>,
    /// TLSA publication instructions returned after renewal.
    pub tlsa_dns_record: Option<DnsRecord>,
    /// Explanation of a failed order.
    pub failure_reason: Option<String>,
    /// Order deadline.
    pub expires_at: DateTime<Utc>,
    /// Next required action.
    pub next_step: RenewalNextStep,
}

/// ACME verification result for a renewal (HTTP 200 or 202).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RenewalVerificationResponse {
    /// Validation/issuance state.
    pub status: RenewalStatus,
    /// CSR identifier, if applicable.
    pub csr_id: Option<String>,
    /// TLSA publication instructions, if available.
    pub tlsa_dns_record: Option<DnsRecord>,
    /// Next required action.
    pub next_step: RenewalNextStep,
}

/// ACME challenge information in a renewal response. The parent key selects
/// DNS-01 or HTTP-01 even when the optional `type` member is absent.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RenewalChallengeInfo {
    /// Challenge method, when repeated in the payload.
    #[serde(rename = "type")]
    pub challenge_type: Option<ChallengeType>,
    /// Challenge token.
    pub token: Option<String>,
    /// ACME key authorization.
    pub key_authorization: Option<String>,
    /// HTTP-01 path.
    pub http_path: Option<String>,
    /// DNS-01 record.
    pub dns_record: Option<RenewalDnsRecordDetails>,
    /// Challenge deadline.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Optional next-action members returned by the V2 renewal contract.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RenewalNextStep {
    /// Action, when another caller action is required.
    pub action: Option<NextStepAction>,
    /// Human-readable instructions.
    pub description: Option<String>,
    /// Endpoint for the action.
    pub endpoint: Option<String>,
    /// Estimated duration.
    pub estimated_time_minutes: Option<i32>,
}

/// Optional DNS-01 record members in the renewal challenge schema.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RenewalDnsRecordDetails {
    /// Record owner name.
    pub name: Option<String>,
    /// Record type.
    #[serde(rename = "type")]
    pub record_type: Option<String>,
    /// Record value.
    pub value: Option<String>,
}
