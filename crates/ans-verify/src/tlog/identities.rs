//! Optional identity TL reads without changing existing custom log adapters.

use super::HttpTransparencyLogClient;
use crate::TlogError;
use ans_types::{
    IdentityAuditResponse, IdentityBadge, LinkedAgentsResponse, LinkedIdentitiesResponse,
};
use async_trait::async_trait;
use uuid::Uuid;

#[cfg(any(test, feature = "test-support"))]
mod mock;
#[cfg(any(test, feature = "test-support"))]
pub use mock::MockIdentityLogClient;

/// The identity-facing public TL API; independent of the agent-only adapter.
#[async_trait]
pub trait IdentityLogClient: Send + Sync {
    /// Current identity badge and its proof-event pointer.
    async fn fetch_identity_badge(&self, identity_id: Uuid) -> Result<IdentityBadge, TlogError>;
    /// Newest-first identity audit page (limit 1–200).
    async fn fetch_identity_audit(
        &self,
        identity_id: Uuid,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<IdentityAuditResponse, TlogError>;
    /// Raw COSE receipt for the latest identity event.
    async fn fetch_identity_receipt(&self, identity_id: Uuid) -> Result<Vec<u8>, TlogError>;
    /// Currently linked live agents (reverse join).
    async fn fetch_identity_agents(
        &self,
        identity_id: Uuid,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<LinkedAgentsResponse, TlogError>;
    /// Current identity associations of an agent, including revoked identities.
    async fn fetch_agent_identities(
        &self,
        agent_id: Uuid,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<LinkedIdentitiesResponse, TlogError>;
    /// Historical link/unlink records naming an agent.
    async fn fetch_agent_identity_history(
        &self,
        agent_id: Uuid,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<IdentityAuditResponse, TlogError>;
}

impl HttpTransparencyLogClient {
    async fn identity_bytes(
        &self,
        path: &str,
        limit: Option<u32>,
        offset: Option<u32>,
        receipt: bool,
    ) -> Result<Vec<u8>, TlogError> {
        const MAX_BYTES: usize = 2 * 1024 * 1024;
        if limit.is_some_and(|n| !(1..=200).contains(&n)) {
            return Err(TlogError::InvalidUrl(
                "TL page limit must be between 1 and 200".into(),
            ));
        }
        let base = self.base_url.as_ref().ok_or_else(|| {
            TlogError::InvalidUrl("identity reads require a configured TL base URL".into())
        })?;
        let url = base
            .join(path)
            .map_err(|e| TlogError::InvalidUrl(e.to_string()))?;
        let mut query = Vec::new();
        if let Some(n) = limit {
            query.push(("limit", n));
        }
        if let Some(n) = offset {
            query.push(("offset", n));
        }
        let mut response = self
            .client
            .get(url.as_str())
            .headers(self.build_headers()?)
            .header(
                reqwest::header::USER_AGENT,
                concat!("ans-verify/", env!("CARGO_PKG_VERSION")),
            )
            .header(
                reqwest::header::ACCEPT,
                if receipt {
                    "application/scitt-receipt+cose"
                } else {
                    "application/json"
                },
            )
            .query(&query)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(crate::HttpError::from)?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(TlogError::NotFound {
                url: url.to_string(),
            });
        }
        if receipt && status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
            let retry_after_seconds = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok());
            return Err(TlogError::CheckpointPending {
                retry_after_seconds,
            });
        }
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(TlogError::ServiceUnavailable);
        }
        if !status.is_success() {
            return Err(TlogError::InvalidResponse(format!(
                "Unexpected status code: {status}"
            )));
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_BYTES as u64)
        {
            return Err(TlogError::InvalidResponse(
                "identity response exceeds 2 MiB".into(),
            ));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(crate::HttpError::from)? {
            if chunk.len() > MAX_BYTES - bytes.len() {
                return Err(TlogError::InvalidResponse(
                    "identity response exceeds 2 MiB".into(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    async fn identity_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<T, TlogError> {
        let bytes = self.identity_bytes(path, limit, offset, false).await?;
        serde_json::from_slice(&bytes).map_err(|e| TlogError::InvalidResponse(e.to_string()))
    }
}

#[async_trait]
impl IdentityLogClient for HttpTransparencyLogClient {
    async fn fetch_identity_badge(&self, id: Uuid) -> Result<IdentityBadge, TlogError> {
        self.identity_json(&format!("v1/identities/{id}"), None, None)
            .await
    }
    async fn fetch_identity_audit(
        &self,
        id: Uuid,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<IdentityAuditResponse, TlogError> {
        self.identity_json(&format!("v1/identities/{id}/audit"), limit, offset)
            .await
    }
    async fn fetch_identity_receipt(&self, id: Uuid) -> Result<Vec<u8>, TlogError> {
        self.identity_bytes(&format!("v1/identities/{id}/receipt"), None, None, true)
            .await
    }
    async fn fetch_identity_agents(
        &self,
        id: Uuid,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<LinkedAgentsResponse, TlogError> {
        self.identity_json(&format!("v1/identities/{id}/agents"), limit, offset)
            .await
    }
    async fn fetch_agent_identities(
        &self,
        id: Uuid,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<LinkedIdentitiesResponse, TlogError> {
        self.identity_json(&format!("v1/agents/{id}/identities"), limit, offset)
            .await
    }
    async fn fetch_agent_identity_history(
        &self,
        id: Uuid,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<IdentityAuditResponse, TlogError> {
        self.identity_json(&format!("v1/agents/{id}/identities/history"), limit, offset)
            .await
    }
}

#[cfg(test)]
mod tests;
