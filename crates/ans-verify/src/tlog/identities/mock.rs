//! In-memory identity log responses for tests and examples.
use super::{
    IdentityAuditResponse, IdentityBadge, IdentityLogClient, LinkedAgentsResponse,
    LinkedIdentitiesResponse, TlogError, Uuid, async_trait,
};
use std::collections::HashMap;

/// Fixture-backed implementation of all identity log reads.
/// Audit and history fixtures use the API's newest-first ordering.
#[derive(Debug, Default)]
pub struct MockIdentityLogClient {
    badges: HashMap<Uuid, IdentityBadge>,
    audits: HashMap<Uuid, IdentityAuditResponse>,
    receipts: HashMap<Uuid, Vec<u8>>,
    agents: HashMap<Uuid, LinkedAgentsResponse>,
    identities: HashMap<Uuid, LinkedIdentitiesResponse>,
    histories: HashMap<Uuid, IdentityAuditResponse>,
}
impl MockIdentityLogClient {
    /// Create an empty log; unconfigured reads return `TlogError::NotFound`.
    pub fn new() -> Self {
        Self::default()
    }
    /// Configure the current badge for an identity.
    pub fn with_badge(mut self, id: Uuid, badge: IdentityBadge) -> Self {
        self.badges.insert(id, badge);
        self
    }
    /// Configure the complete newest-first identity audit.
    pub fn with_audit(mut self, id: Uuid, audit: IdentityAuditResponse) -> Self {
        self.audits.insert(id, audit);
        self
    }
    /// Configure a COSE identity receipt.
    pub fn with_receipt(mut self, id: Uuid, receipt: Vec<u8>) -> Self {
        self.receipts.insert(id, receipt);
        self
    }
    /// Configure the reverse agent join.
    pub fn with_agents(mut self, id: Uuid, agents: LinkedAgentsResponse) -> Self {
        self.agents.insert(id, agents);
        self
    }
    /// Configure an agent's identity join.
    pub fn with_agent_identities(mut self, id: Uuid, identities: LinkedIdentitiesResponse) -> Self {
        self.identities.insert(id, identities);
        self
    }
    /// Configure the complete newest-first identity history for an agent.
    pub fn with_agent_history(mut self, id: Uuid, history: IdentityAuditResponse) -> Self {
        self.histories.insert(id, history);
        self
    }
}

fn response<T: Clone>(responses: &HashMap<Uuid, T>, id: Uuid) -> Result<T, TlogError> {
    responses
        .get(&id)
        .cloned()
        .ok_or_else(|| TlogError::NotFound {
            url: id.to_string(),
        })
}
fn page<T>(items: Vec<T>, limit: Option<u32>, offset: Option<u32>) -> Result<Vec<T>, TlogError> {
    let limit = limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return Err(TlogError::InvalidUrl(
            "TL page limit must be between 1 and 200".into(),
        ));
    }
    Ok(items
        .into_iter()
        .skip(offset.unwrap_or(0) as usize)
        .take(limit as usize)
        .collect())
}
#[async_trait]
impl IdentityLogClient for MockIdentityLogClient {
    async fn fetch_identity_badge(&self, id: Uuid) -> Result<IdentityBadge, TlogError> {
        response(&self.badges, id)
    }
    async fn fetch_identity_receipt(&self, id: Uuid) -> Result<Vec<u8>, TlogError> {
        response(&self.receipts, id)
    }
    async fn fetch_identity_audit(
        &self,
        id: Uuid,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<IdentityAuditResponse, TlogError> {
        let mut result = response(&self.audits, id)?;
        result.records = page(result.records, limit, offset)?;
        Ok(result)
    }
    async fn fetch_identity_agents(
        &self,
        id: Uuid,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<LinkedAgentsResponse, TlogError> {
        let mut result = response(&self.agents, id)?;
        result.agents = page(result.agents, limit, offset)?;
        Ok(result)
    }
    async fn fetch_agent_identities(
        &self,
        id: Uuid,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<LinkedIdentitiesResponse, TlogError> {
        let mut result = response(&self.identities, id)?;
        result.identities = page(result.identities, limit, offset)?;
        Ok(result)
    }
    async fn fetch_agent_identity_history(
        &self,
        id: Uuid,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<IdentityAuditResponse, TlogError> {
        let mut result = response(&self.histories, id)?;
        result.records = page(result.records, limit, offset)?;
        Ok(result)
    }
}
