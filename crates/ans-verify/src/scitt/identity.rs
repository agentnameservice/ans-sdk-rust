//! Agreement between a signed receipt event and a verified status token.

use ans_types::StatusTokenPayload;
use serde::Deserialize;
use uuid::Uuid;

use super::{ScittError, VerifiedReceipt};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ReceiptLeaf {
    Envelope { payload: EnvelopePayload },
    Event(LeafIdentity),
}

#[derive(Debug, Deserialize)]
struct EnvelopePayload {
    producer: Producer,
}

#[derive(Debug, Deserialize)]
struct Producer {
    event: LeafIdentity,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LeafIdentity {
    ans_name: String,
    ans_id: Option<Uuid>,
    agent: Option<Agent>,
}

#[derive(Debug, Deserialize)]
struct Agent {
    host: String,
}

/// ANS-6 §§5.2, 6.3, 7.5: signatures alone do not bind two artifacts to
/// the same registration. Method A also binds the event's host to the
/// connection; Method B deliberately uses only the name/id agreement.
pub fn bind_receipt_to_status(
    receipt: &VerifiedReceipt,
    status: &StatusTokenPayload,
    expected_host: Option<&str>,
) -> Result<(), ScittError> {
    bind_receipt_to_peer(
        receipt,
        &status.ans_name.to_string(),
        status.agent_id,
        expected_host,
    )
}

pub fn bind_status_to_badge(
    status: &StatusTokenPayload,
    badge: &ans_types::Badge,
) -> Result<(), ScittError> {
    if status.agent_id != badge.agent_id()
        || !status
            .ans_name
            .to_string()
            .eq_ignore_ascii_case(badge.agent_name())
    {
        return Err(ScittError::IdentityBinding(
            "status token does not match the badge registration".into(),
        ));
    }
    Ok(())
}

pub fn bind_receipt_to_badge(
    receipt: &VerifiedReceipt,
    badge: &ans_types::Badge,
    expected_host: Option<&str>,
) -> Result<(), ScittError> {
    bind_receipt_to_peer(receipt, badge.agent_name(), badge.agent_id(), expected_host)
}

fn bind_receipt_to_peer(
    receipt: &VerifiedReceipt,
    ans_name: &str,
    agent_id: Uuid,
    expected_host: Option<&str>,
) -> Result<(), ScittError> {
    let leaf: ReceiptLeaf = serde_json::from_slice(&receipt.event_bytes)
        .map_err(|e| ScittError::InvalidReceiptIdentity(e.to_string()))?;
    let identity = match leaf {
        ReceiptLeaf::Envelope { payload } => payload.producer.event,
        ReceiptLeaf::Event(identity) => identity,
    };
    if !identity.ans_name.eq_ignore_ascii_case(ans_name) {
        return Err(ScittError::IdentityBinding(
            "receipt ansName does not match the live registration ansName".into(),
        ));
    }
    if identity.ans_id.is_some_and(|id| id != agent_id) {
        return Err(ScittError::IdentityBinding(
            "receipt ansId does not match the live registration agentId".into(),
        ));
    }
    if let Some(expected) = expected_host {
        let agent = identity.agent.ok_or_else(|| {
            ScittError::InvalidReceiptIdentity("receipt event has no agent.host".into())
        })?;
        if !agent.host.eq_ignore_ascii_case(expected) {
            return Err(ScittError::IdentityBinding(
                "receipt agent.host does not match the connection host".into(),
            ));
        }
    }
    Ok(())
}
