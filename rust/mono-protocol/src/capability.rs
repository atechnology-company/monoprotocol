use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::{DeviceId, IdentityId, ObjectId};

/// Signed grant: identity issues capabilities to a peer (device or agent).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub grant_id: String,
    pub issuer: IdentityId,
    pub subject: CapabilitySubject,
    pub object_id: ObjectId,
    pub actions: Vec<CapabilityAction>,
    pub expires_at: Option<DateTime<Utc>>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CapabilitySubject {
    Device { device_id: DeviceId },
    Agent { agent_id: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityAction {
    ReadMetadata,
    ReadPayload,
    Write,
    Replicate,
    Handoff,
    Revoke,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub grants: Vec<CapabilityGrant>,
}

impl CapabilitySet {
    pub fn allows(&self, action: CapabilityAction, object_id: &ObjectId) -> bool {
        let now = Utc::now();
        self.grants.iter().any(|g| {
            g.object_id == *object_id
                && g.actions.contains(&action)
                && g.expires_at.map(|e| e > now).unwrap_or(true)
        })
    }
}
