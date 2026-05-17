use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::content::ContentHash;
use crate::ids::{DeviceId, ObjectId, OperationId};
use crate::version::VersionVector;

/// Periodic full-ish checkpoint (git-like snapshot).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub object_id: ObjectId,
    pub merkle_root: ContentHash,
    pub version: VersionVector,
    pub blob_ref: ContentHash,
    pub created_at: DateTime<Utc>,
    pub author_device: DeviceId,
}

/// Intent-based mutation between snapshots.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateOperation {
    pub op_id: OperationId,
    pub object_id: ObjectId,
    pub parent_snapshot: Option<ContentHash>,
    pub mutation: OperationKind,
    pub version_after: VersionVector,
    pub created_at: DateTime<Utc>,
    pub author_device: DeviceId,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OperationKind {
    Upsert { patch_ref: ContentHash },
    Delete,
    HandoffOffer { target_device: DeviceId },
    RevokeDevice { device_id: DeviceId },
    AgentAction { action_type: String, audit_ref: ContentHash },
}

/// Operations + snapshots: replay ops since last snapshot, then compact.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SyncJournal {
    pub latest_snapshot: Option<StateSnapshot>,
    pub operations: Vec<StateOperation>,
}

impl SyncJournal {
    pub fn append_operation(&mut self, op: StateOperation) {
        self.operations.push(op);
    }

    pub fn compact(&mut self, snapshot: StateSnapshot) {
        self.latest_snapshot = Some(snapshot);
        self.operations.clear();
    }
}
