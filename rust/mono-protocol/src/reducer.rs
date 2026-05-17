use chrono::Utc;

use crate::content::ContentHash;
use crate::ids::{DeviceId, ObjectId};
use crate::merkle::MerkleNode;
use crate::object::{CookieJarObject, SyncObject, TabSetObject};
use crate::sync_log::{OperationKind, StateOperation, StateSnapshot, SyncJournal};
use crate::transfer::TransferClass;
use crate::version::VersionVector;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReducerError {
    #[error("operation targets wrong object")]
    WrongObject,
    #[error("unsupported mutation for this object")]
    UnsupportedMutation,
    #[error("version regression")]
    VersionRegression,
    #[error("serialization failed")]
    Serialize,
}

pub trait ObjectReducer: SyncObject {
    fn apply_operation(&mut self, op: &StateOperation) -> Result<VersionVector, ReducerError>;

    fn compact_journal(&self, journal: &SyncJournal, author_device: DeviceId) -> StateSnapshot;
}

fn transfer_class_label(class: TransferClass) -> &'static str {
    match class {
        TransferClass::PublicMetadata => "public_metadata",
        TransferClass::PrivateState => "private_state",
        TransferClass::SensitiveSession => "sensitive_session",
        TransferClass::HardwareBoundSecret => "hardware_bound_secret",
    }
}

fn assert_object(op: &StateOperation, object_id: &ObjectId) -> Result<(), ReducerError> {
    if &op.object_id != object_id {
        return Err(ReducerError::WrongObject);
    }
    Ok(())
}

fn merge_version(
    current: &VersionVector,
    after: &VersionVector,
) -> Result<VersionVector, ReducerError> {
    if current.dominates(after) && current != after {
        return Err(ReducerError::VersionRegression);
    }
    let mut merged = current.clone();
    merged.merge(after);
    Ok(merged)
}

impl ObjectReducer for TabSetObject {
    fn apply_operation(&mut self, op: &StateOperation) -> Result<VersionVector, ReducerError> {
        assert_object(op, &self.object_id)?;
        match &op.mutation {
            OperationKind::Upsert { patch_ref } => {
                self.tabs_json = format!("patch:{}", patch_ref.hex());
            }
            OperationKind::Delete => {
                self.tabs_json = "[]".into();
            }
            OperationKind::HandoffOffer { .. }
            | OperationKind::RevokeDevice { .. }
            | OperationKind::AgentAction { .. } => return Err(ReducerError::UnsupportedMutation),
        }
        self.version = merge_version(&self.version, &op.version_after)?;
        Ok(self.version.clone())
    }

    fn compact_journal(&self, journal: &SyncJournal, author_device: DeviceId) -> StateSnapshot {
        let payload = self.serialize_payload().expect("tab set payload");
        let blob_ref = ContentHash::hash(&payload);
        let parents = journal
            .latest_snapshot
            .as_ref()
            .map(|s| vec![s.merkle_root])
            .unwrap_or_default();
        let node = MerkleNode::seal(
            self.object_id.as_str(),
            transfer_class_label(self.transfer_class()),
            &payload,
            parents,
        );
        StateSnapshot {
            object_id: self.object_id.clone(),
            merkle_root: node.hash,
            version: self.version.clone(),
            blob_ref,
            created_at: Utc::now(),
            author_device,
        }
    }
}

impl ObjectReducer for CookieJarObject {
    fn apply_operation(&mut self, op: &StateOperation) -> Result<VersionVector, ReducerError> {
        assert_object(op, &self.object_id)?;
        match &op.mutation {
            OperationKind::Upsert { patch_ref } => {
                self.jar_ref = format!("patch:{}", patch_ref.hex());
            }
            OperationKind::Delete => {
                self.jar_ref.clear();
                self.cookies.clear();
            }
            OperationKind::HandoffOffer { .. }
            | OperationKind::RevokeDevice { .. }
            | OperationKind::AgentAction { .. } => return Err(ReducerError::UnsupportedMutation),
        }
        self.version = merge_version(&self.version, &op.version_after)?;
        Ok(self.version.clone())
    }

    fn compact_journal(&self, journal: &SyncJournal, author_device: DeviceId) -> StateSnapshot {
        let payload = self.serialize_payload().expect("cookie jar payload");
        let blob_ref = ContentHash::hash(&payload);
        let parents = journal
            .latest_snapshot
            .as_ref()
            .map(|s| vec![s.merkle_root])
            .unwrap_or_default();
        let node = MerkleNode::seal(
            self.object_id.as_str(),
            transfer_class_label(self.transfer_class()),
            &payload,
            parents,
        );
        StateSnapshot {
            object_id: self.object_id.clone(),
            merkle_root: node.hash,
            version: self.version.clone(),
            blob_ref,
            created_at: Utc::now(),
            author_device,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilitySet;
    use crate::cookie::CookieRecord;
    use crate::crypto::{decrypt_envelope, derive_sync_key};
    use crate::envelope::SyncEnvelope;
    use crate::ids::{IdentityId, KeyId, OperationId};
    use chrono::Duration;

    fn sample_tab(device: &DeviceId) -> TabSetObject {
        let mut tab = TabSetObject {
            object_id: ObjectId::new(),
            owner: IdentityId::new(),
            permissions: CapabilitySet::default(),
            version: VersionVector::default(),
            tabs_json: r#"[{"url":"https://example.com"}]"#.into(),
        };
        tab.version.bump(device);
        tab
    }

    fn upsert_op(
        object_id: &ObjectId,
        device: &DeviceId,
        patch_ref: ContentHash,
    ) -> StateOperation {
        let mut version_after = VersionVector::default();
        version_after.bump(device);
        StateOperation {
            op_id: OperationId::new(),
            object_id: object_id.clone(),
            parent_snapshot: None,
            mutation: OperationKind::Upsert { patch_ref },
            version_after,
            created_at: Utc::now(),
            author_device: device.clone(),
            signature: Vec::new(),
        }
    }

    #[test]
    fn tab_set_apply_operation_bumps_version() {
        let device = DeviceId::new();
        let mut tab = sample_tab(&device);
        let patch = ContentHash::hash(tab.tabs_json.as_bytes());
        let op = upsert_op(tab.object_id(), &device, patch);
        let after = tab.apply_operation(&op).unwrap();
        assert_eq!(after, op.version_after);
        assert!(tab.tabs_json.contains("patch:"));
    }

    #[test]
    fn tab_set_compact_journal_merkle_seal() {
        let device = DeviceId::new();
        let tab = sample_tab(&device);
        let journal = SyncJournal::default();
        let snap = tab.compact_journal(&journal, device.clone());
        let payload = tab.serialize_payload().unwrap();
        let node = MerkleNode::seal(
            tab.object_id.as_str(),
            "public_metadata",
            &payload,
            vec![],
        );
        assert_eq!(snap.merkle_root, node.hash);
        assert_eq!(snap.blob_ref, ContentHash::hash(&payload));
    }

    #[test]
    fn tab_set_journal_append_compact_round_trip() {
        let device = DeviceId::new();
        let mut tab = sample_tab(&device);
        let mut journal = SyncJournal::default();

        let patch_a = ContentHash::hash(b"tabs-a");
        let op_a = upsert_op(tab.object_id(), &device, patch_a);
        tab.apply_operation(&op_a).unwrap();
        journal.append_operation(op_a);

        let patch_b = ContentHash::hash(b"tabs-b");
        let op_b = upsert_op(tab.object_id(), &device, patch_b);
        tab.apply_operation(&op_b).unwrap();
        journal.append_operation(op_b);

        assert_eq!(journal.operations.len(), 2);

        let snap = tab.compact_journal(&journal, device.clone());
        assert_ne!(snap.merkle_root.0, [0u8; 32]);
        assert_eq!(snap.object_id, tab.object_id);
        assert_eq!(snap.version, tab.version);

        let payload = tab.serialize_payload().unwrap();
        let node = MerkleNode::seal(
            tab.object_id.as_str(),
            "public_metadata",
            &payload,
            vec![],
        );
        assert_eq!(snap.merkle_root, node.hash);

        journal.compact(snap.clone());
        assert_eq!(journal.latest_snapshot.as_ref().unwrap().merkle_root, snap.merkle_root);
        assert!(journal.operations.is_empty());
    }

    #[test]
    fn two_device_tab_sync_encrypt_envelope() {
        let owner = IdentityId::new();
        let key = derive_sync_key(b"device-shared-ikm", owner.as_str());
        let device_a = DeviceId::new();
        let object_id = ObjectId::new();

        let mut tab_a = TabSetObject {
            object_id: object_id.clone(),
            owner: owner.clone(),
            permissions: CapabilitySet::default(),
            version: VersionVector::default(),
            tabs_json: r#"[{"url":"https://a.com"}]"#.into(),
        };
        tab_a.version.bump(&device_a);

        let patch_ref = ContentHash::hash(tab_a.tabs_json.as_bytes());
        let op = upsert_op(&object_id, &device_a, patch_ref);
        tab_a.apply_operation(&op).unwrap();

        let mut env = SyncEnvelope::for_object(
            object_id.clone(),
            crate::object::ObjectKind::TabSet,
            owner.clone(),
            device_a.clone(),
            TransferClass::PublicMetadata,
            KeyId("key-test".into()),
            Utc::now() + Duration::hours(1),
        );
        tab_a.encrypt(&key, &mut env).unwrap();
        env.validate_meta().unwrap();

        let plain = decrypt_envelope(&env, &key).unwrap();
        let mut tab_b: TabSetObject = serde_json::from_slice(&plain).unwrap();
        tab_b.apply_operation(&op).unwrap();

        assert_eq!(tab_a.tabs_json, tab_b.tabs_json);
        assert_eq!(tab_a.version, tab_b.version);
    }

    #[test]
    fn tab_set_apply_rejects_version_regression() {
        let device_a = DeviceId::new();
        let mut tab = sample_tab(&device_a);
        let patch = ContentHash::hash(b"patch-a");
        let op_a = upsert_op(tab.object_id(), &device_a, patch);
        tab.apply_operation(&op_a).unwrap();

        let mut stale = VersionVector::default();
        stale
            .clocks
            .insert(device_a.0.clone(), tab.version.clocks[&device_a.0] - 1);
        let mut bad_op = upsert_op(tab.object_id(), &device_a, ContentHash::hash(b"patch-b"));
        bad_op.version_after = stale;
        assert_eq!(
            tab.apply_operation(&bad_op),
            Err(ReducerError::VersionRegression)
        );
    }

    #[test]
    fn cookie_jar_delete_clears_cookies() {
        let device = DeviceId::new();
        let mut jar = CookieJarObject {
            object_id: ObjectId::new(),
            owner: IdentityId::new(),
            permissions: CapabilitySet::default(),
            version: VersionVector::default(),
            jar_ref: "jar-1".into(),
            cookies: vec![CookieRecord::new("a", "b", "example.com")],
        };
        jar.version.bump(&device);
        let mut version_after = VersionVector::default();
        version_after.bump(&device);
        let op = StateOperation {
            op_id: OperationId::new(),
            object_id: jar.object_id().clone(),
            parent_snapshot: None,
            mutation: OperationKind::Delete,
            version_after,
            created_at: Utc::now(),
            author_device: device,
            signature: Vec::new(),
        };
        jar.apply_operation(&op).unwrap();
        assert!(jar.cookies.is_empty());
        assert!(jar.jar_ref.is_empty());
    }

    #[test]
    fn cookie_jar_compact_journal_seals_merkle() {
        let device = DeviceId::new();
        let jar = CookieJarObject {
            object_id: ObjectId::new(),
            owner: IdentityId::new(),
            permissions: CapabilitySet::default(),
            version: VersionVector::default(),
            jar_ref: "jar-1".into(),
            cookies: Vec::new(),
        };
        let snap = jar.compact_journal(&SyncJournal::default(), device);
        assert_ne!(snap.merkle_root.0, [0u8; 32]);
    }
}
