use serde::{de::DeserializeOwned, Serialize};

use crate::capability::CapabilitySet;
use crate::cookie::CookieRecord;
use crate::envelope::SyncEnvelope;
use crate::ids::{IdentityId, ObjectId};
use crate::ownership::StateResidency;
use crate::transfer::TransferClass;
use crate::version::VersionVector;
use crate::crypto::{encrypt_object_payload, SyncCryptoError};

/// Every replicated entity (tabs, cookies, clipboard, agent tasks, …) implements this.
pub trait SyncObject: Serialize + DeserializeOwned {
    fn object_kind(&self) -> ObjectKind;

    fn object_id(&self) -> &ObjectId;

    fn owner(&self) -> &IdentityId;

    fn permissions(&self) -> &CapabilitySet;

    fn version(&self) -> &VersionVector;

    fn transfer_class(&self) -> TransferClass;

    fn preferred_residency(&self) -> StateResidency;

    fn serialize_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    fn encrypt(&self, key: &[u8; 32], envelope: &mut SyncEnvelope) -> Result<(), SyncCryptoError> {
        let policy = self.transfer_class().policy();
        let plain = self.serialize_payload().map_err(|_| SyncCryptoError::Encrypt)?;
        if policy.encryption_required {
            encrypt_object_payload(envelope, key, &plain)
        } else {
            envelope.ciphertext = base64_payload(&plain);
            envelope.tag.clear();
            envelope.nonce.clear();
            envelope.content_hash = Some(crate::content::ContentHash::hash(&plain).hex());
            Ok(())
        }
    }
}

fn base64_payload(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    TabSet,
    BrowserSession,
    CookieJar,
    ClipboardEntry,
    FileBlob,
    HistorySegment,
    PermissionGrant,
    AgentTask,
    HandoffIntent,
    AuditSegment,
}

impl ObjectKind {
    pub fn default_transfer_class(self) -> TransferClass {
        match self {
            Self::TabSet | Self::HistorySegment | Self::HandoffIntent => TransferClass::PublicMetadata,
            Self::BrowserSession | Self::ClipboardEntry | Self::FileBlob | Self::AgentTask => {
                TransferClass::PrivateState
            }
            Self::CookieJar | Self::PermissionGrant => TransferClass::SensitiveSession,
            Self::AuditSegment => TransferClass::PublicMetadata,
        }
    }
}

/// Example concrete object: open tabs for a profile.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TabSetObject {
    pub object_id: ObjectId,
    pub owner: IdentityId,
    pub permissions: CapabilitySet,
    pub version: VersionVector,
    pub tabs_json: String,
}

impl SyncObject for TabSetObject {
    fn object_kind(&self) -> ObjectKind {
        ObjectKind::TabSet
    }

    fn object_id(&self) -> &ObjectId {
        &self.object_id
    }

    fn owner(&self) -> &IdentityId {
        &self.owner
    }

    fn permissions(&self) -> &CapabilitySet {
        &self.permissions
    }

    fn version(&self) -> &VersionVector {
        &self.version
    }

    fn transfer_class(&self) -> TransferClass {
        ObjectKind::TabSet.default_transfer_class()
    }

    fn preferred_residency(&self) -> StateResidency {
        StateResidency::BrowserProfile
    }
}

/// Cookie jar segment — sensitive session tier by default.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CookieJarObject {
    pub object_id: ObjectId,
    pub owner: IdentityId,
    pub permissions: CapabilitySet,
    pub version: VersionVector,
    pub jar_ref: String,
    #[serde(default)]
    pub cookies: Vec<CookieRecord>,
}

impl SyncObject for CookieJarObject {
    fn object_kind(&self) -> ObjectKind {
        ObjectKind::CookieJar
    }

    fn object_id(&self) -> &ObjectId {
        &self.object_id
    }

    fn owner(&self) -> &IdentityId {
        &self.owner
    }

    fn permissions(&self) -> &CapabilitySet {
        &self.permissions
    }

    fn version(&self) -> &VersionVector {
        &self.version
    }

    fn transfer_class(&self) -> TransferClass {
        TransferClass::SensitiveSession
    }

    fn preferred_residency(&self) -> StateResidency {
        StateResidency::Cupboard
    }
}
