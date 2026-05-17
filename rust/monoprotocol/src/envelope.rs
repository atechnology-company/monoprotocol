use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::{DeviceId, EnvelopeId, IdentityId, KeyId, ObjectId};
use crate::object::ObjectKind;
use crate::transfer::TransferClass;
use crate::PROTOCOL_VERSION;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TwoFaMethod {
    /// Platform passkeys (iCloud Keychain, Android passkeys, FIDO2 security keys).
    WebAuthn,
    /// Six-digit TOTP (authenticator apps).
    Totp,
    /// SMS one-time code (six digits).
    Sms,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TwoFaProof {
    pub method: TwoFaMethod,
    pub assertion: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
}

/// Wire envelope for any replicated object payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncEnvelope {
    pub version: String,
    pub envelope_id: EnvelopeId,
    pub object_id: ObjectId,
    pub object_kind: ObjectKind,
    pub owner: IdentityId,
    pub source_device_id: DeviceId,
    pub transfer_class: TransferClass,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub key_id: KeyId,
    pub nonce: String,
    pub ciphertext: String,
    pub tag: String,
    pub content_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_anchor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub twofa_proof: Option<TwoFaProof>,
}

impl SyncEnvelope {
    pub fn for_object(
        object_id: ObjectId,
        object_kind: ObjectKind,
        owner: IdentityId,
        source_device_id: DeviceId,
        transfer_class: TransferClass,
        key_id: KeyId,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION.to_string(),
            envelope_id: EnvelopeId::new(),
            object_id,
            object_kind,
            owner,
            source_device_id,
            transfer_class,
            created_at: Utc::now(),
            expires_at,
            key_id,
            nonce: String::new(),
            ciphertext: String::new(),
            tag: String::new(),
            content_hash: None,
            merkle_anchor: None,
            twofa_proof: None,
        }
    }

    pub fn validate_meta(&self) -> Result<(), EnvelopeError> {
        self.validate_meta_at(Utc::now())
    }

    pub fn validate_meta_at(&self, now: DateTime<Utc>) -> Result<(), EnvelopeError> {
        if self.version != PROTOCOL_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(self.version.clone()));
        }
        if self.created_at >= self.expires_at {
            return Err(EnvelopeError::InvalidLifetime);
        }
        if now > self.expires_at {
            return Err(EnvelopeError::Expired);
        }
        let policy = self.transfer_class.policy();
        if policy.twofa_required_to_apply {
            match &self.twofa_proof {
                None => return Err(EnvelopeError::MissingTwoFa),
                Some(proof) => crate::twofa::verify_twofa_proof(proof).map_err(|_| {
                    EnvelopeError::InvalidTwoFa
                })?,
            }
        }
        if policy.encryption_required {
            if self.nonce.is_empty() || self.tag.is_empty() || self.ciphertext.is_empty() {
                return Err(EnvelopeError::MissingEncryption);
            }
            let nonce_len = base64::engine::general_purpose::STANDARD
                .decode(self.nonce.as_bytes())
                .map_err(|_| EnvelopeError::InvalidEncryption)?
                .len();
            if nonce_len != 12 {
                return Err(EnvelopeError::InvalidEncryption);
            }
        } else if !self.nonce.is_empty() || !self.tag.is_empty() {
            return Err(EnvelopeError::UnexpectedEncryption);
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(String),
    #[error("transfer policy requires 2FA proof")]
    MissingTwoFa,
    #[error("2FA proof failed verification")]
    InvalidTwoFa,
    #[error("envelope expired")]
    Expired,
    #[error("created_at must be before expires_at")]
    InvalidLifetime,
    #[error("transfer policy requires encrypted payload fields")]
    MissingEncryption,
    #[error("invalid encrypted payload fields")]
    InvalidEncryption,
    #[error("public metadata must not carry nonce or tag")]
    UnexpectedEncryption,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn sensitive_session_rejects_missing_twofa() {
        let env = SyncEnvelope::for_object(
            crate::ids::ObjectId::new(),
            crate::object::ObjectKind::CookieJar,
            crate::ids::IdentityId::new(),
            crate::ids::DeviceId::new(),
            TransferClass::SensitiveSession,
            crate::ids::KeyId::new(),
            Utc::now() + Duration::hours(1),
        );
        assert_eq!(env.validate_meta(), Err(EnvelopeError::MissingTwoFa));
    }

    #[test]
    fn public_metadata_rejects_nonce_and_tag() {
        let mut env = SyncEnvelope::for_object(
            crate::ids::ObjectId::new(),
            crate::object::ObjectKind::TabSet,
            crate::ids::IdentityId::new(),
            crate::ids::DeviceId::new(),
            TransferClass::PublicMetadata,
            crate::ids::KeyId::new(),
            Utc::now() + Duration::hours(1),
        );
        env.nonce = "AAEC".into();
        assert_eq!(
            env.validate_meta_at(Utc::now()),
            Err(EnvelopeError::UnexpectedEncryption)
        );
    }

    #[test]
    fn private_state_requires_encryption_fields() {
        let env = SyncEnvelope::for_object(
            crate::ids::ObjectId::new(),
            crate::object::ObjectKind::TabSet,
            crate::ids::IdentityId::new(),
            crate::ids::DeviceId::new(),
            TransferClass::PrivateState,
            crate::ids::KeyId::new(),
            Utc::now() + Duration::hours(1),
        );
        assert_eq!(
            env.validate_meta_at(Utc::now()),
            Err(EnvelopeError::MissingEncryption)
        );
    }

    #[test]
    fn sensitive_session_rejects_short_twofa_assertion() {
        let mut env = SyncEnvelope::for_object(
            crate::ids::ObjectId::new(),
            crate::object::ObjectKind::CookieJar,
            crate::ids::IdentityId::new(),
            crate::ids::DeviceId::new(),
            TransferClass::SensitiveSession,
            crate::ids::KeyId::new(),
            Utc::now() + Duration::hours(1),
        );
        env.twofa_proof = Some(TwoFaProof {
            method: TwoFaMethod::Totp,
            assertion: "x".into(),
            credential_id: None,
        });
        assert_eq!(env.validate_meta(), Err(EnvelopeError::InvalidTwoFa));
    }
}
