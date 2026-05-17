use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::envelope::SyncEnvelope;

const SYNC_KEY_INFO: &[u8] = b"mono-sync-key-v1";

#[derive(Debug, thiserror::Error)]
pub enum SyncCryptoError {
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error("invalid base64")]
    Base64,
}

pub fn derive_sync_key(ikm: &[u8], identity_id: &str) -> [u8; 32] {
    let salt = format!("mono-identity-{identity_id}");
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), ikm);
    let mut okm = [0u8; 32];
    hk.expand(SYNC_KEY_INFO, &mut okm)
        .expect("32 bytes is a valid HKDF length");
    okm
}

pub fn encrypt_object_payload(
    envelope: &mut SyncEnvelope,
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<(), SyncCryptoError> {
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    encrypt_object_payload_with_nonce(envelope, key, plaintext, nonce_bytes)
}

/// Deterministic encryption for conformance vectors (`spec/CONFORMANCE.md`).
pub fn encrypt_object_payload_with_nonce(
    envelope: &mut SyncEnvelope,
    key: &[u8; 32],
    plaintext: &[u8],
    nonce_bytes: [u8; 12],
) -> Result<(), SyncCryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SyncCryptoError::Encrypt)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let combined = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_| SyncCryptoError::Encrypt)?;
    if combined.len() < 16 {
        return Err(SyncCryptoError::Encrypt);
    }
    let (ct, tag) = combined.split_at(combined.len() - 16);
    envelope.nonce = STANDARD.encode(nonce_bytes);
    envelope.ciphertext = STANDARD.encode(ct);
    envelope.tag = STANDARD.encode(tag);
    envelope.content_hash = Some(crate::content::ContentHash::hash(plaintext).hex());
    Ok(())
}

pub fn decrypt_envelope(envelope: &SyncEnvelope, key: &[u8; 32]) -> Result<Vec<u8>, SyncCryptoError> {
    if envelope.nonce.is_empty() && envelope.tag.is_empty() {
        return STANDARD
            .decode(&envelope.ciphertext)
            .map_err(|_| SyncCryptoError::Base64);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SyncCryptoError::Decrypt)?;
    let nonce_bytes = STANDARD.decode(&envelope.nonce).map_err(|_| SyncCryptoError::Base64)?;
    if nonce_bytes.len() != 12 {
        return Err(SyncCryptoError::Decrypt);
    }
    let mut combined = STANDARD
        .decode(&envelope.ciphertext)
        .map_err(|_| SyncCryptoError::Base64)?;
    combined.extend(STANDARD.decode(&envelope.tag).map_err(|_| SyncCryptoError::Base64)?);
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|_| SyncCryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::SyncEnvelope;
    use crate::ids::*;
    use crate::object::ObjectKind;
    use crate::transfer::TransferClass;
    use chrono::Duration;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let owner = IdentityId::new();
        let key = derive_sync_key(b"test-ikm", owner.as_str());
        let mut env = SyncEnvelope::for_object(
            ObjectId::new(),
            ObjectKind::TabSet,
            owner,
            DeviceId::new(),
            TransferClass::PrivateState,
            KeyId("key-test".into()),
            chrono::Utc::now() + Duration::hours(1),
        );
        let plain = br#"{"tabs":[]}"#;
        encrypt_object_payload(&mut env, &key, plain).unwrap();
        let out = decrypt_envelope(&env, &key).unwrap();
        assert_eq!(out, plain);
    }
}
