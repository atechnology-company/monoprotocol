//! Mono sync protocol — reference types and crypto (non-normative).
//!
//! The canonical specification is the Markdown under `spec/` in this repository.

pub mod capability;
pub mod content;
pub mod cookie;
pub mod crypto;
pub mod envelope;
pub mod ids;
pub mod merkle;
pub mod object;
pub mod ownership;
pub mod reducer;
pub mod sync_log;
pub mod transfer;
pub mod twofa;
pub mod version;
pub mod webauthn;

pub use capability::{CapabilityAction, CapabilityGrant, CapabilitySet, CapabilitySubject};
pub use content::ContentHash;
pub use cookie::{CookieRecord, SameSite};
pub use crypto::{
    decrypt_envelope, derive_sync_key, encrypt_object_payload, encrypt_object_payload_with_nonce,
    SyncCryptoError,
};
pub use envelope::{EnvelopeError, SyncEnvelope, TwoFaMethod, TwoFaProof};
pub use ids::{
    AccountId, DeviceId, EnvelopeId, IdentityId, KeyId, ObjectId, OperationId, ProfileId,
};
pub use merkle::{MerkleNode, MerkleProof};
pub use object::{CookieJarObject, ObjectKind, SyncObject, TabSetObject};
pub use ownership::{StateOwner, StateResidency};
pub use reducer::{ObjectReducer, ReducerError};
pub use sync_log::{OperationKind, StateOperation, StateSnapshot, SyncJournal};
pub use transfer::{TransferClass, TransferPolicy};
pub use twofa::{verify_twofa_proof, verify_twofa_proof_with_registry, TwoFaError};
pub use webauthn::{begin_challenge, StoredPasskey, WebAuthnRegistry};
pub use version::VersionVector;

pub const PROTOCOL_VERSION: &str = "mono-sync/0.2.0-draft";
