use std::fs;
use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{TimeZone, Utc};
use mono_protocol::{
    derive_sync_key, encrypt_object_payload_with_nonce, ContentHash, DeviceId,
    EnvelopeId, IdentityId, KeyId, ObjectId, ObjectKind, SyncEnvelope, TransferClass,
    PROTOCOL_VERSION,
};
use serde::Serialize;
use serde_json::json;

fn conformance_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../conformance")
}

#[derive(Serialize)]
struct GoldenFile {
    protocol_version: &'static str,
    vectors: Vec<serde_json::Value>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = conformance_root();
    fs::create_dir_all(root.join("golden"))?;
    fs::create_dir_all(root.join("json"))?;
    fs::create_dir_all(root.join("cbor"))?;

    let ikm_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    let ikm = hex::decode(ikm_hex)?;
    let identity_id = "018f3e8e-7b3c-7000-8000-000000000001";
    let key = derive_sync_key(&ikm, identity_id);
    let nonce_hex = "000102030405060708090a0b";
    let nonce_bytes: [u8; 12] = hex::decode(nonce_hex)?.try_into().unwrap();
    let plaintext = br#"{"tabs":[]}"#;
    let mut env = fixture_envelope_private_state();
    encrypt_object_payload_with_nonce(&mut env, &key, plaintext, nonce_bytes)?;

    let golden = GoldenFile {
        protocol_version: PROTOCOL_VERSION,
        vectors: vec![
            json!({
                "id": "hkdf_derive_sync_key_v1",
                "ikm_hex": ikm_hex,
                "identity_id": identity_id,
                "salt": format!("mono-identity-{identity_id}"),
                "info": "mono-sync-key-v1",
                "expected_sync_key_hex": hex::encode(key),
            }),
            json!({
                "id": "aes_gcm_private_state_tab_set_payload",
                "ikm_hex": ikm_hex,
                "identity_id": identity_id,
                "plaintext_utf8": "{\"tabs\":[]}",
                "nonce_hex": nonce_hex,
                "expected_nonce_b64": env.nonce,
                "expected_ciphertext_b64": env.ciphertext,
                "expected_tag_b64": env.tag,
                "expected_content_hash_hex": ContentHash::hash(plaintext).hex(),
            }),
        ],
    };
    fs::write(
        root.join("golden/crypto.json"),
        serde_json::to_string_pretty(&golden)?,
    )?;

    let public_env = fixture_envelope_public_metadata();
    write_json_fixture(&root, "envelope_public_metadata", &public_env)?;
    write_json_fixture(&root, "envelope_private_state_encrypted", &env)?;

    let policy_matrix = json!({
        "protocol_version": PROTOCOL_VERSION,
        "transfer_classes": [
            {
                "class": "public_metadata",
                "encryption_required": false,
                "twofa_required_to_apply": false,
                "relay_may_store_ciphertext": true,
                "gossip_allowed": true,
                "p2p_preferred": true,
                "revocation_invalidates": true,
                "agent_may_read_metadata": true,
                "agent_may_read_payload": true
            },
            {
                "class": "private_state",
                "encryption_required": true,
                "twofa_required_to_apply": false,
                "relay_may_store_ciphertext": true,
                "gossip_allowed": true,
                "p2p_preferred": true,
                "revocation_invalidates": true,
                "agent_may_read_metadata": true,
                "agent_may_read_payload": false
            },
            {
                "class": "sensitive_session",
                "encryption_required": true,
                "twofa_required_to_apply": true,
                "relay_may_store_ciphertext": true,
                "gossip_allowed": true,
                "p2p_preferred": true,
                "revocation_invalidates": true,
                "agent_may_read_metadata": true,
                "agent_may_read_payload": false
            },
            {
                "class": "hardware_bound_secret",
                "encryption_required": true,
                "twofa_required_to_apply": true,
                "relay_may_store_ciphertext": false,
                "gossip_allowed": false,
                "p2p_preferred": false,
                "revocation_invalidates": true,
                "agent_may_read_metadata": false,
                "agent_may_read_payload": false
            }
        ]
    });
    fs::write(
        root.join("json/transfer_policy_matrix.json"),
        serde_json::to_string_pretty(&policy_matrix)?,
    )?;

    println!("wrote fixtures under {}", root.display());
    Ok(())
}

fn write_json_fixture(
    root: &PathBuf,
    name: &str,
    envelope: &SyncEnvelope,
) -> Result<(), Box<dyn std::error::Error>> {
    let json_path = root.join(format!("json/{name}.json"));
    fs::write(&json_path, serde_json::to_string_pretty(envelope)?)?;
    let mut cbor_bytes: Vec<u8> = Vec::new();
    ciborium::ser::into_writer(envelope, &mut cbor_bytes)?;
    fs::write(root.join(format!("cbor/{name}.cbor")), &cbor_bytes)?;
    let manifest = json!({
        "protocol_version": PROTOCOL_VERSION,
        "fixture": name,
        "json": format!("json/{name}.json"),
        "cbor": format!("cbor/{name}.cbor"),
        "cbor_hex": hex::encode(&cbor_bytes),
    });
    fs::write(
        root.join(format!("cbor/{name}.manifest.json")),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    Ok(())
}

fn fixture_envelope_public_metadata() -> SyncEnvelope {
    let created = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
    let expires = Utc.with_ymd_and_hms(2026, 1, 16, 12, 0, 0).unwrap();
    let plain = br#"{"tabs":[{"url":"https://example.com","title":"Example"}]}"#;
    SyncEnvelope {
        version: PROTOCOL_VERSION.to_string(),
        envelope_id: EnvelopeId("018f3e8e-7b3c-7000-8000-000000000010".into()),
        object_id: ObjectId("018f3e8e-7b3c-7000-8000-000000000020".into()),
        object_kind: ObjectKind::TabSet,
        owner: IdentityId("018f3e8e-7b3c-7000-8000-000000000001".into()),
        source_device_id: DeviceId("018f3e8e-7b3c-7000-8000-000000000030".into()),
        transfer_class: TransferClass::PublicMetadata,
        created_at: created,
        expires_at: expires,
        key_id: KeyId("key-conformance-0".into()),
        nonce: String::new(),
        ciphertext: STANDARD.encode(plain),
        tag: String::new(),
        content_hash: Some(ContentHash::hash(plain).hex()),
        merkle_anchor: None,
        twofa_proof: None,
    }
}

fn fixture_envelope_private_state() -> SyncEnvelope {
    let created = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
    let expires = Utc.with_ymd_and_hms(2026, 1, 16, 12, 0, 0).unwrap();
    SyncEnvelope {
        version: PROTOCOL_VERSION.to_string(),
        envelope_id: EnvelopeId("018f3e8e-7b3c-7000-8000-000000000011".into()),
        object_id: ObjectId("018f3e8e-7b3c-7000-8000-000000000021".into()),
        object_kind: ObjectKind::TabSet,
        owner: IdentityId("018f3e8e-7b3c-7000-8000-000000000001".into()),
        source_device_id: DeviceId("018f3e8e-7b3c-7000-8000-000000000030".into()),
        transfer_class: TransferClass::PrivateState,
        created_at: created,
        expires_at: expires,
        key_id: KeyId("key-conformance-1".into()),
        nonce: String::new(),
        ciphertext: String::new(),
        tag: String::new(),
        content_hash: None,
        merkle_anchor: None,
        twofa_proof: None,
    }
}
