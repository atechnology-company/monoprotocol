use std::fs;
use std::path::PathBuf;

use chrono::{TimeZone, Utc};
use monoprotocol::{
    decrypt_envelope, derive_sync_key, encrypt_object_payload_with_nonce, SyncEnvelope,
    TransferClass, TransferPolicy, PROTOCOL_VERSION,
};
use serde::Deserialize;

fn conformance_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

#[derive(Deserialize)]
struct GoldenFile {
    protocol_version: String,
    vectors: Vec<serde_json::Value>,
}

#[test]
fn golden_crypto_vectors() {
    let path = conformance_root().join("golden/crypto.json");
    let golden: GoldenFile =
        serde_json::from_str(&fs::read_to_string(&path).expect("golden/crypto.json"))
            .expect("parse golden");
    assert_eq!(golden.protocol_version, PROTOCOL_VERSION);

    for vector in &golden.vectors {
        let id = vector["id"].as_str().expect("vector id");
        match id {
            "hkdf_derive_sync_key_v1" => {
                let ikm = hex::decode(vector["ikm_hex"].as_str().unwrap()).unwrap();
                let identity_id = vector["identity_id"].as_str().unwrap();
                let key = derive_sync_key(&ikm, identity_id);
                assert_eq!(
                    hex::encode(key),
                    vector["expected_sync_key_hex"].as_str().unwrap()
                );
            }
            "aes_gcm_private_state_tab_set_payload" => {
                let ikm = hex::decode(vector["ikm_hex"].as_str().unwrap()).unwrap();
                let identity_id = vector["identity_id"].as_str().unwrap();
                let key = derive_sync_key(&ikm, identity_id);
                let nonce_hex = vector["nonce_hex"].as_str().unwrap();
                let nonce: [u8; 12] = hex::decode(nonce_hex).unwrap().try_into().unwrap();
                let plain = vector["plaintext_utf8"].as_str().unwrap().as_bytes();
                let mut env = private_state_fixture_envelope();
                encrypt_object_payload_with_nonce(&mut env, &key, plain, nonce).unwrap();
                assert_eq!(env.nonce, vector["expected_nonce_b64"].as_str().unwrap());
                assert_eq!(
                    env.ciphertext,
                    vector["expected_ciphertext_b64"].as_str().unwrap()
                );
                assert_eq!(env.tag, vector["expected_tag_b64"].as_str().unwrap());
                assert_eq!(
                    env.content_hash.as_deref(),
                    Some(vector["expected_content_hash_hex"].as_str().unwrap())
                );
                let out = decrypt_envelope(&env, &key).unwrap();
                assert_eq!(out, plain);
            }
            other => panic!("unknown golden vector: {other}"),
        }
    }
}

fn conformance_now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 15, 18, 0, 0).unwrap()
}

#[test]
fn wire_json_envelope_fixtures_validate() {
    let now = conformance_now();
    for name in ["envelope_public_metadata", "envelope_private_state_encrypted"] {
        let path = conformance_root().join(format!("json/{name}.json"));
        let env: SyncEnvelope =
            serde_json::from_str(&fs::read_to_string(&path).expect("json fixture")).unwrap();
        assert_eq!(env.version, PROTOCOL_VERSION);
        env.validate_meta_at(now).expect("fixture must pass validate_meta_at");
    }
}

#[test]
fn transfer_policy_matrix_matches_spec() {
    let path = conformance_root().join("json/transfer_policy_matrix.json");
    let doc: serde_json::Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(
        doc["protocol_version"].as_str().unwrap(),
        PROTOCOL_VERSION
    );
    for entry in doc["transfer_classes"].as_array().unwrap() {
        let class: TransferClass = serde_json::from_value(entry["class"].clone()).unwrap();
        let p: TransferPolicy = class.policy();
        assert_eq!(p.encryption_required, entry["encryption_required"].as_bool().unwrap());
        assert_eq!(
            p.twofa_required_to_apply,
            entry["twofa_required_to_apply"].as_bool().unwrap()
        );
        assert_eq!(
            p.relay_may_store_ciphertext,
            entry["relay_may_store_ciphertext"].as_bool().unwrap()
        );
        assert_eq!(p.gossip_allowed, entry["gossip_allowed"].as_bool().unwrap());
        assert_eq!(p.p2p_preferred, entry["p2p_preferred"].as_bool().unwrap());
        assert_eq!(
            p.revocation_invalidates,
            entry["revocation_invalidates"].as_bool().unwrap()
        );
        assert_eq!(
            p.agent_may_read_metadata,
            entry["agent_may_read_metadata"].as_bool().unwrap()
        );
        assert_eq!(
            p.agent_may_read_payload,
            entry["agent_may_read_payload"].as_bool().unwrap()
        );
    }
}

#[test]
fn wire_cbor_envelope_fixtures_match_json() {
    for name in ["envelope_public_metadata", "envelope_private_state_encrypted"] {
        let json_path = conformance_root().join(format!("json/{name}.json"));
        let cbor_path = conformance_root().join(format!("cbor/{name}.cbor"));
        let from_json: SyncEnvelope =
            serde_json::from_str(&fs::read_to_string(&json_path).unwrap()).unwrap();
        let cbor_bytes = fs::read(&cbor_path).expect("cbor fixture");
        let from_cbor: SyncEnvelope = ciborium::de::from_reader(cbor_bytes.as_slice()).unwrap();
        assert_eq!(from_json.envelope_id.0, from_cbor.envelope_id.0);
        assert_eq!(from_json.ciphertext, from_cbor.ciphertext);
        assert_eq!(from_json.transfer_class, from_cbor.transfer_class);
    }
}

#[test]
fn golden_decrypt_roundtrip_from_json_fixture() {
    let path = conformance_root().join("json/envelope_private_state_encrypted.json");
    let env: SyncEnvelope = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let golden_path = conformance_root().join("golden/crypto.json");
    let golden: GoldenFile = serde_json::from_str(&fs::read_to_string(golden_path).unwrap()).unwrap();
    let vector = golden
        .vectors
        .iter()
        .find(|v| v["id"] == "aes_gcm_private_state_tab_set_payload")
        .unwrap();
    let ikm = hex::decode(vector["ikm_hex"].as_str().unwrap()).unwrap();
    let key = derive_sync_key(&ikm, vector["identity_id"].as_str().unwrap());
    let plain = decrypt_envelope(&env, &key).unwrap();
    assert_eq!(plain, vector["plaintext_utf8"].as_str().unwrap().as_bytes());
}

fn private_state_fixture_envelope() -> SyncEnvelope {
    let path = conformance_root().join("json/envelope_private_state_encrypted.json");
    let mut env: SyncEnvelope =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    env.nonce.clear();
    env.ciphertext.clear();
    env.tag.clear();
    env.content_hash = None;
    env
}
