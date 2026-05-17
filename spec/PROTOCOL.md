# Mono sync protocol (normative)

**Protocol version string:** `mono-sync/0.2.0-draft`

This document is **canonical**. The Rust crate in `rust/mono-protocol/` is a reference implementation and MUST conform to this spec and the fixtures in `conformance/`. See [OBJECTS.md](./OBJECTS.md) and [CONFORMANCE.md](./CONFORMANCE.md).

---

## 1. Core model

```text
Identity owns objects → devices replicate objects → transfer class drives policy
```

Replication is **object-centric**: each entity is a `SyncObject` with a stable `ObjectId`, owned by an `IdentityId`, replicated between `DeviceId` peers under policy derived from `TransferClass`.

---

## 2. Identifiers

All identifiers are **UTF-8 strings** on the wire. New identifiers SHOULD be UUID version 7 (RFC 9562) in canonical string form.

| Field | JSON key | Semantics |
|-------|----------|-----------|
| Identity | `owner` / grant `issuer` | Root user identity |
| Object | `object_id` | Replicated object instance |
| Device | `source_device_id` / `author_device` | Originating or authoring peer |
| Envelope | `envelope_id` | Wire wrapper instance |
| Operation | `op_id` | Journal mutation |
| Key | `key_id` | Symmetric key epoch / rotation label |

`account_id` and `profile_id` are adapter aliases for product mapping; they are not used on the sync envelope.

---

## 3. Transfer classes

Enum values on the wire use **snake_case**:

| Value | Meaning |
|-------|---------|
| `public_metadata` | May be stored and gossiped; payload not encrypted on wire |
| `private_state` | Encrypted; no 2FA to apply |
| `sensitive_session` | Encrypted; 2FA required to apply on receiver |
| `hardware_bound_secret` | Encrypted; no relay or gossip; 2FA required |

### 3.1 Transfer policy matrix

`TransferClass` maps to `TransferPolicy`. Implementations MUST match `conformance/json/transfer_policy_matrix.json`.

| Class | `encryption_required` | `twofa_required_to_apply` | `relay_may_store_ciphertext` | `gossip_allowed` | `p2p_preferred` | `revocation_invalidates` | `agent_may_read_metadata` | `agent_may_read_payload` |
|-------|----------------------|---------------------------|-------------------------------|------------------|-----------------|--------------------------|---------------------------|--------------------------|
| `public_metadata` | false | false | true | true | true | true | true | true |
| `private_state` | true | false | true | true | true | true | true | false |
| `sensitive_session` | true | true | true | true | true | true | true | false |
| `hardware_bound_secret` | true | true | false | false | false | true | false | false |

---

## 4. Wire envelope (`SyncEnvelope`)

### 4.1 Encodings

- **JSON:** UTF-8. Field names are **snake_case**. Timestamps are RFC 3339 / ISO 8601 in UTC with `Z` suffix (e.g. `2026-01-15T12:00:00Z`).
- **CBOR:** RFC 8949. Logical field names and values match JSON. Conformance fixtures use definite-length encoding as produced by the reference CBOR serializer.

Optional object fields with no value MUST be omitted in JSON (not `null`), except where noted.

### 4.2 `SyncEnvelope` fields

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `version` | string | yes | MUST equal `mono-sync/0.2.0-draft` |
| `envelope_id` | string | yes | |
| `object_id` | string | yes | |
| `object_kind` | string | yes | See [OBJECTS.md](./OBJECTS.md) |
| `owner` | string | yes | `IdentityId` |
| `source_device_id` | string | yes | |
| `transfer_class` | string | yes | §3 |
| `created_at` | string | yes | RFC 3339 UTC |
| `expires_at` | string | yes | RFC 3339 UTC; MUST be after `created_at` |
| `key_id` | string | yes | Key rotation label |
| `nonce` | string | yes | Base64 (RFC 4648 §4); see §5 |
| `ciphertext` | string | yes | Base64 payload; see §5 |
| `tag` | string | yes | Base64 GCM tag; see §5 |
| `content_hash` | string | no | Lowercase hex BLAKE3-256 of **plaintext** (§5.3) |
| `merkle_anchor` | string | no | Opaque anchor for mesh snapshots |
| `twofa_proof` | object | conditional | Required when policy `twofa_required_to_apply` |

### 4.3 `twofa_proof` object

| Field | Type | Required |
|-------|------|----------|
| `method` | `webauthn` \| `totp` \| `sms` | yes |
| `assertion` | string | yes |
| `credential_id` | string | no |

**Draft 0.2.0:** The reference implementation performs **wire-format validation** only (non-empty assertion; TOTP/SMS exactly six ASCII digits). Production implementations MUST verify WebAuthn signatures, TOTP HMAC, or SMS codes against configured secrets. See [CONFORMANCE.md](./CONFORMANCE.md).

---

## 5. Cryptography

### 5.1 Sync key derivation (HKDF)

Given:

- `ikm`: master input keying material (byte sequence; length ≥ 32 recommended)
- `identity_id`: owner identity string

Compute:

```text
salt   = UTF8("mono-identity-" + identity_id)
info   = UTF8("mono-sync-key-v1")
okm    = HKDF-SHA256(ikm, salt, info, L=32)
```

`HKDF` follows RFC 5869 (extract then expand). `salt` is passed to HKDF as the salt parameter (not hashed again by the caller).

### 5.2 AES-256-GCM payload encryption

When `encryption_required` is true:

1. `nonce` — 12 random bytes, unique per `(key_id, envelope_id)` under a given key.
2. `plaintext` — object payload bytes (typically UTF-8 JSON).
3. `ciphertext` — Base64 encoding of the **encrypted bytes only** (not including the tag).
4. `tag` — Base64 encoding of the 16-byte GCM authentication tag.
5. AEAD: AES-256-GCM with AAD empty.

Decryption: Base64-decode `nonce`, `ciphertext`, `tag`; decrypt with `ciphertext || tag` as the AEAD ciphertext input (tag appended for libraries that expect a single buffer).

### 5.3 Public metadata (no encryption)

When `encryption_required` is false:

- `nonce` MUST be the empty string `""`.
- `tag` MUST be the empty string `""`.
- `ciphertext` MUST be Base64(plaintext) using standard Base64 (RFC 4648 §4).

`content_hash` SHOULD be set to lowercase hex BLAKE3-256 of the plaintext.

### 5.4 Content hash

`content_hash` is 64 lowercase hexadecimal characters representing BLAKE3-256 of the plaintext bytes (before encryption). Implementations MAY omit it only when the plaintext is not yet available; receivers SHOULD verify when present.

---

## 6. Envelope validation

Implementations MUST reject envelopes that fail any check below. The reference API is `validate_meta_at(envelope, now_utc)`.

1. `version` equals `mono-sync/0.2.0-draft`.
2. `now_utc` ≤ `expires_at` and `created_at` < `expires_at`.
3. Transfer policy from §3.1 applied to `transfer_class`.
4. If `twofa_required_to_apply`: `twofa_proof` present and passes §4.3 format rules.
5. If `encryption_required`: `nonce` and `tag` non-empty; Base64-decoded `nonce` length exactly 12; `ciphertext` non-empty.
6. If not `encryption_required`: `nonce` and `tag` empty strings.

Failures SHOULD map to distinct error codes for debugging (see reference `EnvelopeError`).

---

## 7. Sync journal

Per `object_id`:

1. Append signed `StateOperation` records between snapshots.
2. `compact()` into `StateSnapshot` with Merkle root and content-addressed `blob_ref`.
3. Peers replay operations after the latest known snapshot.

Operation and snapshot field layouts are defined by the reference types; binary wire encoding for journal records is **out of scope** for 0.2.0-draft (product layer).

---

## 8. Capabilities

`CapabilityGrant` binds `issuer` (`IdentityId`) to `subject` (`device` or `agent`) for `object_id` with `actions`:

`read_metadata`, `read_payload`, `write`, `replicate`, `handoff`, `revoke`

Grants carry a binary `signature` and optional `expires_at`. Signature algorithm is product-defined in 0.2.0-draft; the reference stores opaque bytes.

---

## 9. Scope and non-goals (0.2.0-draft)

- Mesh transport, gossip, handshake, and IBC framing are **not** defined here (see mono product docs).
- Journal record signing algorithms are **not** normative in this draft.
- Full WebAuthn / TOTP verification is **not** required in the reference crate; see §4.3.
