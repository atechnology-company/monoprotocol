# Replicated objects (normative)

**Protocol version string:** `mono-sync/0.2.0-draft`

Companion to [PROTOCOL.md](./PROTOCOL.md). Defines object kinds, the `SyncObject` contract, ownership, and residency.

---

## 1. `SyncObject` contract

Every replicated entity:

1. Has a stable `object_id` and `owner` (`IdentityId`).
2. Declares `object_kind` (§2).
3. Carries a `version` map (`VersionVector`: device id → monotonic counter).
4. Exposes `permissions` (`CapabilitySet` of grants).
5. Declares `transfer_class` (§3) — **policy source of truth** for encryption, 2FA, relay, gossip, and agent visibility.
6. Declares `preferred_residency` (§4).

Payload serialization for encryption: **UTF-8 JSON** of the object struct (field names snake_case), unless a product adapter documents a different encoding for a specific kind (not normative in 0.2.0-draft).

---

## 2. `object_kind` values

Wire values are **snake_case**:

| `object_kind` | Default `transfer_class` | Typical `preferred_residency` |
|---------------|--------------------------|-------------------------------|
| `tab_set` | `public_metadata` | `browser_profile` |
| `browser_session` | `private_state` | `browser_profile` |
| `cookie_jar` | `sensitive_session` | `cupboard` |
| `clipboard_entry` | `private_state` | `cupboard` |
| `file_blob` | `private_state` | `cupboard` |
| `history_segment` | `public_metadata` | `cupboard` |
| `permission_grant` | `sensitive_session` | `browser_profile` |
| `agent_task` | `private_state` | `browser_profile` |
| `handoff_intent` | `public_metadata` | `mesh_peer` |
| `audit_segment` | `public_metadata` | `cupboard` |

Implementations MAY override `transfer_class` per instance when product policy requires; the envelope MUST still reflect the effective class.

---

## 3. Transfer class semantics

See [PROTOCOL.md §3](./PROTOCOL.md#3-transfer-classes). Object authors MUST set envelope `transfer_class` to match the effective policy for the payload.

---

## 4. Ownership and residency

| Concept | Rule |
|---------|------|
| **Owner** | Always the `IdentityId` of the user |
| **Residency** | Where ciphertext or plaintext bytes are stored at rest |

`preferred_residency` wire values (snake_case):

| Value | Meaning |
|-------|---------|
| `cupboard` | User content store (blob) |
| `tableware_coordination` | Coordination hints only; no content ownership |
| `browser_profile` | Local browser profile store |
| `mesh_peer` | Ephemeral peer-held handoff |
| `local_content_cache` | Device-local cache |

---

## 5. Reference object examples

### 5.1 `TabSetObject`

JSON payload fields: `object_id`, `owner`, `permissions`, `version`, `tabs_json` (string containing JSON array of tabs).

Default class: `public_metadata`.

### 5.2 `CookieJarObject`

JSON payload fields: `object_id`, `owner`, `permissions`, `version`, `jar_ref`, `cookies` (array of cookie records).

Default class: `sensitive_session`. Envelopes MUST include valid `twofa_proof` per [PROTOCOL.md §4.3](./PROTOCOL.md#43-twofa_proof-object).

---

## 6. Journal (per object)

```text
SyncJournal {
  latest_snapshot: Option<StateSnapshot>
  operations: [StateOperation, ...]
}
```

Compaction replaces `operations` with a new `StateSnapshot` containing `merkle_root`, `version`, `blob_ref` (content hash), `created_at`, `author_device`.

Operation `kind` tags (snake_case): `upsert`, `delete`, `handoff_offer`, `revoke_device`, `agent_action`.
