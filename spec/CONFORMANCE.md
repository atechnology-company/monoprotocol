# Conformance (normative)

**Protocol version string:** `mono-sync/0.2.0-draft`

Implementations claiming compatibility MUST pass all fixtures in `conformance/` for the encodings they support.

---

## 1. Fixture layout

| Path | Purpose |
|------|---------|
| `golden/crypto.json` | HKDF and AES-256-GCM golden vectors (deterministic nonce) |
| `json/*.json` | Wire `SyncEnvelope` JSON fixtures |
| `cbor/*.cbor` | Same envelopes as CBOR |
| `cbor/*.manifest.json` | `cbor_hex` for hex-only test runners |
| `json/transfer_policy_matrix.json` | Policy matrix from [PROTOCOL.md §3.1](./PROTOCOL.md#31-transfer-policy-matrix) |

---

## 2. Golden crypto vectors

File: `golden/crypto.json`

### 2.1 `hkdf_derive_sync_key_v1`

- `ikm_hex`: 32 bytes `01`..`20`
- `identity_id`: `018f3e8e-7b3c-7000-8000-000000000001`
- `salt`: `mono-identity-018f3e8e-7b3c-7000-8000-000000000001`
- `info`: `mono-sync-key-v1`
- Compare `expected_sync_key_hex` to HKDF output.

### 2.2 `aes_gcm_private_state_tab_set_payload`

- Same `ikm` and `identity_id` as §2.1
- `plaintext_utf8`: `{"tabs":[]}`
- `nonce_hex`: 12 bytes `00`..`0b`
- Compare Base64 `nonce`, `ciphertext`, `tag`, and `content_hash` to fixture.
- Decrypt MUST recover `plaintext_utf8`.

Regenerate after spec changes:

```bash
cd rust && cargo run -p gen-golden
```

---

## 3. Wire envelope fixtures

| Fixture | Class | Encryption |
|---------|-------|------------|
| `envelope_public_metadata` | `public_metadata` | Plaintext in `ciphertext` (Base64) |
| `envelope_private_state_encrypted` | `private_state` | AES-256-GCM per §2.2 |

Fixed timestamps (for reproducible JSON/CBOR):

- `created_at`: `2026-01-15T12:00:00Z`
- `expires_at`: `2026-01-16T12:00:00Z`

Validation tests MUST use `now_utc = 2026-01-15T18:00:00Z` so envelopes are not expired.

---

## 4. Reference test suite

```bash
cd rust
cargo test -p monoprotocol-conformance
cargo test -p monoprotocol
```

---

## 5. Third-party checklist

- [ ] HKDF + AES-GCM matches `golden/crypto.json`
- [ ] JSON parse of `json/envelope_*.json`
- [ ] CBOR parse equivalent to JSON for `cbor/envelope_*.cbor`
- [ ] Policy matrix matches `transfer_policy_matrix.json`
- [ ] `validate_meta_at` accepts valid fixtures at conformance `now_utc`
- [ ] Rejects wrong `version`, expired envelope, missing 2FA on `sensitive_session`, encryption field misuse

---

## 6. Reference implementation limits (0.2.0-draft)

The Rust crate validates 2FA **wire format only** unless product secrets are configured. Do not rely on it for production authentication without replacing `twofa` verification.
