# Pre-release audit (`mono-sync/0.2.0-draft`)

Audit date: 2026-05-17. Spec is canonical under `spec/`; this document records gaps and release checks.

## Passed

| Area | Status |
|------|--------|
| Spec ↔ crypto (HKDF salt/info, AES-GCM split tag, BLAKE3 content hash) | Golden vectors in `conformance/golden/crypto.json` |
| Spec ↔ wire JSON/CBOR | Fixtures + `monoprotocol-conformance` tests |
| Spec ↔ transfer policy matrix | `conformance/json/transfer_policy_matrix.json` |
| `validate_meta_at` (version, lifetime, 2FA presence, encryption fields) | Conformance fixtures at fixed `now_utc` |
| License | MPL-2.0 (`LICENSE`) |
| Crate version | `0.2.0` aligned with `mono-sync/0.2.0-draft` |

## Known limitations (documented in spec)

| Item | Risk | Mitigation |
|------|------|------------|
| 2FA verification is wire-format only in reference Rust | High if used as production auth | `spec/PROTOCOL.md` §4.3; `spec/CONFORMANCE.md` §6 |
| WebAuthn stub accepts long opaque assertions | Medium | Products must use full WebAuthn verifier |
| Journal / capability signatures not normative on wire | Low for 0.2.0 | Out of scope until next draft |
| Mesh / transport not in this repo | N/A | Stay in `mono` product crates |

## Release checklist

- [x] Normative `spec/PROTOCOL.md`, `OBJECTS.md`, `CONFORMANCE.md`
- [x] Committed conformance fixtures (regenerate with `cargo run -p gen-golden`)
- [x] `cargo test` green in `rust/`
- [x] CI workflow verifies tests and fixture drift
- [x] Push to `github.com/atechnology-company/monoprotocol`
- [ ] Tag `v0.2.0-draft.1` (optional)
- [x] Publish `monoprotocol` v0.2.0 to crates.io

## mono integration

`mono` depends on `path = "../monoprotocol/rust/monoprotocol"` (crate name `monoprotocol` on crates.io). The in-tree `crates/mono-protocol` copy is removed to avoid drift.
