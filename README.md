# Mono sync protocol (`monoprotocol`)

**Version:** `mono-sync/0.2.0-draft`  
**License:** [Mozilla Public License 2.0](LICENSE)

The **Markdown specification** in [`spec/`](spec/) is canonical. The Rust crate under [`rust/mono-protocol/`](rust/mono-protocol/) is a reference implementation that MUST match the spec and [`conformance/`](conformance/) fixtures; third-party code should implement against the spec first.

## Repository layout

| Path | Role |
|------|------|
| `spec/PROTOCOL.md` | Normative protocol (wire, crypto, journal, capabilities) |
| `spec/OBJECTS.md` | Normative replicated object model |
| `spec/CONFORMANCE.md` | How to run and extend test vectors |
| `conformance/` | Golden HKDF/AES-GCM vectors, JSON and CBOR wire fixtures |
| `rust/mono-protocol` | Reference types and crypto (MPL-2.0) |
| `rust/mono-protocol-conformance` | Tests that load `conformance/` fixtures |

## Quick start (Rust)

```bash
cd rust
cargo test
cargo run -p gen-golden   # regenerate conformance/golden and wire fixtures
```

## Implementing in another language

1. Read `spec/PROTOCOL.md` and `spec/OBJECTS.md`.
2. Implement HKDF + AES-256-GCM exactly as in `spec/CONFORMANCE.md`.
3. Pass all vectors in `conformance/golden/crypto.json`.
4. Parse `conformance/json/*.json` and `conformance/cbor/*.cbor` into your envelope type.

## Pre-release audit

See [AUDIT.md](AUDIT.md) for known limitations (especially 2FA stub behavior) and the release checklist.

## Related projects

Product mesh, gateway, browser, and adapters remain in [mono](https://github.com/atechnology-company/mono) and depend on this protocol crate.
