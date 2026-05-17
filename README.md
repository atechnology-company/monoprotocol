# Mono sync protocol (`monoprotocol`)

**Version:** `mono-sync/0.2.0-draft`  
**License:** [Mozilla Public License 2.0](LICENSE)

**monoprotocol** is the canonical specification and reference implementation for **Mono sync** — a wire format and cryptographic rules for replicating user-owned data between devices. An **identity** owns **sync objects**; each object is replicated peer-to-peer under a **transfer class** that defines encryption, relay, gossip, and two-factor requirements. Product code (mesh, gateway, browser) lives in [mono](https://github.com/atechnology-company/mono); this repository is the protocol layer only.

The **Markdown specification** in [`spec/`](spec/) is normative. The Rust crate [`monoprotocol`](https://crates.io/crates/monoprotocol) under [`rust/monoprotocol/`](rust/monoprotocol/) is a reference implementation that MUST match the spec and [`conformance/`](conformance/) fixtures. Implement in any language against the spec first; use the crate for interoperability testing or as a starting point.

## What you get

- **Normative spec** — identifiers, transfer classes, `SyncEnvelope` wire encoding (JSON and CBOR), HKDF key derivation, AES-256-GCM payloads, journal semantics, and capability grants ([`spec/PROTOCOL.md`](spec/PROTOCOL.md), [`spec/OBJECTS.md`](spec/OBJECTS.md)).
- **Conformance vectors** — golden crypto outputs, JSON/CBOR envelope fixtures, and transfer-policy matrices so independent implementations can verify byte-for-byte compatibility ([`conformance/`](conformance/), [`spec/CONFORMANCE.md`](spec/CONFORMANCE.md)).
- **Reference Rust crate** — types, crypto, validation, and tests published as [`monoprotocol` on crates.io](https://crates.io/crates/monoprotocol) (MPL-2.0).

## Repository layout

| Path | Role |
|------|------|
| `spec/PROTOCOL.md` | Normative protocol (wire, crypto, journal, capabilities) |
| `spec/OBJECTS.md` | Normative replicated object model |
| `spec/CONFORMANCE.md` | How to run and extend test vectors |
| `conformance/` | Golden HKDF/AES-GCM vectors, JSON and CBOR wire fixtures |
| `rust/monoprotocol` | Published crate `monoprotocol` on crates.io (MPL-2.0) |
| `rust/monoprotocol-conformance` | Tests that load `conformance/` fixtures |

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

## Related projects

Product mesh, gateway, browser, and adapters remain in [mono](https://github.com/atechnology-company/mono) and depend on this protocol crate.
