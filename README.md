# VERA Substrata — Deterministic SB 253 Attestation Core

Four-layer zero-trust engine for producing cryptographically attested Scope 1 & 2 emissions receipts under California SB 253 / CARB.

**Even The Odds Foundry LLC** · Author: Jacarri Sanders

---

## The Four Layers

1. **Agnostic Ingestion** — Any structured activity data → single canonical byte stream. No domain logic in the trust boundary.
2. **Pure Deterministic Compute** — Fixed-point decimal arithmetic only. Same input bytes → same output bytes on every machine. No floating-point drift, no hidden state.
3. **Quantum-Ready Crypto** — Ed25519 for current speed + hash-based commitment path for post-quantum resistance. Merkle tree over every line item.
4. **Zero-Trust Transport** — The signature travels with the payload. TLS is optional. Air-gapped or compromised channel still yields a verifiable receipt. Optional remote HTTP surface included.

---

## Build

```bash
# CLI only (default)
cargo build --release

# With remote HTTP listener
cargo build --release --features remote
```

Binary: `target/release/vera`

---

## Quick Start — Normal Inventory

```bash
# 1. Generate a keypair (store the SECRET securely)
./target/release/vera keygen > keys.txt

# 2. Produce a signed receipt
./target/release/vera attest \
  --input examples/sample_input.json \
  --secret-key keys.txt \
  --output receipt.json

# 3. Verify
./target/release/vera verify --receipt receipt.json
```

---

## Quick Start — First-Year Relief (Statement of Non-Reporting)

```bash
./target/release/vera attest \
  --input examples/first_year_relief.json \
  --secret-key keys.txt \
  --output relief_receipt.json

./target/release/vera verify --receipt relief_receipt.json
```

This path is for entities that were **not** collecting (and not planning to collect) Scope 1 / Scope 2 data as of CARB’s 5 December 2024 Enforcement Notice. The engine short-circuits to an empty inventory and sets the statutory flags correctly.

---

## Remote Mode (optional)

```bash
cargo build --release --features remote

./target/release/vera serve --secret-key keys.txt --bind 0.0.0.0:8787
```

Endpoints:

- `GET  /health` — liveness + engine version
- `POST /v1/attest` — body `{"input": <RawInput>}` → signed receipt
- `POST /v1/verify` — body `<AttestationReceipt>` → validity + summary

The HTTP channel is convenience only. The receipt remains self-verifying offline.

---

## Schema

The output receipt conforms to:

`schemas/vera_sb253_attestation_receipt.schema.json`

All statutory fields required for the 2026 SB 253 cycle (and forward-compatible with later years) are present.

---

## Design Invariants

- Numbers travel as decimal strings until the pure compute layer.
- Canonicalization is order-stable.
- Signatures cover the receipt with signature fields zeroed.
- First-year relief (statement of non-reporting) is a first-class path.
- Scope 3 structure is present but not required for 2026 filings (consistent with current Ninth Circuit posture).
- Remote surface never becomes a trust boundary — the signature does.

---

## License

Proprietary — Even The Odds Foundry LLC  
See [LICENSE](LICENSE)
