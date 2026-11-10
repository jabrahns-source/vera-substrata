# VERA SB 253 Attestation Receipt Schema

The full machine-enforceable JSON Schema for the attestation receipt lives in:

`vera_sb253_attestation_receipt.schema.json`

It encodes every field required by California SB 253 / CARB Title 17 §§ 96070–96077 for the 2026 reporting cycle, including:

- Entity identity & coverage tests
- Scope 1 & 2 blocks
- First-year relief path
- Assurance fields
- Full cryptographic provenance (Ed25519 + post-quantum path + Merkle)
- Enforcement awareness ($500k penalty, fee timeline, Ninth Circuit posture)

The schema is also available in the local artifacts of the original build session and will be committed in the next update if not already present.
