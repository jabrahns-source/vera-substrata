# Empirical Validation Campaign

Immutable, reproducible evidence that the core claims hold.

## Bash version (any Linux / macOS / WSL)

```bash
bash evidence/run_campaign_bash.sh
```

Produces evidence files under `target/evidence/`:
- Fixed-point determinism matrix
- Canonical ordering stability
- Merkle root stability
- Tamper detection
- Golden vector + immutable hash

## Colab / Jupyter version

Upload or open `VERA_Empirical_Campaign_Colab.ipynb` (available in the local build artifacts) and run all cells.

The notebook mirrors the same five tiers in pure Python so anyone can re-execute without a Rust toolchain.

## What is proven

1. Fixed-point arithmetic is free of floating-point drift (repeated calls produce identical results).
2. Canonical ordering of activities is stable across different input orders.
3. Merkle roots are stable for identical ordered leaf sets.
4. Content changes are detectable via hash comparison.
5. A known golden vector (1000 × 0.05 = 50) matches exactly.

These are the empirical foundations of the deterministic claim. Full cryptographic signature tests live in the Rust test suite (`src/lib.rs`).
