# Dependency Baseline Report

Generated: 2026-02-18
Branch: `workstream-a/cs-transport-trust`

## Summary

| Metric | Value |
|--------|-------|
| Clean build time (dev, workspace) | 2m 54s |
| Duplicate crate pairs | 71 |
| Total workspace crates | 6 |

## Per-Crate Dependency Counts

| Crate | Dependency Nodes |
|-------|-----------------|
| ephemeral-ml-common | 197 |
| ephemeral-ml-client | 717 |
| ephemeral-ml-enclave | 1089 |
| ephemeral-ml-host | 1034 |
| ephemeral-ml-compliance | 197 |
| ephemeralml-verifier-api | 492 |

## Key Duplicate Libraries

High-impact duplicates (each pulls in its own sub-tree):

| Library | Versions | Root Cause |
|---------|----------|------------|
| reqwest | 0.12.28, 0.13.2 | verifier-api (0.12 dev-dep) vs client (0.13) |
| axum | 0.7.9, 0.8.8 | tonic 0.12 (axum 0.7) vs verifier-api (axum 0.8) |
| hyper | 0.14.32, 1.8.1 | axum 0.7 / tonic (hyper 0.14) vs axum 0.8 (hyper 1.x) |
| rustls | 0.21.12, 0.23.36 | tokenizers/candle (0.21) vs AWS SDK (0.23) |
| rand | 0.8.5, 0.9.2 | Most crates (0.8) vs newer deps (0.9) |
| p256 | 0.11.1, 0.13.2 | AWS sigv4 (0.11) vs hpke (0.13) |
| thiserror | 1.0.69, 2.0.18 | Older deps (1.x) vs newer deps (2.x) |
| http | 0.2.12, 1.4.0 | tonic/hyper 0.14 (0.2) vs hyper 1.x (1.0) |
| h2 | 0.3.27, 0.4.13 | hyper 0.14 (h2 0.3) vs hyper 1.x (h2 0.4) |
| tower | 0.4.13, 0.5.3 | tonic (0.4) vs axum 0.8 (0.5) |
| getrandom | 0.2.17, 0.3.4, 0.4.1 | Three versions from rand 0.8/0.9 + newer deps |

## Actionable Reduction Targets

### DEP-002: Remove unused client deps
Check for unused `[dependencies]` entries in client crate. 717 nodes is high.

### DEP-003: Unify reqwest version
- `verifier-api` dev-dep: reqwest 0.12 -> 0.13 (match client)
- Eliminates one reqwest + its rustls/hyper sub-tree

### DEP-004: Feature-gate AWS deps for GCP-only builds
- `cargo build --no-default-features --features gcp` should not pull aws-sdk-*
- enclave/host Cargo.toml: gate aws-config, aws-sdk-kms, aws-sdk-s3 behind `aws` feature
- Saves ~200+ nodes for GCP-only deployments

### DEP-005: Reduce tokio feature sets
- Many crates use `tokio = { features = ["full"] }`
- Only enclave/host need `rt-multi-thread` + `net` + `signal`
- common/client/compliance may only need `macros` + `rt`

### DEP-006: CI guardrail
- Add `cargo tree -d --depth 0` to CI; fail if duplicate count increases
- Prevents accidental dependency drift

## Non-Actionable Duplicates

These are caused by upstream crate version mismatches and cannot be resolved without upstream changes:

- **axum 0.7 vs 0.8**: Caused by tonic 0.12 depending on axum 0.7. Will resolve when tonic upgrades.
- **rustls 0.21 vs 0.23**: Caused by tokenizers/candle using older rustls. Will resolve upstream.
- **p256 0.11 vs 0.13**: AWS sigv4 uses older p256. AWS SDK update needed.
- **rand 0.8 vs 0.9**: Ecosystem-wide migration in progress. Cannot force.
