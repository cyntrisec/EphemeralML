# Dependency Security Audit — 2026-02-21

**Repository:** EphemeralML-cyntrisec v0.2.9
**Tool:** `cargo-audit 0.22.1`
**Advisory DB commit:** `9dad93ab565dedea29b49d673c8004da4fbc71d2`
**Advisory DB timestamp:** 2026-02-21T02:48:10+01:00
**Advisory count:** 926
**Lockfile dependencies scanned:** 580

## Findings

| ID | Crate | Version | Severity | Type | Status |
|----|-------|---------|----------|------|--------|
| RUSTSEC-2023-0071 | rsa | 0.9.10 | Medium (CVSS 5.9) | Vulnerability | Active — no upstream patch |
| RUSTSEC-2024-0436 | paste | 1.0.15 | Informational | Unmaintained | Transitive via tokenizers/gemm |
| RUSTSEC-2021-0127 | serde_cbor | 0.11.2 | Informational | Unmaintained | Transitive via aws-nitro-enclaves-nsm-api |

### RUSTSEC-2023-0071 — rsa Marvin Attack

- **Direct dep of:** ephemeral-ml-enclave
- **Mitigation:** `decrypt_blinded()` used in `enclave/src/attestation.rs` and `enclave/src/mock.rs`
- **Upstream status:** No patched release; constant-time rewrite in progress
- **CI:** Ignored in audit job with tracked rationale

### RUSTSEC-2024-0436 — paste unmaintained

- **Dep chain:** tokenizers 0.22.2 / pulp → gemm-common → candle-core
- **Risk:** Compile-time macro only; no runtime impact
- **Action:** Wait for upstream tokenizers/gemm to migrate to `pastey`

### RUSTSEC-2021-0127 — serde_cbor unmaintained

- **Dep chain:** aws-nitro-enclaves-nsm-api 0.4.0 → serde_cbor 0.11.2
- **Risk:** Low — CBOR parsing in trusted enclave context
- **Action:** Monitor for aws-nitro-enclaves-nsm-api release migrating to ciborium

## System-Level Note

OpenSSL CVE-2025-15467 (CVSS 9.8) affects the C library linked by the `openssl` Rust crate.
Operationally closed for current baseline (Ubuntu Jammy `libssl3 3.0.2-0ubuntu1.21`
includes the backported fix). New hosts/images must still be validated before deploy.

## Raw Data

See `cargo-audit.json` in this directory.
