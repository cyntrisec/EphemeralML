# Final Fact-Check Report

**Date:** 2026-02-28
**Scope:** All publication-facing claims in IETF draft, NIST comment, and supporting docs
**Method:** Code-level verification against implementation, spec, and evidence artifacts

## Claim Verification Matrix

| # | Claim | Source | Code Path | Evidence | Verdict |
|---|-------|--------|-----------|----------|---------|
| 1 | 18 claims (16 req + 2 opt) | IETF §6.9-10 | `air_receipt.rs:68-93` (struct fields) | `air-v1.cddl` (18 entries) | **CONFIRMED** |
| 2 | Key range -65537 to -65549 | IETF §5.2 | `air_receipt.rs:30-42` (13 constants) | `claim-mapping.md` §3 | **CONFIRMED** |
| 3 | 4-layer verification | IETF §7 | `air_verify.rs` (L1-L4 functions) | Golden vectors (layer field) | **CONFIRMED** |
| 4 | 27 receipt diagnostic codes | NIST §2a | `air_verify.rs:23-85` (AirCheckCode enum) | — | **CONFIRMED** (was "36", corrected) |
| 5 | 38 attestation diagnostic codes | NIST §2a | `attest_verify.rs:24-122` (AttestCheckCode) | — | **CONFIRMED** (was "36", corrected) |
| 6 | 575 tests, 0 failures | IETF §12, NIST | `cargo test -q` output | — | **CONFIRMED** (was "574", corrected) |
| 7 | Ed25519 verify_strict | IETF §4.2 | `air_verify.rs:454`, `receipt_signing.rs:420` | — | **CONFIRMED** |
| 8 | +3.2% enclave overhead | NIST evidence | — | `benchmark-nitro/benchmark_report.md:25` | **CONFIRMED** (74.61→77.00ms) |
| 9 | +12.6% fully instrumented | README, benchmarks | — | `benchmark_results_multimodel_*/` | **CONFIRMED** (historical, labeled) |
| 10 | 10 golden vectors (2+8) | IETF §13, App B | `vectors/valid/` (2), `vectors/invalid/` (8) | — | **CONFIRMED** |
| 11 | Nitro CBOR receipt emitted | IETF §12 | — | `aws-nitro/receipt.cbor` (585 bytes) | **CONFIRMED** |
| 12 | GCP CPU TDX 10/10, 2/2 | NIST, matrix | — | `gcp-cpu-tdx/metadata.json` | **CONFIRMED** |
| 13 | GCP GPU H100 CC 10/10, 2/2 | NIST, matrix | — | `gcp-gpu-h100cc/metadata.json` | **CONFIRMED** |
| 14 | 16-rule compliance baseline | NIST §3b | — | `gcp-cpu-tdx/compliance_verify_log.txt` | **CONFIRMED** |
| 15 | COSE content_type = 61 | IETF §4.2 | `air_receipt.rs:364` (CoapContentFormat::Cwt) | coset source: `Cwt: 61` | **CONFIRMED** |
| 16 | alg/content_type/eat_profile in L1 | IETF §7.1 | `air_verify.rs:327-426` (layer1_parse) | `v1-wrong-alg.json` (layer: 1) | **CONFIRMED** |
| 17 | Per-inference crypto < 0.03ms | NIST §4d | — | `benchmarks.md:185` (0.028ms) | **CONFIRMED** (historical, labeled) |
| 18 | CBOR hex A2012703183D | IETF §13 | Manual decode: {1:-8, 3:61} | Matches golden vector protected header | **CONFIRMED** |

## Corrections Applied

| Item | Was | Now | Files Fixed |
|------|-----|-----|-------------|
| Test count | 574 | 575 | IETF draft, NIST comment, claim_evidence_matrix |
| Diagnostic codes | "36 defined variants" | "27 receipt + 38 attestation" | NIST comment |

## Wording Compliance (Guardrails C-001, C-101..C-103)

| Pattern | Status |
|---------|--------|
| C-001: "Reduces trust... through attestation, policy controls, and signed receipts" | Used correctly |
| C-101: No "no trust in [provider] required" | CLEAN |
| C-102: No "proves data irrecoverably deleted" | CLEAN (negative context only) |
| C-103: No "guarantees security/compliance" | CLEAN (negative context only) |

## Residual Non-Claims (Explicitly Documented)

All of these are documented in the NIST Explicit Limits section and/or the IETF draft Non-Goals:

1. No cryptographic deletion proof
2. Hash proves identity, not correctness
3. No regulatory certification
4. Single-inference scope only
5. GPU validation limited (functional only, not benchmarked at scale)
6. Attestation document verification out of scope
7. TEE hardware correctness assumed (Trust Assumption TA-1)
