# Known Limits and Non-Claims

**Date:** 2026-02-28
**Purpose:** Canonical list of what AIR v1 does NOT prove, claim, or guarantee. Reference this before any external communication.

## Format / Spec Limits

| Limit | Detail | Where Documented |
|-------|--------|-----------------|
| Single-inference only | AIR v1 covers one inference event. No pipeline chaining. | IETF draft §1.2 (Non-Goals), NIST Explicit Limits |
| CBOR only | No JSON serialization defined | IETF draft §6.2, claim-mapping.md §6 |
| Ed25519 only | No algorithm negotiation in v1 | IETF draft §6.6 |
| No detached bundles | Attestation doc referenced by hash, not embedded | IETF draft §6.7 |
| Closed claims map | Unknown integer keys rejected | IETF draft §4.4, §6.13 |

## Security Non-Claims

| Non-Claim | Detail | Where Documented |
|-----------|--------|-----------------|
| No deletion proof | Receipts do not prove data was destroyed after inference | NIST Explicit Limits, spec/v1/limitations-v1.md L-4 |
| Hash != correctness | model_hash proves identity, not that the model is correct, unbiased, or safe | IETF draft §9.4, NIST Explicit Limits |
| TEE assumed correct | A TEE hardware vulnerability breaks all guarantees | IETF draft §9.6, threat-model.md TA-1 |
| No attestation doc verification | AIR references attestation by hash; verification is platform-specific | IETF draft §9.5 |
| Clock depends on host | iat accuracy limited by platform clock (Nitro uses host, TDX has TSC) | IETF draft §9.7 |
| Side-channel key leak | Key exfiltration via TEE side channels is not mitigated | threat-model.md T-2 |
| Denial of receipt | Workload can refuse to emit a receipt | threat-model.md T-9 |

## Evidence Limits

| Limit | Detail |
|-------|--------|
| Legacy benchmark not reproducible | +12.6% (C-1) from commit `b00bab1`, pipeline removed from main |
| GPU benchmark uses MiniLM only | Not representative of GPU performance; pipeline validation only |
| Enclave memory RSS = 0 | Host-path limitation; do not claim memory figures |
| Per-inference crypto from legacy pipeline | 0.028ms from commit `b00bab1`; magnitude stable but not re-measured |
| Same-team interop only | Python verifier is independent implementation but same team; no third-party interop yet |

## Regulatory / Compliance Non-Claims

| Non-Claim | Detail |
|-----------|--------|
| No regulatory certification | AIR v1 is not certified by NIST, HIPAA, SOC 2, or any regulatory body |
| No automatic compliance | Receipts may support compliance evidence but do not confer compliance |
| No legal opinion | This is a technical specification, not legal advice |

## Overhead Claim Boundaries

| Claim | Value | Scope | Reproducible |
|-------|-------|-------|-------------|
| C-2 (enclave execution) | +3.2% | Enclave-side only, excludes transport | Yes (on main) |
| C-1 (fully instrumented) | +12.6% | Host-observed, includes VSock | No (historical) |
| Headline range | +3-13% | Depends on measurement boundary | Partial |

Rules:
- Never present C-2 (+3.2%) without noting it excludes transport
- Never present C-1 (+12.6%) as reproducible on current main
- Always cite measurement scope alongside percentage
