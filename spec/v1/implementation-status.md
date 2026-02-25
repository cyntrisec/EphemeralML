# AIR v1 — Implementation Status (Reference Verifier)

**Status:** Active reference implementation (Rust)  
**Date:** 2026-02-25  
**Normative baseline:** AIR v1.0 FROZEN (`m3-spec-frozen`, commit `d7c9d01`)

This document is non-normative. It summarizes what is implemented in the current Rust
reference implementation, what is covered by conformance tests, and what remains as backlog.

## 1. Scope

AIR v1 defines a receipt format and verifier behavior for **single-inference receipts**:

- COSE_Sign1 envelope (RFC 9052)
- CWT/EAT claims + AIR private claims
- Four-layer verification model:
  - parse
  - crypto
  - claim validation
  - policy evaluation

AIR v1 does **not** include pipeline chaining (vNEXT), SCITT integration, or deletion proof.

## 2. Reference Implementation (Rust)

Primary implementation:

- `common/src/air_receipt.rs` — AIR v1 build/parse/signature helpers
- `common/src/air_verify.rs` — four-layer verifier + structured `AirCheckCode`

### Implemented AIR v1 features

| Area | Status | Notes |
|------|--------|-------|
| COSE_Sign1 receipt generation | Implemented | Ed25519 signatures, tagged CBOR (`tag 18`) |
| CWT/EAT + AIR claim encoding | Implemented | Deterministic CBOR map encoding |
| AIR v1 parser | Implemented | Protected headers + claims decoding |
| Four-layer verifier | Implemented | Parse / Crypto / Claims / Policy |
| Structured failure codes | Implemented | `AirCheckCode` for conformance + diagnostics |
| Legacy v0.1 conversion | Implemented | `AirReceiptClaims::from_legacy()` |
| Golden vectors | Implemented | 2 valid + 8 invalid |
| CI vector gate | Implemented | Vector conformance checks run in CI |

### Claim validation coverage (Layer 3)

| Check | Status | Notes |
|------|--------|-------|
| `cti` present + non-zero | Implemented | `cti` is parsed as `bstr(16)` and checked |
| `model_hash` non-zero | Implemented | Fail-closed (`ZERO_MODEL_HASH`) |
| Measurement lengths | Implemented | `pcr0/pcr1/pcr2` must be 48 bytes |
| `measurement_type` allowlist | Implemented | `nitro-pcr`, `tdx-mrtd-rtmr` |
| `model_hash_scheme` allowlist | Implemented | Unknown values rejected fail-closed |

### Policy evaluation coverage (Layer 4)

| Check | Status | Notes |
|------|--------|-------|
| Freshness (`iat`, skew, max_age) | Implemented | `TIMESTAMP_STALE`, `TIMESTAMP_FUTURE` |
| Expected `model_hash` | Implemented | `MODEL_HASH_MISMATCH` |
| Expected `model_id` | Implemented | `MODEL_ID_MISMATCH` |
| Expected platform (`measurement_type`) | Implemented | `PLATFORM_MISMATCH` |
| Nonce binding (`eat_nonce`) | Implemented | `NONCE_MISMATCH`, `NONCE_MISSING` |
| Replay callback hook (`seen_cti`) | Implemented | Verifier supports hook; caller must supply stateful cache |

## 3. Conformance Corpus Status

Current AIR v1 corpus (`spec/v1/vectors/`):

- **2 valid vectors**
- **8 invalid vectors**
- Coverage across all verifier layers:
  - Layer 1 parse/header
  - Layer 2 signature
  - Layer 3 claims
  - Layer 4 policy

### Current vector set

| Vector | Expected outcome | Layer |
|--------|------------------|-------|
| `valid/v1-nitro-no-nonce.json` | PASS | all |
| `valid/v1-tdx-with-nonce.json` | PASS | all |
| `invalid/v1-wrong-alg.json` | `BAD_ALG` | L1 |
| `invalid/v1-wrong-key.json` | `SIG_FAILED` | L2 |
| `invalid/v1-zero-model-hash.json` | `ZERO_MODEL_HASH` | L3 |
| `invalid/v1-bad-measurement-length.json` | `BAD_MEASUREMENT_LENGTH` | L3 |
| `invalid/v1-nonce-mismatch.json` | `NONCE_MISMATCH` | L4 |
| `invalid/v1-model-hash-mismatch.json` | `MODEL_HASH_MISMATCH` | L4 |
| `invalid/v1-platform-mismatch.json` | `PLATFORM_MISMATCH` | L4 |
| `invalid/v1-stale-iat.json` | `TIMESTAMP_STALE` | L4 |

## 4. Trust Verification Status (Platform Runtime)

AIR v1 defines the receipt format. Runtime attestation verification is implemented separately in
EphemeralML and `confidential-ml-transport`.

### AWS Nitro

**Status:** Implemented and exercised in E2E flows

- COSE attestation verification
- Cert chain validation
- PCR pinning (policy-driven)
- Receipt/public-key binding checks

Known gap (non-blocking for AIR v1 format):

- Revocation checks are not yet fully enforced in Nitro path (`CRL` / `OCSP` backlog)

### GCP Confidential Space (JWT / CS envelope)

**Status:** Implemented with structured error codes and strict-mode enforcement

Implemented:

- RS256 signature verification
- JWKS `kid` lookup
- Issuer pinning
- Expiry checks
- Nonce binding
- Audience pinning fail-closed in strict mode
- MRTD pinning requirement fail-closed in strict mode (bridge construction)

### Intel TDX (quote verification in `confidential-ml-transport`)

**Status:** Implemented with partial DCAP collateral verification (not full DCAP)

Implemented:

- T1 parse: quote/document parsing, header/body shape checks
- T2 crypto: ECDSA-P256 quote signature verification
- T2/T4 binding: REPORTDATA public key / nonce checks
- T3 chain (partial):
  - PCK chain validation to trusted root
  - PCK leaf key bound to quote attestation key
  - CRL issuer/signature/time validation
  - CRL revocation lookup
- T4 policy:
  - MRTD pinning
  - RTMR pinning
  - nonce binding

Backlog (defined-only / not yet implemented):

- QE identity collateral validation
- TCB info collateral validation
- FMSPC consistency checks
- TCB status evaluation (`acceptable` vs `revoked`)

See `docs/security/M2_TRUST_MATRIX_STATUS.md` for the full T1/T2/T3/T4 matrix and code-level status.

## 5. E2E Emission Status

**AIR v1 receipts are now emitted in all production E2E inference paths** (commit `a421e98`, 2026-02-25).

### Where AIR v1 is emitted

| Path | Format | Artifact | Notes |
|------|--------|----------|-------|
| Direct mode (GCP) | COSE_Sign1 CBOR, base64 in JSON | `air_v1_receipt_b64` field | Alongside legacy `receipt` JSON |
| Direct mode (mock) | Same | Same | Emitted when `--expected-model-hash` provided |
| Pipeline mode (Nitro/GCP) | `__receipt_air_v1__` tensor (raw CBOR) | `--receipt-output-air-v1` file | Alongside `__receipt__` legacy tensor |
| Client save | Decoded from base64 | `/tmp/ephemeralml-receipt.cbor` | Automatic in GCP client mode |

### Verifier auto-detect

`ephemeralml-verify` automatically detects AIR v1 receipts by checking the first byte for CBOR tag 18 (`0xD2`).
Legacy JSON receipts continue to work unchanged. No flags needed.

### E2E script coverage

| Script | AIR v1 collected | AIR v1 verified |
|--------|-----------------|-----------------|
| `scripts/gcp/mvp_gpu_e2e.sh` | `receipt.cbor` in evidence dir | Strict-by-default AIR v1 verify (`EPHEMERALML_REQUIRE_AIR_V1_VERIFY=true`, opt-out available) |
| `scripts/gcp/verify.sh` | `receipt.cbor` in artifact manifest | AIR v1 verification + SHA-256 hash (optional strict fail mode via `EPHEMERALML_REQUIRE_AIR_V1_VERIFY`) |
| `scripts/gcp/e2e_kms_test.sh` | `receipt.cbor` copied | — |
| `scripts/nitro_e2e.sh` | `--receipt-output-air-v1` flag | — |

### Backward compatibility

- Server: `air_v1_receipt_b64` uses `skip_serializing_if = "Option::is_none"` — old clients ignore it
- Client: `#[serde(default)]` — old servers produce `None`, no breakage
- Legacy `receipt.json` continues in all paths
- If `model_hash` is unavailable, AIR v1 is simply not emitted (non-fatal)

### Latest cross-cloud verification run (2026-02-25)

- AWS Nitro E2E: PASS
- GCP CPU (TDX / Confidential Space) E2E: PASS (strict AIR v1 verification enabled in `verify.sh`)
- GCP GPU (TDX + H100 CC) E2E: PASS

Evidence bundles (local repo paths from latest run):

- `evidence/nitro-e2e-20260225T160258Z/`
- `evidence/mvp-20260225_194858/` (GCP CPU, strict AIR v1 verify)
- `evidence/mvp-20260225_161319/`

## 6. Known Gaps (Summary)

These do **not** change AIR v1 wire format validity, but matter for deployment assurances:

1. TDX DCAP is partial (PCK chain + CRL checks are implemented; QE/TCB/FMSPC are backlog).
2. Replay protection is verifier-policy dependent and requires caller-provided state (`seen_cti`).
3. AIR v1 covers single-inference receipts only (no pipeline proof chain in v1).
4. AIR v1 is an evidence format standard, not a compliance certification.

## 7. M4 Interop Readiness

Ready now:

- Frozen spec (`spec/v1/`)
- CDDL schema
- Conformance vectors
- Reference verifier
- Interop kit
- Public AIR v1 entrypoint docs
- Independent Python verifier harness (same team)
- Fresh-VM AIR v1 vector validation (`10/10`)

Still needed for M4 exit:

- At least one external third-party verifier run
- Interop feedback loop (docs/examples fixes, no normative churn unless necessary)

## 8. Test Coverage

505 tests passing across the workspace (`cargo test --workspace --features mock`):

- 83 verification tests (AIR v1 4-layer verifier + golden vectors + platform attestation)
- 59 receipt tests (legacy + AIR v1 round-trip, signing, compliance, property-based)
- 7 conformance vector tests (ct_001 through ct_020)
- Remaining: transport, pipeline, crypto, E2E integration, model handling
