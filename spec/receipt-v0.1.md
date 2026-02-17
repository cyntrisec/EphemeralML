# EphemeralML Attested Execution Receipt — Specification v0.1

**Status:** FROZEN (v0.1)
**Date:** 2026-02-17

## 1. Overview

An Attested Execution Receipt (AER) is a cryptographically signed record proving
that a specific ML inference was executed inside a hardware-attested confidential
workload. It is the core product artifact of EphemeralML.

## 2. Encoding

- Receipts are encoded as **CBOR** (RFC 8949)
- Map keys are serialized via `serde_cbor::Value` which uses `BTreeMap`, ensuring
  **deterministic sorted-key ordering**
- Receipts may also be represented as JSON for human readability, but the
  **canonical form for signature computation is always CBOR**

## 3. Fields

| Field | CBOR Type | Required | Description |
|-------|-----------|----------|-------------|
| `receipt_id` | text string | Yes | UUID v4 unique identifier |
| `protocol_version` | unsigned int | Yes | Fixed to `1` for v0.1 |
| `security_mode` | text string | Yes | `"GatewayOnly"` for v0.1 |
| `enclave_measurements` | map | Yes | Platform measurements (see §3.1) |
| `attestation_doc_hash` | byte string (32) | Yes | SHA-256 of attestation document |
| `request_hash` | byte string (32) | Yes | SHA-256 of inference request |
| `response_hash` | byte string (32) | Yes | SHA-256 of inference response |
| `policy_version` | text string | Yes | Policy version identifier |
| `sequence_number` | unsigned int | Yes | Monotonic counter within session |
| `execution_timestamp` | unsigned int | Yes | Unix timestamp (seconds) |
| `model_id` | text string | Yes | Model identifier |
| `model_version` | text string | Yes | Model version string |
| `execution_time_ms` | unsigned int | Yes | Inference wall-clock time (ms) |
| `memory_peak_mb` | unsigned int | Yes | Peak memory usage (MB) |
| `signature` | byte string (64) or null | Yes | Ed25519 signature (see §4) |
| `previous_receipt_hash` | byte string (32) or null | No | SHA-256 of previous stage receipt (pipeline only) |

### 3.1 Enclave Measurements

| Field | CBOR Type | Description |
|-------|-----------|-------------|
| `pcr0` | byte string (48) | PCR0 (Nitro) or MRTD (TDX) — SHA-384 |
| `pcr1` | byte string (48) | PCR1 (Nitro) or RTMR0 (TDX) — SHA-384 |
| `pcr2` | byte string (48) | PCR2 (Nitro) or RTMR1 (TDX) — SHA-384 |
| `pcr8` | byte string (48) or null | PCR8 (Nitro only, optional) |
| `measurement_type` | text string | `"nitro-pcr"` or `"tdx-mrtd-rtmr"` |

All measurement byte strings MUST be exactly 48 bytes (SHA-384).

## 4. Signature

### 4.1 Algorithm

**Ed25519** (RFC 8032) with `verify_strict` — canonical S values required.

### 4.2 Canonical Encoding for Signing

1. Clone the receipt
2. Set `signature` to `null`
3. Serialize to `serde_cbor::Value` (struct → Value, maps become BTreeMap with sorted keys)
4. Serialize the `Value` to CBOR bytes
5. Sign the resulting byte string with Ed25519

### 4.3 Determinism Guarantee

The two-step serialization (struct → Value → bytes) ensures key ordering is
deterministic regardless of Rust struct field declaration order. Implementations
MUST verify round-trip determinism: `decode(encode(receipt)) == encode(receipt)`.

## 5. Verification Checks

A receipt is **VERIFIED** if and only if all applicable checks pass:

| Check | ID | Description |
|-------|-----|-------------|
| Signature | SIG | Ed25519 `verify_strict` succeeds with provided public key |
| Model Match | MODEL | `model_id` matches expected value (if specified) |
| Measurement Type | MTYPE | `measurement_type` matches expected platform (if specified) |
| Timestamp Freshness | FRESH | `execution_timestamp` is within `max_age` of current time AND not in the future |
| Measurements Valid | MEAS | All pcr0/pcr1/pcr2 are exactly 48 bytes |

Checks may be **skipped** (e.g., model match when no expected model is provided).
A skipped check does not cause verification failure.

## 6. Pipeline Chaining

For multi-stage pipeline inference, each stage's receipt includes
`previous_receipt_hash` — the SHA-256 of the previous stage's CBOR-encoded
receipt. Stage 0 has `previous_receipt_hash = null`.

## 7. Interoperability

- CBOR library: any RFC 8949 compliant implementation
- Ed25519: RFC 8032 with strict verification (canonical S)
- SHA-256: FIPS 180-4
- SHA-384: FIPS 180-4 (for measurements)
- UUID: RFC 4122 v4
