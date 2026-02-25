# AIR v1 — EAT Claim Mapping

**Issue:** #69
**Status:** M1 DRAFT
**Date:** 2026-02-25
**Companion:** `cddl/air-v1.cddl` (wire schema)

This document maps every AIR v1 receipt field to its CWT/EAT claim, CBOR key, type constraint, and verification semantics. It is the normative bridge between the M0 scope documents and the CDDL schema.

## 1. COSE_Sign1 Envelope

AIR v1 receipts use COSE_Sign1 (RFC 9052 §4.2), CBOR tag 18.

```
COSE_Sign1 = [
  protected   : bstr,       ; serialized protected header map
  unprotected : map,         ; unprotected header map
  payload     : bstr,        ; serialized CWT claims map
  signature   : bstr .size 64  ; Ed25519 signature
]
```

The signature covers `Sig_structure1 = ["Signature1", protected, external_aad, payload]` where `external_aad` is empty (`h''`).

### 1.1 Protected Header

| Label | Name | Value | Notes |
|-------|------|-------|-------|
| 1 | alg | -8 (EdDSA) | Ed25519 with verify_strict. Verifiers MUST reject other values. |
| 3 | content type | 61 | `application/cwt`. Identifies payload as CWT claims. |

### 1.2 Unprotected Header

| Label | Name | Value | Notes |
|-------|------|-------|-------|
| 4 | kid | bstr | Optional. Key identifier for the signing key. |

## 2. Standard CWT/EAT Claims

These claims use IANA-registered CWT integer keys.

### iss (Issuer) — key 1

| Property | Value |
|----------|-------|
| CWT key | 1 |
| CBOR type | tstr |
| Required | Yes |
| Semantics | Identifies the issuing entity (e.g., `"cyntrisec.com"`, `"customer.example.com"`). |
| Verification | Informational. Verifier MAY check against an expected issuer allowlist. |

### iat (Issued At) — key 6

| Property | Value |
|----------|-------|
| CWT key | 6 |
| CBOR type | uint |
| Required | Yes |
| Semantics | Unix timestamp (seconds) when the inference completed. Maps to v0.1 `execution_timestamp`. |
| Verification | FRESH check: `now - max_age <= iat <= now + clock_skew`. Verifier SHOULD reject future timestamps. |

### cti (CWT ID) — key 7

| Property | Value |
|----------|-------|
| CWT key | 7 |
| CBOR type | bstr .size 16 |
| Required | Yes |
| Semantics | Receipt identifier. UUID v4 encoded as 16 raw bytes (not the 36-char string form). Maps to v0.1 `receipt_id`. |
| Verification | Verifiers maintaining replay state SHOULD track seen cti values. |
| Migration note | v0.1 used `receipt_id` as a text UUID. v1 uses raw bytes in cti. Display as UUID string for human readability. |

### eat_profile — key 265

| Property | Value |
|----------|-------|
| CWT key | 265 |
| CBOR type | tstr |
| Required | Yes |
| Semantics | Fixed value: `"https://spec.cyntrisec.com/air/v1"`. Identifies this receipt as AIR v1. |
| Verification | Verifiers MUST reject receipts with unknown eat_profile values. |

### eat_nonce — key 10

| Property | Value |
|----------|-------|
| CWT key | 10 |
| CBOR type | bstr |
| Required | No (optional) |
| Semantics | Challenge nonce provided by the client to bind the receipt to a specific request session. |
| Verification | If the verifier supplied a nonce, it MUST check that eat_nonce matches. Primary replay resistance mechanism when verifier-side cti dedup is not feasible. |

## 3. AIR Private Claims

These claims use negative integer keys to avoid collision with IANA CWT claim registry. Range -65537 to -65548 assigned; -65549 to -65599 reserved for v1.x extensions.

### model_id — key -65537

| Property | Value |
|----------|-------|
| CBOR type | tstr |
| Required | Yes |
| Semantics | Human-readable model identifier (e.g., `"minilm-l6-v2"`). Operator-assigned, opaque. |
| Verification | MODEL check: verifier MAY compare against expected value. Not cryptographic — use model_hash for binding. |

### model_version — key -65538

| Property | Value |
|----------|-------|
| CBOR type | tstr |
| Required | Yes |
| Semantics | Human-readable model version (e.g., `"1.0.0"`). Operator-assigned, opaque. |
| Verification | MODEL check (combined with model_id). Not cryptographic. |

### model_hash — key -65539

| Property | Value |
|----------|-------|
| CBOR type | bstr .size 32 |
| Required | Yes |
| Semantics | SHA-256 of model weights. The cryptographic binding between the receipt and a specific model artifact. |
| Verification | MHASH check: verifier MUST compare against a known-good hash when model identity matters. This is the primary model identity proof. |
| Open issue | #80: multi-file hashing scheme is implementation-defined in v1.0. A `model_hash_scheme` claim may be added in v1.x. |

### request_hash — key -65540

| Property | Value |
|----------|-------|
| CBOR type | bstr .size 32 |
| Required | Yes |
| Semantics | SHA-256 of the inference request payload. Binds the receipt to a specific input. |
| Verification | Client holding the original request can recompute and compare. |

### response_hash — key -65541

| Property | Value |
|----------|-------|
| CBOR type | bstr .size 32 |
| Required | Yes |
| Semantics | SHA-256 of the inference response payload. Binds the receipt to a specific output. |
| Verification | Client holding the original response can recompute and compare. |

### attestation_doc_hash — key -65542

| Property | Value |
|----------|-------|
| CBOR type | bstr .size 32 |
| Required | Yes |
| Semantics | SHA-256 of the platform attestation document (Nitro COSE doc, TDX quote, etc.). Links the receipt to TEE evidence. |
| Verification | Verifier SHOULD independently obtain and verify the attestation document, then compare its hash. AIR v1 does not define attestation document verification (see limitations L-3). |

### enclave_measurements — key -65543

| Property | Value |
|----------|-------|
| CBOR type | map |
| Required | Yes |
| Semantics | Platform measurement registers. Structure depends on measurement_type (see §4). |
| Verification | MEAS check: all pcr0/pcr1/pcr2 values MUST be exactly 48 bytes. MTYPE check: measurement_type MUST be a recognized platform string. |

### policy_version — key -65544

| Property | Value |
|----------|-------|
| CBOR type | tstr |
| Required | Yes |
| Semantics | Version of the policy governing this workload (e.g., `"policy-2026.02"`). |
| Verification | Informational. Verifier MAY compare against an expected policy version. |

### sequence_number — key -65545

| Property | Value |
|----------|-------|
| CBOR type | uint |
| Required | Yes |
| Semantics | Monotonically increasing counter within a single workload session. Resets on restart. |
| Verification | Verifiers processing a stream SHOULD check monotonicity. Gaps indicate missed receipts (within a session). |

### execution_time_ms — key -65546

| Property | Value |
|----------|-------|
| CBOR type | uint |
| Required | Yes |
| Semantics | Wall-clock inference time in milliseconds. |
| Verification | Informational. Anomalously low or high values may indicate issues but are not a verification failure. |

### memory_peak_mb — key -65547

| Property | Value |
|----------|-------|
| CBOR type | uint |
| Required | Yes |
| Semantics | Peak memory usage during inference in megabytes. |
| Verification | Informational. |

### security_mode — key -65548

| Property | Value |
|----------|-------|
| CBOR type | tstr |
| Required | Yes |
| Semantics | Security mode of the workload (e.g., `"GatewayOnly"`, `"FullAttestation"`). |
| Verification | Informational. Verifier MAY require a specific security mode. |

## 4. Measurement Map Variants

The `enclave_measurements` claim (key -65543) contains a map whose structure depends on the `measurement_type` field inside it.

### 4.1 Nitro PCR (`measurement_type = "nitro-pcr"`)

| Field | CBOR Type | Required | Description |
|-------|-----------|----------|-------------|
| `"pcr0"` | bstr .size 48 | Yes | PCR0 — SHA-384 |
| `"pcr1"` | bstr .size 48 | Yes | PCR1 — SHA-384 |
| `"pcr2"` | bstr .size 48 | Yes | PCR2 — SHA-384 |
| `"pcr8"` | bstr .size 48 | No | PCR8 — SHA-384 (optional) |
| `"measurement_type"` | tstr | Yes | `"nitro-pcr"` |

### 4.2 TDX MRTD/RTMR (`measurement_type = "tdx-mrtd-rtmr"`)

| Field | CBOR Type | Required | Description |
|-------|-----------|----------|-------------|
| `"pcr0"` | bstr .size 48 | Yes | MRTD — SHA-384 |
| `"pcr1"` | bstr .size 48 | Yes | RTMR0 — SHA-384 |
| `"pcr2"` | bstr .size 48 | Yes | RTMR1 — SHA-384 |
| `"measurement_type"` | tstr | Yes | `"tdx-mrtd-rtmr"` |

### 4.3 Cross-Platform Naming

TDX registers are mapped to `pcr0`/`pcr1`/`pcr2` field names for verifier simplicity. The `measurement_type` field disambiguates semantics. This allows a single verifier codepath for measurement validation.

## 5. Migration from v0.1 Claims

| v0.1 Field | v1 Claim | Key | Change |
|------------|----------|-----|--------|
| `receipt_id` (tstr UUID) | `cti` | 7 | Text UUID → 16-byte bstr |
| `protocol_version` (uint) | `eat_profile` | 265 | Integer → profile URI string |
| `execution_timestamp` (uint) | `iat` | 6 | Same semantics, standard CWT key |
| `signature` (bstr in map) | COSE_Sign1 signature field | — | Moved out of claims into envelope |
| `previous_receipt_hash` | — | — | Removed in v1 (pipeline is vNEXT) |
| _(new)_ | `model_hash` | -65539 | New required claim, no v0.1 equivalent |
| _(new)_ | `eat_nonce` | 10 | New optional claim for replay resistance |

## 6. v1.x Extension Rules

1. New optional claims MAY be added in v1.x minor versions using keys -65549 to -65599.
2. New claims MUST NOT be required — a v1.0 verifier must still accept v1.x receipts.
3. New measurement_type variants MAY be added (e.g., `"sev-snp-vcek"` for AMD SEV-SNP).
4. The protected header MUST NOT gain new required fields in v1.x.
5. `model_hash_scheme` (Issue #80) is the first candidate extension claim (key -65549).
