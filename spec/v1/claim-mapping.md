# AIR v1 — EAT Claim Mapping

**Issue:** #69
**Status:** v1.0 FROZEN
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

> **Implementation note (v1.0):** The reference implementation rejects non-empty unprotected headers. This is stricter than the CDDL, which permits optional `kid`. Rationale: unprotected headers are not covered by the COSE signature and can be tampered in transit. If `kid` is needed in a future v1.x, it should move to the protected header.

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

These claims use negative integer keys to avoid collision with IANA CWT claim registry. Range -65537 to -65548 assigned (required); -65549 assigned (optional). Range -65550 to -65599 reserved for v1.x extensions.

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
| Hash scheme | See `model_hash_scheme` (key -65549, optional) for how the hash was computed. When absent, treat model_hash as opaque. |

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

### model_hash_scheme — key -65549

| Property | Value |
|----------|-------|
| CBOR type | tstr |
| Required | No (optional, RECOMMENDED) |
| Semantics | Declares how `model_hash` was computed. Enables verifiers to reproduce the hash from model artifacts. |
| Verification | If present, verifier MUST recognize the scheme. Unknown schemes MUST be rejected (fail-closed). If absent, verifier treats model_hash as opaque (can still compare against known-good hash, but cannot reproduce it). |

**Defined scheme values:**

| Scheme | Description |
|--------|-------------|
| `"sha256-single"` | SHA-256 of a single model weights file. This is the default for single-file models (e.g., SafeTensors, GGUF, ONNX). |
| `"sha256-concat"` | SHA-256 of deterministically concatenated weight files. Files MUST be concatenated in lexicographic filename order. The concatenation order MUST be reproducible from the model artifact directory. |
| `"sha256-manifest"` | SHA-256 of a manifest document that lists per-file hashes. The manifest format is implementation-defined but MUST be self-describing (i.e., the manifest contains enough information to verify each file independently). |

**Extensibility:** New scheme values MAY be registered in v1.x minor updates. Implementations MUST NOT invent unregistered scheme values.

**Issue:** #80 (RESOLVED)

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

## 6. EAT Profile Declaration (RFC 9711 §6.3)

This section consolidates the mandatory profile positions per RFC 9711 §6.3.

| Declaration | AIR v1 Position |
|---|---|
| **Profile identifier** | URI: `"https://spec.cyntrisec.com/air/v1"` (carried in `eat_profile`, key 265) |
| **Encoding** | CBOR only (RFC 8949). JSON serialization is not defined. |
| **Envelope** | COSE_Sign1 (RFC 9052 §4.2), CBOR tag 18. Untagged COSE_Sign1 MUST be rejected. |
| **Payload content type** | COSE content_type = 61 (`application/cwt`). The payload is a CWT claims map. |
| **HTTP media type** | `application/eat+cwt` (RFC 9782). Receivers SHOULD accept both `application/cwt` and `application/eat+cwt`. |
| **Signing algorithm** | Ed25519 only (COSE alg = -8). `verify_strict` required (canonical S per RFC 8032 §5.1.7). No algorithm negotiation in v1. |
| **Detached bundles** | Not supported in v1. The attestation document is referenced by hash (`attestation_doc_hash`), not embedded. |
| **Key identification** | Out of band. The verifier obtains the Ed25519 public key through a platform-specific channel (e.g., attestation document, key registry). Optional `kid` in unprotected header is reserved but currently rejected by the reference implementation (see §1.2 note). |
| **Mandatory claims** | 16 required: iss, iat, cti, eat_profile, model_id, model_version, model_hash, request_hash, response_hash, attestation_doc_hash, enclave_measurements, policy_version, sequence_number, execution_time_ms, memory_peak_mb, security_mode. |
| **Optional claims** | 2 optional: eat_nonce (replay resistance), model_hash_scheme (hash computation method). |
| **Freshness** | `iat` carries execution timestamp (Unix seconds). Verifier applies `max_age` + `clock_skew` policy. `eat_nonce` provides optional challenge-response replay resistance (RFC 9711 §4.1, 8–64 bytes). |
| **Deterministic encoding** | Required. Map keys sorted per RFC 8949 §4.2.1 (shorter encoded form first, then bytewise lexicographic). |
| **Closed map** | The claims map is closed: unknown integer keys MUST be rejected. Duplicate keys MUST be rejected. |
| **Unprotected header** | MUST be empty. AIR v1 requires all header parameters in the protected bucket. The CDDL permits `? 4 => bstr` (kid) for forward compatibility, but the reference implementation rejects non-empty unprotected headers since they are not signed and can be tampered. |
| **Private claim keys** | -65537 to -65549 (private use per RFC 8392). No IANA registration required. Keys -65550 to -65599 reserved for v1.x extensions. |

## 7. v1.x Extension Rules

1. New optional claims MAY be added in v1.x minor versions using keys -65550 to -65599.
2. New claims MUST NOT be required — a v1.0 verifier must still accept v1.x receipts.
3. New measurement_type variants MAY be added (e.g., `"sev-snp-vcek"` for AMD SEV-SNP).
4. The protected header MUST NOT gain new required fields in v1.x.
5. New `model_hash_scheme` values MAY be registered in v1.x minor updates.
