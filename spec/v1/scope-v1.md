# AIR v1 — Scope and Non-Goals

**Issue:** #62
**Status:** FROZEN (M0)
**Date:** 2026-02-25
**Gating:** M1 implementation work MUST NOT begin until this document and all M0 deliverables are frozen. Any M1 issue that expands scope beyond what is defined here requires an amendment to this document first.

## 1. Scope — What v1 Defines

AIR v1 defines a **single-inference receipt**: one signed COSE envelope proving that one ML inference request was executed inside one attested confidential workload.

### 1.1 In Scope

| Area | Detail |
|------|--------|
| **Envelope format** | COSE_Sign1 (RFC 9052) wrapping a CWT (RFC 8392) payload |
| **Claims** | EAT base claims (RFC 9711) + AIR-specific private claims (model_id, model_version, model_hash, request_hash, response_hash, execution_time_ms, memory_peak_mb, enclave_measurements, attestation_doc_hash, policy_version, sequence_number, security_mode) |
| **Signing algorithm** | Ed25519 (RFC 8032) with verify_strict (canonical S). MTI (mandatory-to-implement). |
| **Hash algorithm** | SHA-256 (FIPS 180-4) for all content hashes. SHA-384 for platform measurements (PCR/RTMR values). |
| **Deterministic encoding** | CBOR deterministic encoding (RFC 8949 §4.2) for the signed payload |
| **Verification procedure** | Six checks: signature (SIG), model hash (MHASH), model match (MODEL), measurement type (MTYPE), timestamp freshness (FRESH), measurement validity (MEAS) |
| **Platform measurements** | Nitro PCR (pcr0/pcr1/pcr2/pcr8) and TDX MRTD/RTMR (mapped to same fields) |
| **Test vectors** | Golden vectors for valid receipts, invalid signatures, expired timestamps, malformed measurements |
| **CDDL schema** | Formal CDDL (RFC 8610) definition of receipt structure |
| **eat_profile URI** | `https://spec.cyntrisec.com/air/v1` registered per EAT conventions |

### 1.2 Platforms

v1 receipt measurements cover:

- **AWS Nitro Enclaves** — PCR0/PCR1/PCR2/PCR8, measurement_type `"nitro-pcr"`
- **Intel TDX** — MRTD/RTMR0/RTMR1, measurement_type `"tdx-mrtd-rtmr"`

Additional platforms (AMD SEV-SNP, ARM CCA) may be added in v1.x minor versions without breaking existing verifiers.

## 2. Non-Goals — What v1 Does NOT Define

| Non-Goal | Rationale |
|----------|-----------|
| **Pipeline chaining** | Multi-stage receipts (previous_receipt_hash linking) are deferred to vNEXT (M6). v1 receipts have no chaining field. |
| **Deletion/destruction proof** | DestroyEvidence is self-reported, not cryptographically provable. v1 does not claim provable data destruction. |
| **Transport protocol** | How receipts travel (VSock, TCP, gRPC) is out of scope. v1 defines the receipt, not the wire protocol. |
| **Key management** | How signing keys are provisioned, rotated, or bound to attestation is implementation-specific. v1 defines the signature algorithm, not key lifecycle. |
| **SCITT integration** | Transparency log registration (IETF SCITT) is a future layer. v1 receipts are compatible but do not require SCITT. |
| **C2PA integration** | Content provenance embedding is complementary but out of scope for v1. |
| **Model format** | v1 does not define how model_id or model_version are assigned. These are opaque strings. `model_hash` is a SHA-256 digest whose computation method is declared by the optional `model_hash_scheme` claim (key -65549). Defined schemes: `"sha256-single"`, `"sha256-concat"`, `"sha256-manifest"`. When `model_hash_scheme` is absent, the hash is treated as opaque. |
| **Attestation document format** | The attestation_doc_hash is a SHA-256 of the platform's attestation document. v1 does not define the document format itself (Nitro COSE, TDX quote, etc.). |
| **Privacy / differential privacy** | v1 does not address what the receipt reveals about inputs/outputs beyond their hashes. |
| **Performance requirements** | v1 does not mandate latency or throughput for receipt generation. |

## 3. Migration from v0.1

The current EphemeralML receipt (spec/receipt-v0.1.md) is a proprietary CBOR format with the signature embedded as a struct field. v1 replaces this with:

| v0.1 | v1 |
|------|-----|
| Custom CBOR map with `signature` field | COSE_Sign1 envelope (signature is a separate structure element, not in the COSE header) |
| Custom field names (text string keys) | CWT claims (integer keys) + AIR private claims |
| `protocol_version: 1` | `eat_profile: "https://spec.cyntrisec.com/air/v1"` |
| No formal schema | CDDL schema provided |
| No test vectors | Golden test vectors provided |

v0.1 receipts are NOT forward-compatible with v1 verifiers. The migration is a clean break.

## 4. Success Criteria for v1 Freeze

v1 is frozen when:

1. CDDL schema passes `cddl` tool validation
2. At least 10 golden test vectors exist (valid + invalid)
3. Reference verifier passes all vectors
4. At least one non-Rust implementation can verify a v1 receipt (e.g., Python, Go, or JS)
5. Spec document has had at least one external review
