# AIR v1 — Normative Dependencies

**Issue:** #66
**Status:** FROZEN (M0)
**Date:** 2026-02-25

## 1. Normative References

These specifications are **required** for implementing AIR v1. A conformant implementation MUST support all normative references.

| Ref ID | Specification | Version | Usage in AIR v1 |
|--------|--------------|---------|-----------------|
| RFC 9052 | CBOR Object Signing and Encryption (COSE): Structures and Process | 2022 | Receipt envelope: COSE_Sign1 structure |
| RFC 8392 | CBOR Web Token (CWT) | 2018 | Payload format: claims carried as CWT claims |
| RFC 9711 | Entity Attestation Token (EAT) | 2025 | Attestation claims framework: eat_profile, eat_nonce, iss, iat, cti |
| RFC 8949 | Concise Binary Object Representation (CBOR) | 2020 | Wire encoding; deterministic encoding per §4.2 |
| RFC 8610 | Concise Data Definition Language (CDDL) | 2019 | Schema definition for receipt structure |
| RFC 8032 | Edwards-Curve Digital Signature Algorithm (EdDSA) | 2017 | Signing algorithm: Ed25519 with verify_strict |
| FIPS 180-4 | Secure Hash Standard (SHA) | 2015 | SHA-256 for content hashes; SHA-384 for platform measurements |

## 2. Mandatory-to-Implement (MTI) Algorithms

| Function | MTI Algorithm | COSE Algorithm ID | Notes |
|----------|--------------|-------------------|-------|
| Signing | Ed25519 | -8 (EdDSA) | verify_strict required (canonical S values per RFC 8032 §5.1.7) |
| Content hash | SHA-256 | — | request_hash, response_hash, attestation_doc_hash, model_hash |
| Measurement hash | SHA-384 | — | PCR/RTMR values (48 bytes) |
| Deterministic CBOR | RFC 8949 §4.2 | — | Preferred serialization + sorted map keys |

### 2.1 Algorithm Agility

v1.0 mandates Ed25519 only. Future v1.x minor versions MAY add:
- Ed448 (RFC 8032)
- ECDSA P-256 (for environments where Ed25519 is unavailable)

The COSE header `alg` field identifies the algorithm. Verifiers MUST reject unknown algorithm IDs.

## 3. Informative References

These specifications are relevant but not required for conformance.

| Ref ID | Specification | Relevance |
|--------|--------------|-----------|
| RFC 5869 | HMAC-based Key Derivation Function (HKDF) | Used in transport layer (out of receipt scope) |
| RFC 9180 | Hybrid Public Key Encryption (HPKE) | Future transport upgrade path |
| IETF SCITT (draft) | Supply Chain Integrity, Transparency, and Trust | Future transparency log integration |
| RFC 4122 | UUID | receipt_id format (v4) |
| RFC 9334 | RATS Architecture | Attester/Verifier/Relying Party model |
| RFC 9782 | Entity Attestation Token (EAT) Media Types | HTTP/CoAP media type `application/eat+cwt` (Content-Format 263) |

## 4. COSE Header Parameters

AIR v1 uses these COSE_Sign1 header parameters:

### Protected Header

| Parameter | CBOR Label | Value | Required |
|-----------|-----------|-------|----------|
| alg | 1 | -8 (EdDSA) | Yes |
| content type | 3 | 61 (application/cwt) | Yes |

### Unprotected Header

| Parameter | CBOR Label | Value | Required |
|-----------|-----------|-------|----------|
| kid | 4 | Signing key identifier (bstr) | Optional |

## 5. CWT Claim Assignments

### Standard CWT/EAT Claims (integer keys)

| Claim | CWT Key | Type | Required | Source |
|-------|---------|------|----------|--------|
| iss (Issuer) | 1 | tstr | Yes | RFC 8392 |
| iat (Issued At) | 6 | uint | Yes | RFC 8392 — execution_timestamp |
| cti (CWT ID) | 7 | bstr | Yes | RFC 8392 — receipt_id (UUID v4, 16 bytes) |
| eat_profile | 265 | tstr | Yes | RFC 9711 — `"https://spec.cyntrisec.com/air/v1"` |
| eat_nonce | 10 | bstr | Optional | RFC 9711 — challenge nonce for replay resistance |

### AIR Private Claims (negative integer keys, range TBD)

Private claims use negative integer keys to avoid collision with IANA-registered CWT claims.

| Claim | Key | Type | Required | Description |
|-------|-----|------|----------|-------------|
| model_id | -65537 | tstr | Yes | Model identifier (operator-assigned, opaque) |
| model_version | -65538 | tstr | Yes | Model version string (operator-assigned, opaque) |
| model_hash | -65539 | bstr(32) | Yes | SHA-256 of model weights — cryptographic model identity |
| request_hash | -65540 | bstr(32) | Yes | SHA-256 of inference request |
| response_hash | -65541 | bstr(32) | Yes | SHA-256 of inference response |
| attestation_doc_hash | -65542 | bstr(32) | Yes | SHA-256 of attestation document |
| enclave_measurements | -65543 | map | Yes | Platform measurements (see scope-v1.md §1.2) |
| policy_version | -65544 | tstr | Yes | Policy version identifier |
| sequence_number | -65545 | uint | Yes | Monotonic counter within session |
| execution_time_ms | -65546 | uint | Yes | Inference wall-clock time (ms) |
| memory_peak_mb | -65547 | uint | Yes | Peak memory usage (MB) |
| security_mode | -65548 | tstr | Yes | Security mode identifier |
| model_hash_scheme | -65549 | tstr | No | How model_hash was computed (Issue #80) |

## 6. Rust Crate Dependencies

Reference implementation crates (informative, not normative):

| Crate | Usage |
|-------|-------|
| `coset` | COSE_Sign1 construction and parsing |
| `ciborium` | CBOR encoding/decoding (RFC 8949) |
| `ed25519-dalek` | Ed25519 sign/verify_strict |
| `sha2` | SHA-256 and SHA-384 |
| `uuid` | Receipt ID generation |
