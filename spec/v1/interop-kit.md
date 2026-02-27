# AIR v1 — Interop Kit

**Status:** v1.0 FROZEN
**Date:** 2026-02-25

> **Production note (2026-02-25):** AIR v1 receipts are now emitted in live
> inference flows on both AWS Nitro and GCP Confidential Space. The receipts
> below are not hypothetical — they match what the production server produces.
> See [implementation-status.md](implementation-status.md) §5 for the full
> emission matrix.

> **Terminology note:** AIR here means **Attested Inference Receipt** (EphemeralML), not the IHE Radiology **AI Results (AIR)** profile. AIR v1 is not IETF EAR; AIR is workload-emitted inference evidence, while EAR is verifier-emitted attestation results. A verifier may consume AIR v1 plus platform evidence and emit an EAR in a RATS-based deployment.

This document is the starting point for implementing an AIR v1 verifier in any language. It bundles the minimum information needed to parse, verify, and validate AIR v1 receipts against the golden test vectors.

## 1. Quick Start

### What you need

1. A COSE_Sign1 parser (RFC 9052)
2. A CBOR decoder (RFC 8949)
3. An Ed25519 verify_strict implementation (RFC 8032)
4. SHA-256 (for hash comparison, not for receipt verification itself)

### Verify a receipt in 5 steps

```
1. Decode CBOR tag 18 → COSE_Sign1 [protected, unprotected, payload, signature]
2. Check protected header: alg == -8 (EdDSA), content_type == 61 (application/cwt)
3. Build Sig_structure1 = ["Signature1", protected, h'', payload]
4. Ed25519 verify_strict(public_key, Sig_structure1, signature)
5. Decode payload as CBOR map → validate claims (see §3)
```

## 2. Test Key

All golden vectors use this deterministic Ed25519 keypair:

| Field | Hex (64 chars = 32 bytes) |
|-------|---------------------------|
| Seed | `2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a` |
| Public key | `197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61` |

## 3. Claim Map (Integer Keys)

### Standard CWT/EAT claims

| Key | Name | Type | Required |
|-----|------|------|----------|
| 1 | iss | tstr | Yes |
| 6 | iat | uint | Yes |
| 7 | cti | bstr(16) | Yes |
| 10 | eat_nonce | bstr | No |
| 265 | eat_profile | tstr | Yes — must be `"https://spec.cyntrisec.com/air/v1"` |

### AIR private claims

| Key | Name | Type | Required |
|-----|------|------|----------|
| -65537 | model_id | tstr | Yes |
| -65538 | model_version | tstr | Yes |
| -65539 | model_hash | bstr(32) | Yes |
| -65540 | request_hash | bstr(32) | Yes |
| -65541 | response_hash | bstr(32) | Yes |
| -65542 | attestation_doc_hash | bstr(32) | Yes |
| -65543 | enclave_measurements | map | Yes |
| -65544 | policy_version | tstr | Yes |
| -65545 | sequence_number | uint | Yes |
| -65546 | execution_time_ms | uint | Yes |
| -65547 | memory_peak_mb | uint | Yes |
| -65548 | security_mode | tstr | Yes |
| -65549 | model_hash_scheme | tstr | No |

### Enclave measurements map

The map at key -65543 contains:

| Field | Type | Required |
|-------|------|----------|
| `"measurement_type"` | tstr | Yes — `"nitro-pcr"` or `"tdx-mrtd-rtmr"` |
| `"pcr0"` | bstr(48) | Yes |
| `"pcr1"` | bstr(48) | Yes |
| `"pcr2"` | bstr(48) | Yes |
| `"pcr8"` | bstr(48) | No (Nitro only) |

## 4. Golden Vectors

### Valid: `vectors/valid/v1-nitro-no-nonce.json`

Nitro measurements, no nonce. Your verifier MUST accept this receipt with the test public key and no policy constraints.

### Valid: `vectors/valid/v1-tdx-with-nonce.json`

TDX measurements, with `eat_nonce`. Your verifier MUST accept this receipt when the expected nonce matches.

### Invalid vectors (8 total)

| Vector | Expected failure |
|--------|-----------------|
| `v1-wrong-key.json` | Signature verification fails |
| `v1-wrong-alg.json` | Protected header `alg` is not -8 |
| `v1-zero-model-hash.json` | model_hash is all zeros |
| `v1-bad-measurement-length.json` | PCR value is not 48 bytes |
| `v1-nonce-mismatch.json` | eat_nonce does not match policy |
| `v1-model-hash-mismatch.json` | model_hash does not match policy |
| `v1-platform-mismatch.json` | measurement_type does not match policy |
| `v1-stale-iat.json` | iat is too old per policy max_age_secs |

## 5. Verification Checklist

A conformant verifier MUST implement these checks:

- [ ] **PARSE**: Decode CBOR tag 18, extract COSE_Sign1 fields
- [ ] **ALG**: Protected header `alg` == -8 (EdDSA). Reject all others.
- [ ] **CONTENT_TYPE**: Protected header content_type == 61
- [ ] **SIG**: Ed25519 verify_strict over Sig_structure1
- [ ] **PROFILE**: eat_profile == `"https://spec.cyntrisec.com/air/v1"`. Reject unknown.
- [ ] **CTI**: cti is exactly 16 bytes
- [ ] **MHASH**: model_hash is exactly 32 bytes, not all zeros
- [ ] **MEAS**: All pcr0/pcr1/pcr2 values are exactly 48 bytes
- [ ] **MTYPE**: measurement_type is `"nitro-pcr"` or `"tdx-mrtd-rtmr"`
- [ ] **SIZE**: Receipt must be ≤ 65,536 bytes (64 KB)
- [ ] **UNPROTECTED**: Unprotected header must be empty
- [ ] **CLOSED_MAP**: Reject unknown integer claim keys. Reject duplicate keys in both the claims map and the enclave_measurements map.
- [ ] **IAT_NONZERO**: `iat` must not be zero (Unix epoch is not a valid receipt timestamp)
- [ ] **TEXT_BOUNDS**: Text claims must be non-empty. Max lengths: iss ≤ 256, model_id ≤ 256, model_version ≤ 128, policy_version ≤ 256, security_mode ≤ 64, model_hash_scheme ≤ 64.
- [ ] **TDX_NO_PCR8**: If `measurement_type` is `"tdx-mrtd-rtmr"`, `pcr8` must be absent

Optional policy checks (verifier-configured):

- [ ] **NONCE**: If verifier supplied a nonce, eat_nonce must match
- [ ] **MODEL**: model_hash matches expected value
- [ ] **PLATFORM**: measurement_type matches expected platform
- [ ] **FRESH**: `now - max_age <= iat <= now + clock_skew`

## 6. Pseudocode: Minimal Verifier

```python
import cbor2, cose, ed25519

def verify_air_v1(receipt_bytes, public_key_bytes):
    # 1. Parse COSE_Sign1
    msg = cose.Sign1Message.decode(receipt_bytes)

    # 2. Check protected header
    assert msg.phdr[1] == -8,   "alg must be EdDSA (-8)"
    assert msg.phdr[3] == 61,   "content_type must be 61"

    # 3. Verify signature (verify_strict)
    sig_structure = cbor2.dumps([
        "Signature1",
        msg.phdr_encoded,
        b"",           # external_aad
        msg.payload
    ])
    ed25519.verify_strict(public_key_bytes, sig_structure, msg.signature)

    # 4. Decode claims
    claims = cbor2.loads(msg.payload)
    assert claims[265] == "https://spec.cyntrisec.com/air/v1"
    assert len(claims[7]) == 16      # cti
    assert len(claims[-65539]) == 32  # model_hash
    assert claims[-65539] != bytes(32)  # not all zeros

    # 5. Validate measurements
    meas = claims[-65543]
    assert meas["measurement_type"] in ("nitro-pcr", "tdx-mrtd-rtmr")
    assert len(meas["pcr0"]) == 48
    assert len(meas["pcr1"]) == 48
    assert len(meas["pcr2"]) == 48

    return claims
```

## 7. Reference Files

| File | Purpose |
|------|---------|
| [cddl/air-v1.cddl](cddl/air-v1.cddl) | Formal CDDL schema |
| [claim-mapping.md](claim-mapping.md) | Full claim semantics and verification rules |
| [dependencies.md](dependencies.md) | Normative RFC references |
| [vectors/](vectors/) | All golden test vectors |
| [scope-v1.md](scope-v1.md) | What v1 does and does not define |
| [limitations-v1.md](limitations-v1.md) | Explicit non-claims |

## 8. Known Implementations

| Language | Library / Package | Status | Coverage | Last Verified | Details |
|----------|--------------------|--------|----------|---------------|---------|
| Rust | `ephemeral-ml-common` (this repo) | Reference implementation — **emitted in production E2E** | AIR verifier + vectors + policy hooks + live emission | 2026-02-25 | [implementation-status.md](implementation-status.md) |
| Python | `spec/v1/scripts/interop_test.py` | Same-team independent verifier (third-party validation pending) | AIR v1 vector verification harness (COSE parse + Sig_structure verify + claims/policy checks) | 2026-02-25 (local + fresh VM `10/10`) | M4b: external third-party interop run pending |

To register your implementation, open an issue or PR.

## 9. Media Types

| Context | Value | Reference |
|---------|-------|-----------|
| COSE protected header (label 3) | 61 (`application/cwt`) | RFC 8392 |
| HTTP Content-Type | `application/eat+cwt` | RFC 9782 |
| CoAP Content-Format | 263 | RFC 9782 |

The COSE content_type (61) describes the **payload** encoding (CWT claims). The HTTP/CoAP media type describes the **outer token** (EAT). These are complementary: AIR v1 is an EAT token whose payload is CWT-encoded.
