# M2 Trust Verification Test Matrix

**Status:** ACTIVE
**Date:** 2026-02-25
**Scope:** Attestation trust chain and policy enforcement verification

## Purpose

M1 proved the AIR v1 receipt format and verifier are correct (AirCheckCode).
M2 proves the attestation trust chain is correct (AttestCheckCode).

These are separate concerns:
- **AirCheckCode** — AIR receipt format/verification (M1, stable)
- **AttestCheckCode** — platform attestation verification (M2)
- **VerifyWarningCode** — non-fatal dangerous states (bypass/unchecked)

## Trust Layers

Parallel to the AIR v1 4-layer verifier:

| Layer | Name | What it checks |
|-------|------|----------------|
| T1_PARSE | Evidence shape | Quote/token structure, version, required fields |
| T2_CRYPTO | Signatures | Quote ECDSA, JWT RS256, COSE ECDSA-P384 |
| T3_CHAIN | Trust chain | Cert chain, collateral, trust anchors, freshness, revocation |
| T4_POLICY | Policy | Measurements, audience, nonce, TCB acceptance level |

## Top-Level Result Shape

```rust
pub struct AttestVerifyResult {
    pub verified: bool,
    pub platform: String,           // "tdx-dcap", "nitro-nsm", "cs-jwt"
    pub checks: Vec<AttestCheck>,
    pub warnings: Vec<VerifyWarningCode>,
}
```

---

## TDX DCAP Matrix (Critical Path)

Implemented in confidential-ml-transport, exercised from EphemeralML integration.

| ID | Layer | Case | Expected Code | Notes |
|----|-------|------|---------------|-------|
| TDX-OK-001 | T1-T4 | Valid quote + valid collateral + strict policy | PASS | Baseline positive |
| TDX-PARSE-001 | T1_PARSE | Malformed quote bytes | TDX_QUOTE_PARSE_FAILED | Corrupt fixture |
| TDX-PARSE-002 | T1_PARSE | Unsupported quote version/type | TDX_QUOTE_UNSUPPORTED_FORMAT | Version/type mismatch |
| TDX-CRYPTO-001 | T2_CRYPTO | Quote signature tampered | TDX_QUOTE_SIG_INVALID | Mutate quote sig |
| TDX-CRYPTO-002 | T2_CRYPTO | REPORTDATA/pubkey binding mismatch | TDX_REPORTDATA_BINDING_MISMATCH | Key not bound to quote |
| TDX-CHAIN-001 | T3_CHAIN | Missing collateral bundle | TDX_COLLATERAL_MISSING | No TCB/QE/PCK collateral |
| TDX-CHAIN-002 | T3_CHAIN | Collateral expired/stale (nextUpdate) | TDX_COLLATERAL_STALE | Freshness check |
| TDX-CHAIN-003 | T3_CHAIN | PCK cert chain invalid | TDX_PCK_CHAIN_INVALID | Wrong issuer/root |
| TDX-CHAIN-004 | T3_CHAIN | QE identity invalid signature | TDX_QE_IDENTITY_INVALID | Tampered QE identity |
| TDX-CHAIN-005 | T3_CHAIN | TCB info invalid signature | TDX_TCB_INFO_INVALID | Tampered TCB info |
| TDX-CHAIN-006 | T3_CHAIN | FMSPC mismatch (quote vs collateral) | TDX_FMSPC_MISMATCH | Critical consistency |
| TDX-CHAIN-007 | T3_CHAIN | Revoked cert during validity window | TDX_PCK_REVOKED | Revoked-during-validity |
| TDX-POL-001 | T4_POLICY | TCB status OutOfDate under strict policy | TDX_TCB_STATUS_UNACCEPTABLE | Policy-driven |
| TDX-POL-002 | T4_POLICY | TCB status Revoked | TDX_TCB_REVOKED | Always fail |
| TDX-POL-003 | T4_POLICY | TCB status ConfigurationNeeded strict | TDX_TCB_STATUS_UNACCEPTABLE | + permissive test |
| TDX-POL-004 | T4_POLICY | MRTD mismatch | TDX_MRTD_MISMATCH | Measurement pinning |
| TDX-POL-005 | T4_POLICY | RTMR mismatch | TDX_RTMR_MISMATCH | If RTMR pinning enabled |
| TDX-POL-006 | T4_POLICY | Nonce mismatch (if quote binds nonce) | TDX_NONCE_MISMATCH | Session binding |
| TDX-POL-007 | T4_POLICY | Collateral not yet valid / clock skew | TDX_COLLATERAL_TIME_INVALID | Time policy |

---

## GCP Confidential Space JWT Matrix (High Priority)

| ID | Layer | Case | Expected Code | Notes |
|----|-------|------|---------------|-------|
| CSJWT-OK-001 | T1-T4 | Valid JWT + JWKS + aud pin + nonce | PASS | Baseline positive |
| CSJWT-CRYPTO-001 | T2_CRYPTO | JWT signature invalid | CSJWT_SIG_INVALID | Mutate signature |
| CSJWT-CHAIN-001 | T3_CHAIN | kid not found in JWKS | CSJWT_KID_NOT_FOUND | Trust lookup |
| CSJWT-CHAIN-002 | T3_CHAIN | JWKS key type/alg mismatch | CSJWT_JWKS_KEY_INVALID | Reject wrong key |
| CSJWT-POL-001 | T4_POLICY | Missing aud when aud pinning required | CSJWT_AUD_MISSING | Mandatory |
| CSJWT-POL-002 | T4_POLICY | Wrong aud | CSJWT_AUD_MISMATCH | Critical |
| CSJWT-POL-003 | T4_POLICY | Wrong issuer | CSJWT_ISS_MISMATCH | Pin issuer |
| CSJWT-POL-004 | T4_POLICY | Token expired (exp) | CSJWT_EXPIRED | Freshness |
| CSJWT-POL-005 | T4_POLICY | nbf/iat invalid (future) | CSJWT_TIME_INVALID | Skew policy |
| CSJWT-POL-006 | T4_POLICY | Nonce mismatch (if bound) | CSJWT_NONCE_MISMATCH | Session binding |
| CSJWT-POL-007 | T4_POLICY | Enclave-side stub active in prod mode | CSJWT_UNVERIFIED_STUB_FORBIDDEN | Fail closed |

---

## AWS Nitro Attestation Matrix (Medium)

Nitro is already strong; M2 hardens policy and revocation.

| ID | Layer | Case | Expected Code | Notes |
|----|-------|------|---------------|-------|
| NITRO-OK-001 | T1-T4 | Valid COSE doc + cert chain + PCR pin | PASS | Baseline positive |
| NITRO-CRYPTO-001 | T2_CRYPTO | COSE doc signature invalid | NITRO_DOC_SIG_INVALID | Tamper doc |
| NITRO-CHAIN-001 | T3_CHAIN | Cert chain invalid / root pin mismatch | NITRO_CERT_CHAIN_INVALID | Trust anchor |
| NITRO-CHAIN-002 | T3_CHAIN | Cert expired/not yet valid | NITRO_CERT_TIME_INVALID | Time validity |
| NITRO-CHAIN-003 | T3_CHAIN | Revocation check + revoked cert | NITRO_CERT_REVOKED | If CRL/OCSP added |
| NITRO-POL-001 | T4_POLICY | PCR mismatch (pcr0/pcr1/pcr2/pcr8) | NITRO_MEASUREMENT_MISMATCH | Pinning |
| NITRO-POL-002 | T4_POLICY | Public key binding mismatch | NITRO_PUBKEY_BINDING_MISMATCH | Receipt key != attested |
| NITRO-POL-003 | T4_POLICY | Nonce mismatch | NITRO_NONCE_MISMATCH | Session binding |

---

## Cross-Cutting Trust Policy Matrix

"Don't accidentally turn security off" tests.

| ID | Layer | Case | Expected Result | Notes |
|----|-------|------|-----------------|-------|
| POL-001 | T4_POLICY | Measurement pinning disabled in strict mode | FAIL: POLICY_MEASUREMENT_PINNING_DISABLED | No silent bypass |
| POL-002 | T4_POLICY | Measurement pinning disabled in dev mode | PASS + WARN_MEASUREMENT_PINNING_BYPASSED | Loud warning |
| POL-003 | T4_POLICY | Aud pinning absent in CS strict mode | FAIL: POLICY_AUDIENCE_PIN_REQUIRED | Mandatory |
| POL-004 | T3_CHAIN | Trust anchor missing | FAIL: TRUST_ANCHOR_MISSING | Fail early |
| POL-005 | T3_CHAIN | Revocation checking unavailable but required | FAIL: REVOCATION_CHECK_UNAVAILABLE | Deterministic |
| POL-006 | T3_CHAIN | Revocation checking unavailable but optional | PASS + WARN_REVOCATION_UNCHECKED | Explicit warning |

---

## Test Fixture Strategy

All M2 tests must be **deterministic and CI-friendly**:

1. **Offline fixtures** for TDX quote + collateral bundles (no live Intel/Google network)
2. **Mutated fixtures** to isolate each layer failure (same pattern as AIR v1 vectors)
3. **Separate networked smoke suite** (optional/manual) for live JWKS/PCS checks
4. Fixtures stored in `spec/internal/fixtures/` or embedded as test constants

## Error Code Mapping

```
AirCheckCode       — AIR receipt format (M1, stable, do not change)
AttestCheckCode    — platform attestation (M2, this matrix)
VerifyWarningCode  — non-fatal dangerous states (M2)
```

EphemeralML client wraps both into one result:
- `air: AirVerifyResult` (existing)
- `attestation: AttestVerifyResult` (new)
- `warnings: Vec<VerifyWarningCode>` (new)

Each entry surfaces: exact code, layer, platform, human-readable reason.

---

## M2 Exit Criteria

1. TDX DCAP positive path passes (TDX-OK-001)
2. All critical TDX negative cases have deterministic tests and expected codes
3. CS JWT audience pinning is mandatory in strict mode and tested
4. No silent measurement-pinning bypass in strict mode
5. Attestation failures use structured codes (not generic errors)
6. Docs explain what is verified vs not verified per platform

## Scoped Out of M2

- SCITT / C2PA
- Pipeline chaining
- Non-Rust verifier
- Broad refactors unrelated to attestation trust
