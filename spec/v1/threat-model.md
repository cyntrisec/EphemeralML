# AIR v1 — Threat Model Summary

**Issue:** #64
**Status:** FROZEN (M0)
**Date:** 2026-02-25

## 1. System Model

```
┌──────────┐    encrypted channel    ┌────────────────────────────┐
│  Client   │◄──────────────────────►│  Confidential Workload     │
│ (Verifier)│                        │  ┌──────────────────────┐  │
│           │    AIR v1 receipt       │  │  ML Model            │  │
│           │◄───────────────────────│  │  Receipt Generator    │  │
│           │                        │  │  Ed25519 Signing Key  │  │
└──────────┘                        │  └──────────────────────┘  │
                                     │  Hardware TEE (Nitro/TDX)  │
                                     └────────────────────────────┘
```

### Roles (per IETF RATS RFC 9334)

| Role | Entity | Description |
|------|--------|-------------|
| **Attester** | Confidential workload | Generates receipts, holds signing key |
| **Verifier** | Client or third party | Validates receipt signature and claims |
| **Relying Party** | End user, auditor, regulator | Consumes verification result |
| **Endorser** | TEE vendor (AWS, Intel) | Provides attestation document / quote |

## 2. Trust Assumptions

AIR v1 assumes:

| Assumption | Detail |
|------------|--------|
| **TA-1: TEE hardware is correct** | The CPU's TEE implementation (Nitro hypervisor, Intel TDX module) faithfully isolates the workload and produces correct attestation documents. A hardware bug or backdoor breaks all guarantees. |
| **TA-2: Signing key stays in TEE** | The Ed25519 private key is generated inside and never leaves the confidential workload. If the key is exfiltrated, receipts can be forged. |
| **TA-3: Attestation document is authentic** | The attestation_doc_hash in the receipt corresponds to a genuine attestation document from the TEE platform. Verification of the attestation document itself is out of scope for AIR v1 (see §4, Limitation L-3). |
| **TA-4: Cryptographic primitives are sound** | Ed25519, SHA-256, and SHA-384 provide their expected security properties. |
| **TA-5: Clock is reasonably accurate** | The execution_timestamp reflects real time within a bounded skew. TEE clock integrity depends on the platform. |

## 3. Threat Analysis

### 3.1 Threats Mitigated by AIR v1

| ID | Threat | Mitigation |
|----|--------|------------|
| **T-1** | **Receipt forgery** — Attacker creates a fake receipt for an inference that never happened | Ed25519 signature over deterministic CBOR. Forging requires the signing key (protected by TA-2). |
| **T-2** | **Receipt tampering** — Attacker modifies claims (model_id, hashes) after signing | COSE_Sign1 signature covers the entire protected header + payload. Any modification invalidates the signature. |
| **T-3** | **Replay** — Attacker replays a legitimate receipt for a different request | **Partial mitigation.** cti (receipt_id, UUID v4) is unique and sequence_number is monotonic within session. However, UUID uniqueness alone does not prevent replay — the verifier MUST maintain seen-receipt state (cti deduplication) or the client MUST supply a challenge nonce via `eat_nonce` to bind the receipt to a specific request session. Without at least one of these, replay is possible. |
| **T-4** | **Algorithm confusion** — Attacker substitutes a weaker signature algorithm | Protected header `alg` is signed. Verifier rejects non-Ed25519 algorithms. |
| **T-5** | **Stale receipt** — Attacker presents an old receipt as current | Timestamp freshness check (FRESH) with configurable max_age. |
| **T-6** | **Wrong model** — Receipt claims a different model was used | `model_hash` (SHA-256 of model weights) is a required signed claim. Verifier checks the hash against a known-good value (MHASH check). `model_id` and `model_version` provide human-readable context but are operator-assigned and not cryptographic — the binding is `model_hash`. |

### 3.2 Threats NOT Mitigated by AIR v1

| ID | Threat | Why Not | Mitigation Path |
|----|--------|---------|-----------------|
| **T-7** | **TEE compromise** — Hardware bug allows memory read/key extraction | Breaks TA-1. AIR v1 cannot defend against compromised hardware. | Monitor vendor advisories; update firmware. |
| **T-8** | **Key exfiltration via side channel** | Breaks TA-2. If the key leaks, forged receipts are indistinguishable. | Key rotation, attestation-bound key provisioning (implementation-specific). |
| **T-9** | **Attestation document forgery** | AIR v1 only stores the hash, not the full document. Verifying the attestation document chain (e.g., Nitro COSE → AWS root CA, TDX DCAP → Intel PCS) is out of scope. | Implementation SHOULD verify attestation documents independently. Future AIR versions may embed attestation evidence. |
| **T-10** | **Input/output inference from hashes** | SHA-256 hashes of request/response are in the receipt. If the input space is small, an attacker could brute-force the hash. | Application-level concern. Salting or HMAC could be added in future versions. |
| **T-11** | **Denial of receipt** — Workload refuses to generate a receipt | AIR v1 is a format spec, not a protocol. It cannot force receipt generation. | Client protocol should require receipt before accepting response. |
| **T-12** | **Compromised verifier** — Verifier lies about verification result | Out of scope. The relying party trusts the verifier. | Multiple independent verifiers; transparency logs (SCITT). |
| **T-13** | **Data destruction proof** | AIR v1 does not prove data was deleted after inference. | Self-reported DestroyEvidence exists in EphemeralML but is NOT part of AIR v1 (see limitations.md). |

## 4. Signing Key Binding

### Current State (v0.1)

The signing key is generated inside the enclave and its public key is included in the attestation document. The receipt's signature is verifiable with this public key. However, the **binding between the signing key and the attestation document is implementation-specific** — AIR v1 does not define how this binding is established.

### Recommendation for Implementations

Implementations SHOULD:
1. Generate the Ed25519 signing key inside the TEE at startup
2. Include the public key in the attestation document (e.g., Nitro `public_key` field, TDX REPORTDATA)
3. Provide the attestation document alongside or within the receipt for end-to-end verification

## 5. Security Considerations for Verifiers

1. **MUST** use `verify_strict` (not `verify`) for Ed25519 — rejects non-canonical S values.
2. **MUST** reject receipts with unknown `eat_profile` values.
3. **MUST** check `alg` in the protected header matches Ed25519 (-8).
4. **MUST** check `model_hash` against a known-good value when model identity matters (MHASH check).
5. **SHOULD** enforce timestamp freshness with a reasonable max_age (e.g., 300 seconds).
6. **SHOULD** maintain a seen-cti set or require `eat_nonce` challenge binding to prevent replay (see T-3).
7. **SHOULD** independently verify the attestation document referenced by attestation_doc_hash.
