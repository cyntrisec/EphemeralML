# EphemeralML Audit Evidence Template

**Organization:** ___________________________
**Evaluator:** ___________________________
**Date:** ___________________________
**EphemeralML Version:** ___________________________

---

## 1. Enclave Isolation (HIPAA 164.312(a) — Access Control)

**Requirement:** Data is processed inside a hardware-isolated Trusted Execution Environment.

| Evidence | Location | Verified? |
|----------|----------|-----------|
| TDX attestation quote in receipt | `pilot/evidence/receipt.cbor` | [ ] |
| CVM machine type (c3-standard-4 TDX) | `pilot/evidence/metadata.json` | [ ] |
| Confidential Space image family | Deploy log | [ ] |
| MRTD/RTMR measurements in attestation | Receipt fields | [ ] |

**Notes:** ___________________________

---

## 2. Data-in-Transit Encryption (HIPAA 164.312(e) — Transmission Security)

**Requirement:** All data is encrypted end-to-end between client and TEE.

| Evidence | Location | Verified? |
|----------|----------|-----------|
| HPKE session establishment (X25519 + ChaCha20-Poly1305) | Client output in `verify_output.txt` | [ ] |
| Attestation-bound session key derivation | Receipt `attestation_hash` field | [ ] |
| No plaintext in transit (host is blind relay on AWS; direct TLS on GCP) | Architecture docs | [ ] |

**Notes:** ___________________________

---

## 3. Audit Trail (HIPAA 164.312(b) — Audit Controls)

**Requirement:** Cryptographic proof of what code processed each inference request.

| Evidence | Location | Verified? |
|----------|----------|-----------|
| Signed Attested Execution Receipt | `pilot/evidence/receipt.cbor` | [ ] |
| Receipt contains: model hash, input/output hashes, attestation hash | Receipt fields | [ ] |
| Ed25519 signature verification | `pilot/evidence/verify_output.txt` | [ ] |
| Sequence number (replay protection) | Receipt `sequence_number` field | [ ] |

**Notes:** ___________________________

---

## 4. Key Management (HIPAA 164.312(a)(2)(iv) — Encryption and Decryption)

**Requirement:** Model decryption keys are released only to attested workloads.

| Evidence | Location | Verified? |
|----------|----------|-----------|
| Cloud KMS key with WIP-based access control | `setup_kms.sh` output | [ ] |
| WIP OIDC provider bound to CS attestation token | GCP IAM config | [ ] |
| Model DEK wrapped by Cloud KMS | `encrypt_model.sh` output | [ ] |
| Negative test: wrong model hash rejected | e2e test evidence (if run) | [ ] |

**Notes:** ___________________________

---

## 5. Data Minimization / Ephemeral Processing

**Requirement:** Sensitive data exists only during processing; session keys are zeroized on termination.

| Evidence | Location | Verified? |
|----------|----------|-----------|
| Session-scoped Ed25519 signing key (ephemeral) | Receipt key binding | [ ] |
| `ZeroizeOnDrop` on key material | Source code (`common/src/`) | [ ] |
| CVM terminated after use | `teardown.sh` output | [ ] |
| No persistent storage of plaintext inputs/outputs | Architecture docs | [ ] |

**Notes:** ___________________________

---

## Summary

| Control | Status | Notes |
|---------|--------|-------|
| Enclave Isolation | [ ] Pass / [ ] Fail | |
| Data-in-Transit | [ ] Pass / [ ] Fail | |
| Audit Trail | [ ] Pass / [ ] Fail | |
| Key Management | [ ] Pass / [ ] Fail | |
| Ephemeral Processing | [ ] Pass / [ ] Fail | |

**Overall Assessment:** ___________________________

**Reviewer Signature:** ___________________________
