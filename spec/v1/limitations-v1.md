# AIR v1 — Limitations and Non-Claims

**Issue:** #65
**Status:** FROZEN (M0)
**Date:** 2026-02-25

## Purpose

This document explicitly states what AIR v1 does **not** prove, cannot guarantee, and should not be used to claim. It exists to prevent overstatement of the receipt's security properties and to set correct expectations for implementors, auditors, and regulators.

## Limitations

### L-1: No Proof of Data Destruction

AIR v1 receipts do **not** prove that input data, output data, or intermediate state was deleted after inference.

- The receipt proves what happened (inference executed), not what happened afterward (data destroyed).
- EphemeralML's `DestroyEvidence` struct is a self-report — the workload attests to its own actions. This is NOT cryptographic proof of deletion.
- Provable data destruction is an open research problem in confidential computing. No existing system provides this.

**Correct claim:** "Data was processed inside an attested workload. The receipt proves the inference occurred."
**Incorrect claim:** "The receipt proves data was irrecoverably deleted."

### L-2: Model Hash Proves Identity, Not Correctness

AIR v1 includes a required `model_hash` claim — a SHA-256 of the model weights. This cryptographically binds the receipt to a specific model artifact.

- `model_hash` proves **which** model weights were loaded. A verifier with a known-good hash can confirm exact model identity.
- `model_id` and `model_version` are operator-assigned opaque strings for human readability. They are NOT the cryptographic binding — `model_hash` is.
- `model_hash` does **not** prove the model behaves correctly, is free of bias, or matches a reference specification. It proves byte-level identity of the weights file.
- Attestation documents (Nitro COSE, TDX quotes) measure the workload code/runtime, not the model weights. `model_hash` fills this gap — without it, a compromised workload could load arbitrary weights.
- The optional `model_hash_scheme` claim (key -65549) declares how model_hash was computed. Defined values: `"sha256-single"`, `"sha256-concat"`, `"sha256-manifest"`. When absent, the hash is opaque. Implementations are RECOMMENDED to include this claim for reproducibility.

**Correct claim:** "The receipt cryptographically identifies the exact model weights used via model_hash."
**Incorrect claim:** "The receipt proves the model is unbiased/correct/safe."

### L-3: Attestation Document NOT Verified by Receipt

The `attestation_doc_hash` is a SHA-256 hash of the platform's attestation document. AIR v1 includes this hash as a claim but does **not** define how to verify the attestation document itself.

- Nitro attestation documents require COSE signature verification against AWS's root CA.
- TDX quotes require DCAP collateral verification against Intel's PCS.
- This verification is platform-specific and out of scope for the receipt format.

**What this means:** A valid AIR v1 receipt proves the receipt was signed by a specific key. It does NOT by itself prove the signing key was inside a genuine TEE. That proof requires independent attestation document verification.

### L-4: No Input/Output Confidentiality from Receipt

The receipt contains SHA-256 hashes of the request and response. These hashes are in the clear.

- If the input space is small or predictable, an observer with the receipt could brute-force the request_hash to recover the input.
- The receipt is a proof artifact, not a confidentiality mechanism. Transport encryption protects data in transit; the receipt is for after-the-fact verification.

### L-5: No Defense Against TEE Hardware Compromise

AIR v1's security rests on the assumption that the TEE hardware is correct (TA-1 in threat-model.md).

- If a TEE implementation has a hardware bug, firmware vulnerability, or supply-chain compromise, all receipts signed by affected workloads are suspect.
- AIR v1 does not define revocation or invalidation of receipts when a TEE platform is compromised.

### L-6: Clock Integrity Is Platform-Dependent

`execution_timestamp` (mapped to CWT `iat`) comes from the workload's view of system time.

- Nitro enclaves do not have an independent time source — they use the host's clock.
- TDX workloads have access to TSC but may be subject to host-controlled frequency scaling.
- AIR v1 does not guarantee timestamp accuracy beyond what the platform provides.

### L-7: No Pipeline Chaining in v1

AIR v1 defines single-inference receipts only. Multi-stage pipeline receipts with `previous_receipt_hash` chaining are deferred to a future version.

- The v0.1 `previous_receipt_hash` field is NOT carried forward to v1.0.
- Pipeline receipts are tracked under M6 (milestone: Pipeline Receipt Extension).

### L-8: Sequence Number Is Session-Scoped

The `sequence_number` claim is a monotonic counter within a single workload session. It resets when the workload restarts.

- Verifiers cannot use sequence_number to detect gaps across sessions.
- Cross-session ordering requires external mechanisms (e.g., transparency logs, SCITT).

### L-9: No Regulatory Certification

AIR v1 is a technical specification. It is **not** certified, accredited, or endorsed by any regulatory body.

- AIR v1 is designed to support compliance evidence (e.g., HIPAA 164.312 audit controls, EU AI Act Article 12 logging).
- Using AIR receipts does not automatically satisfy any regulatory requirement.

**Correct claim:** "AIR receipts provide evidence that may support compliance with [specific regulation]."
**Incorrect claim:** "AIR receipts make you HIPAA-compliant."
