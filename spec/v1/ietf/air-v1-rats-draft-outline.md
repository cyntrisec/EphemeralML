# AIR v1 (`-00`) — RATS Internet-Draft Outline (Draft)

**Working title (proposed):**  
Attested Inference Receipt (AIR): A COSE/CWT Profile for Confidential AI Inference

**Intended status (proposed):** Informational (initially), with a path to Standards Track after WG feedback  
**Likely venue:** IETF RATS (Remote ATtestation Procedures)

This is a non-normative authoring outline for M5 preparation.

## 1. Draft Metadata (placeholder)

- `draft-<author>-rats-air-receipts-00`
- Authors: TBD
- WG adoption status: Individual draft (pre-adoption)

## 2. Abstract (draft shape)

Define AIR, a COSE_Sign1/CWT/EAT-based receipt format for a single confidential AI inference.
An AIR receipt binds model identity, input/output hashes, and attestation-linked execution metadata
to a cryptographic signature. This document specifies the AIR v1 claim set, encoding, and verifier
behavior for interoperability.

## 3. Problem Statement (Introduction)

Key points:

- Existing attestation mechanisms prove platform identity, but not a portable per-inference receipt format.
- AI deployments in regulated environments need interoperable cryptographic evidence for individual inference events.
- Current implementations are typically vendor-specific and not reusable across tools/auditors.

What AIR standardizes:

- receipt wire format
- claim semantics
- verifier checks

What AIR does not standardize (v1):

- pipeline proof chaining
- transparency logging (SCITT)
- compliance certification
- cryptographic deletion proof

## 4. Terminology and Roles

Reference:

- RFC 9334 (RATS architecture)
- RFC 9711 (EAT)

Terms to define:

- AIR receipt
- Attester
- Verifier
- Relying party
- `cti`
- `model_hash`
- `model_hash_scheme`
- `measurement_type`

## 5. AIR v1 Receipt Format

### 5.1 Envelope

- COSE_Sign1 (RFC 9052)
- Tagged CBOR (tag 18)
- Protected header requirements:
  - `alg = EdDSA (-8)`
  - `content_type = application/cwt (61)`

### 5.2 Payload

- CWT claims + EAT profile identification + AIR private claims
- Integer key map
- Deterministic CBOR encoding expectations (implementation behavior)

### 5.3 CDDL

Include or reference CDDL from:

- `spec/v1/cddl/air-v1.cddl`

## 6. Claim Semantics

Reference:

- `spec/v1/claim-mapping.md`

Sections:

- Standard CWT/EAT claims (`iss`, `iat`, `cti`, `eat_nonce`, `eat_profile`)
- AIR private claims
- `enclave_measurements` variants (`nitro-pcr`, `tdx-mrtd-rtmr`)
- `model_hash_scheme` extensibility and fail-closed behavior for unknown values

## 7. Verification Procedure (Normative)

Structure to mirror the implemented four-layer verifier:

1. Parse (COSE/CBOR shape)
2. Crypto (Sig_structure1 + signature verification)
3. Claim validation (required claims, lengths, allowlists)
4. Policy evaluation (freshness, nonce, platform, expected model hash)

Need explicit statements on:

- fail-closed behavior
- optional policy checks vs mandatory format checks
- replay handling (`cti`) requiring verifier-side state

## 8. Error Reporting and Diagnostics

Likely non-normative but useful:

- structured error codes in reference implementation (`AirCheckCode`)
- mapping to verifier layers
- note that code strings are implementation diagnostics, not protocol fields

## 9. Security Considerations

Must include:

- AIR proves receipt integrity and attestation-linked metadata, not truth of arbitrary claims beyond the attestation trust base
- replay detection requires verifier state / nonce policy
- `model_hash_scheme` unknown values must be rejected if present
- attestation verification quality depends on platform-specific verifier implementation
- AIR v1 does not define pipeline chaining
- AIR v1 does not provide cryptographic deletion proof

## 10. Privacy Considerations

Cover:

- input/output are represented as hashes (not plaintext)
- hashes may still be sensitive for low-entropy inputs
- nonce, timestamps, and identifiers may leak correlation metadata

## 11. IANA Considerations

Initial options:

- `No IANA actions` (for `-00`)
- future work may consider registry/registration for AIR profile identifiers or claim allocation strategy

## 12. Interoperability Considerations / Implementation Status

Reference current artifacts:

- frozen spec (`m3-spec-frozen`)
- CDDL
- golden vectors (2 valid + 8 invalid)
- Rust reference verifier
- implementation status doc

This section should be updated after at least one external interop run.

## 13. Examples

Include:

- valid minimal AIR receipt example (possibly truncated/annotated)
- invalid example cases described via vector references

Avoid embedding large blobs in the draft if not needed.

## 14. Appendix (Optional)

- Mapping from legacy EphemeralML internal receipt v0.1 to AIR v1
- rationale for single-inference-only scope

## Pre-Submission Checklist (M5)

- [ ] External interop run completed (M4)
- [ ] Public implementation-status document published
- [ ] Draft text converted to `xml2rfc` / `kramdown-rfc`
- [ ] Security and privacy considerations reviewed
- [ ] `idnits` run and issues triaged
- [ ] Links to spec, vectors, and reference verifier included

