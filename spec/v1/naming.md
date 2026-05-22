# Standard Name and Versioning Policy

**Issue:** #63
**Status:** FROZEN (M0)
**Date:** 2026-02-25

## Standard Name

**Attested Inference Receipt (AIR)**

### Rationale

- **Neutral:** Does not reference EphemeralML, Cyntrisec, or any vendor.
- **Descriptive:** "Attested" (hardware-backed), "Inference" (ML scope), "Receipt" (proof artifact).
- **Compact:** Three words, pronounceable acronym (AIR).
- **Domain-searchable:** No collision with existing IETF/W3C/ISO standards.

### Rejected Alternatives

| Name | Rejection Reason |
|------|-----------------|
| Attested Execution Receipt (AER) | Too generic — covers any workload, not ML-specific |
| Confidential Inference Token (CIT) | "Token" overloaded (JWT, access tokens, ML tokens) |
| Trusted Inference Proof (TIP) | "Trusted" implies trust assumption; we prove, not trust |
| EphemeralML Receipt | Vendor-specific, blocks third-party adoption |

## Profile Version Scheme

AIR is versioned by **profile**, not by wire-compatible minor versions. Each
profile version is a complete, closed wire-format specification with its own
`eat_profile` URI.

### Rules

1. **AIR v1** is the first standardized profile (replacing EphemeralML's
   internal v0.1 format).
2. AIR v1 is a closed profile. Its claim map, protected header shape,
   unprotected header shape, `measurement_type` values, and
   `model_hash_scheme` values are fixed by the v1 specification.
3. A conformant AIR v1 verifier MUST reject receipts that carry unknown claim
   keys, unknown profile identifiers, or values outside the v1 closed sets.
4. Any wire-format change — including a new claim, a new measurement type, a
   new model-hash scheme, a new signing-algorithm option, or a new required
   header parameter — requires a new profile with a new `eat_profile` URI.
5. The next profile after AIR v1 is AIR v2.

## EAT Profile URI

The `eat_profile` claim (EAT RFC 9711) identifies which specification governs the receipt:

```
https://spec.cyntrisec.com/air/v1
```

### URI Structure

```
https://spec.cyntrisec.com/air/v{profile}
```

- Profile version in the URI; there are no wire-compatible minor versions.
- The URI is an identifier, not necessarily a fetchable URL (per EAT convention).
- Once v1 is adopted by a standards body (e.g., IETF), the URI migrates to that body's namespace.

## File Naming Convention

Spec documents use the pattern:

```
spec/v1/<document-name>.md     — prose specification
spec/v1/cddl/<name>.cddl       — CDDL schema fragments
spec/v1/vectors/<category>/     — test vectors (CBOR files)
```
