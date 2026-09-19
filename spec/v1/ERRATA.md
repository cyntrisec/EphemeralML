# AIR v1.0 Errata

AIR v1.0 remains frozen. This file records accepted corrections to
inconsistencies in the frozen documents; it does not define new claims,
algorithms, measurement types, or profile identifiers.

## E-1: `eat_nonce` length constraint

- **Status:** Accepted
- **Recorded:** 2026-09-19
- **Affected documents:** `cddl/air-v1.cddl`, `claim-mapping.md`,
  `dependencies.md`, and `interop-kit.md`

The original CDDL declared optional `eat_nonce` as an unrestricted byte
string:

```cddl
? 10 => bstr
```

The corrected declaration is:

```cddl
? 10 => bstr .size (8..64)
```

RFC 9711 Section 4.1 limits a nonce to 8 through 64 bytes. The AIR reference
encoder and parser already enforce this range, and the published AIR `-02`
Internet-Draft carries the same constraint. The omission was therefore a
schema/documentation inconsistency rather than an implementation or wire
encoding change. Existing conformant receipts and golden vectors are
unchanged; a receipt containing an out-of-range nonce is rejected.
