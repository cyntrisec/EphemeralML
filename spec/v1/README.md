# Attested Inference Receipt (AIR) — Specification v1

A cryptographically signed proof that an ML inference was executed inside a hardware-attested confidential workload.

## Status

**v1.0:** M0 FROZEN — Charter & Scope locked. M1 implementation unblocked.

## Documents

| Document | Description |
|----------|-------------|
| [naming.md](naming.md) | Standard name (AIR) and versioning policy |
| [scope-v1.md](scope-v1.md) | What v1 defines and what it does not |
| [dependencies.md](dependencies.md) | Normative references and MTI algorithms |
| [threat-model.md](threat-model.md) | Trust assumptions and threat analysis |
| [limitations-v1.md](limitations-v1.md) | Explicit non-claims and limitations |
| [claim-mapping.md](claim-mapping.md) | EAT claim mapping and verification semantics (M1) |
| [cddl/air-v1.cddl](cddl/air-v1.cddl) | CDDL wire schema (M1) |

## Format

AIR v1 receipts are COSE_Sign1 envelopes (RFC 9052) carrying CWT claims (RFC 8392) with EAT profile identification (RFC 9711). Signed with Ed25519 (RFC 8032, verify_strict).

## Directories

```
spec/v1/
├── cddl/           CDDL schema fragments (RFC 8610)
├── vectors/
│   ├── valid/      Golden test vectors (valid receipts)
│   └── invalid/    Negative test vectors
├── LICENSE         CC BY 4.0
└── README.md       This file
```

> **Note:** A `vectors/pipeline/` directory exists for future use (vNEXT — pipeline chaining extension). It is **not** part of AIR v1 conformance scope.

## Prior Version

[spec/receipt-v0.1.md](../receipt-v0.1.md) — EphemeralML internal format (FROZEN, superseded by AIR v1).

## License

CC BY 4.0 — See [LICENSE](LICENSE).
