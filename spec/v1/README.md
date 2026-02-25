# Attested Inference Receipt (AIR) — Specification v1

A cryptographically signed proof that an ML inference was executed inside a hardware-attested confidential workload.

## Status

**v1.0:** FROZEN — All normative documents locked. Issue #80 (model_hash_scheme) resolved.

## Documents

| Document | Description |
|----------|-------------|
| [naming.md](naming.md) | Standard name (AIR) and versioning policy |
| [scope-v1.md](scope-v1.md) | What v1 defines and what it does not |
| [dependencies.md](dependencies.md) | Normative references and MTI algorithms |
| [threat-model.md](threat-model.md) | Trust assumptions and threat analysis |
| [limitations-v1.md](limitations-v1.md) | Explicit non-claims and limitations |
| [claim-mapping.md](claim-mapping.md) | EAT claim mapping and verification semantics |
| [cddl/air-v1.cddl](cddl/air-v1.cddl) | CDDL wire schema |
| [vectors/](vectors/) | Golden test vectors (10 vectors: 2 valid, 8 invalid) |
| [interop-kit.md](interop-kit.md) | Quick-start guide for external implementors |
| [implementation-status.md](implementation-status.md) | Reference implementation status, platform coverage, and known gaps (non-normative) |

## Public Entry Point

Start here if you are evaluating AIR v1 externally:

1. [interop-kit.md](interop-kit.md) — minimum information to build a verifier
2. [cddl/air-v1.cddl](cddl/air-v1.cddl) — wire schema
3. [vectors/](vectors/) — conformance corpus (valid + invalid vectors)
4. [implementation-status.md](implementation-status.md) — current Rust implementation coverage and gaps
5. [limitations-v1.md](limitations-v1.md) — explicit non-claims

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

## IETF Prep (Non-Normative)

These documents are M4/M5 preparation artifacts and are **not** part of the AIR v1 normative specification:

- [ietf/README.md](ietf/README.md)
- [ietf/air-v1-rats-draft-outline.md](ietf/air-v1-rats-draft-outline.md)
- [ietf/rats-intro-email-draft.md](ietf/rats-intro-email-draft.md)

## License

CC BY 4.0 — See [LICENSE](LICENSE).
