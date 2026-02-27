# AIR v1.0 — Release Note

**Date:** 2026-02-25
**Tag:** `air-v1.0-frozen`

## Summary

Attested Inference Receipt (AIR) v1.0 is the first frozen release of the receipt specification for confidential AI inference. It defines a COSE_Sign1 envelope carrying CWT claims with EAT profile identification, signed with Ed25519.

## What's in this release

### Normative documents (all FROZEN)

| Document | Description |
|----------|-------------|
| `scope-v1.md` | What v1 defines and what it does not |
| `claim-mapping.md` | 18 claims (16 required + 2 optional) mapped to CWT/EAT integer keys with verification semantics |
| `dependencies.md` | 7 normative RFCs, MTI algorithms, crate dependencies |
| `threat-model.md` | 13 threats analyzed with trust assumptions |
| `limitations-v1.md` | 9 explicit non-claims (L-1 through L-9) |
| `naming.md` | Standard name and versioning policy |
| `cddl/air-v1.cddl` | Formal CDDL schema (RFC 8610) |
| `interop-kit.md` | Quick-start for external implementors |

### Golden test vectors (10 total)

| Category | Count | Description |
|----------|-------|-------------|
| Valid | 2 | Nitro (no nonce) + TDX (with nonce) |
| Invalid — structural | 4 | Wrong key, wrong alg, zero model_hash, bad measurement length |
| Invalid — policy | 4 | Nonce mismatch, model_hash mismatch, platform mismatch, stale iat |

### Reference implementation

- `ephemeral-ml-common` crate: `build_air_v1()`, `parse_air_v1()`, `verify_air_v1()`
- 240 tests in `common` (224 unit + 16 conformance vector tests)
- 574 total tests across the workspace

## Key decisions

1. **COSE_Sign1 envelope** (not custom CBOR) — interoperable with existing COSE libraries
2. **CWT claims with EAT profile** — standard claim IDs, profile URI for receipt identification
3. **Ed25519 verify_strict** — single MTI algorithm, no negotiation
4. **Negative integer keys** for private claims (-65537 to -65549) — avoids IANA collision
5. **Issue #80 resolved**: `model_hash_scheme` (key -65549) is optional, RECOMMENDED. Three defined values: `sha256-single`, `sha256-concat`, `sha256-manifest`.
6. **Tier 1+2 parse hardening** (2026-02-28): Pre-parse size limit (64 KB), unprotected header rejection, duplicate CBOR key detection, iat=0 rejection, text claim length bounds, pcr8/TDX cross-check, security_mode allowlist, `current_timestamp()` error propagation. 12 new tests added. Wire format unchanged; golden vectors byte-stable.

## Breaking changes from v0.1

- Receipt format is a clean break from `spec/receipt-v0.1.md`
- `receipt_id` (text UUID) → `cti` (16-byte bstr)
- `protocol_version` (uint) → `eat_profile` (URI string)
- Signature moved from claims map to COSE_Sign1 envelope
- `previous_receipt_hash` removed (pipeline chaining deferred to vNEXT)
- `model_hash` is new (required) — no v0.1 equivalent

## What's NOT in v1.0

See `limitations-v1.md` for the full list. Key items:
- No pipeline chaining (deferred to vNEXT)
- No proof of data destruction
- No attestation document verification (platform-specific, out of scope)
- No AMD SEV-SNP or ARM CCA measurements (may be added in v1.x)

## v1.x extension rules

1. New optional claims may use keys -65550 to -65599
2. New claims must not be required
3. New measurement_type variants may be added
4. Protected header must not gain new required fields
5. New `model_hash_scheme` values may be registered
