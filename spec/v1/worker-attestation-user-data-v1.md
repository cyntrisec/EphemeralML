# Cyntrisec Worker Attestation user_data v1

## Status

v1.0 FROZEN. Future changes require a new schema version.

## Purpose

This schema defines the application-level `user_data` bytes embedded in worker TEE attestation documents.

`confidential-ml-transport` verifies the generic TEE channel and exposes opaque attestation `user_data` bytes. Cyntrisec components decode those bytes as `WorkerAttestationUserData` to bind the attested worker channel to:

- the Ed25519 receipt signing public key,
- the model identifier,
- the model hash.

This schema is adjacent to AIR v1. AIR receipts prove an inference; worker attestation `user_data` proves which worker identity was bound into the attested channel before inference.

## Wire Format

The wire format is deterministic CBOR array:

```text
[
  1,                     ; schema_version
  bstr .size 32,          ; receipt_signing_pubkey, Ed25519 raw public key
  tstr,                   ; model_id
  bstr .size 32           ; model_hash, SHA-256 over canonical model-manifest.json bytes
]
```

CDDL: [cddl/worker-attestation-user-data-v1.cddl](cddl/worker-attestation-user-data-v1.cddl)

## Verification Rules

- Verifiers MUST reject any `schema_version` other than `1`.
- Verifiers MUST reject public keys or hashes that are not exactly 32 bytes.
- v1 fields MUST NOT be extended in place. Add a v2 schema for any breaking or additive change.
