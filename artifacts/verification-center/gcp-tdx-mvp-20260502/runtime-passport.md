# Cyntrisec Runtime Passport

Passport ID: `rpass_846be4a8-5019-4627-aefc-a23f73e3f59f`

Status: `Partial`

Passport SHA-256: `c4f8f4fcd0e7cd151020d6a771451dc568a3018f4fe5aee048cd165a408c23e9`

## Runtime

- Provider: `gcp`
- Runtime type: `gcp-tdx`
- Region: `us-central1`
- Instance type: `c3-standard-4`

## Components

- Doctor: `Unknown` (doctor JSON not supplied)
- Smoke test: `Unknown` (smoke-test JSON not supplied)
- Compliance policy: `Pass` (All 16 rules passed for profile 'baseline')

## Measurements

- measurement_type: `tdx-mrtd-rtmr`
- pcr0: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
- pcr1: `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
- pcr2: `cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc`
- mrtd: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
- rtmr0: `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
- rtmr1: `cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc`
- attestation_doc_hash: `791ceb1be5c52def2cca3dc6413ffa792ae0ed5cef38d5d63b1eb549bea6acda`
- request_hash: `f4a68967743b669666516beb4efbd4c9b33025a0215257734c225b977a24ddb0`
- response_hash: `baac9798d5b94282d5a97ef2e67789d4d5cf508b5c4de14eeba862d5f42ecb49`

## Checks

| Layer | Check | Status | Detail |
|---|---|---|---|
| policy | Ed25519 signature verification | Pass | Ed25519 signature verified (strict) |
| policy | CBOR canonical round-trip determinism | Pass | Canonical encoding is deterministic |
| policy | Attestation document present | Pass | Attestation evidence item found in bundle |
| policy | Attestation hash matches receipt | Pass | SHA-256(attestation) == receipt.attestation_doc_hash |
| policy | Measurements are 48 bytes | Pass | All PCR/MRTD measurements are 48 bytes |
| policy | Recognized measurement type | Pass | Measurement type 'tdx-mrtd-rtmr' is recognized |
| policy | Receipt within max age | Pass | Receipt age 113s <= max 3600s |
| policy | Receipt not future-dated | Pass | Receipt timestamp is not in the future |
| policy | Model ID present | Pass | model_id = 'minilm-l6-v2' |
| policy | Model manifest present in bundle | Pass | ModelManifest evidence item found |
| policy | Receipt chain hash valid | Pass | No previous_receipt_hash (single receipt or first in chain) |
| policy | CBOR deterministic encoding | Pass | CBOR canonical round-trip produces identical bytes |
| policy | Signing key bound to attestation | Pass | signing-key-attestation binding found |
| policy | Policy version present | Pass | policy_version = 'v1-default' |
| policy | Sequence numbers increasing | Pass | Single receipt with sequence_number=0 |
| policy | Destroy evidence present | Pass | Destroy evidence present with 5 action(s) |
| platform | Platform evidence adapter | Pass | gcp / gcp-tdx adapter_version=1 |

## Limitations

- **not_compliance_determination:** Verification output is technical evidence, not a legal or regulatory compliance determination.
- **no_model_quality_claim:** Verification does not prove model accuracy, fairness, safety, clinical correctness, or business appropriateness.
- **no_deletion_proof:** Verification does not prove irrecoverable deletion of all possible copies.
- **raw_content_not_required:** Input and output content are represented by hashes by default; raw content is not required for receipt verification.
- **runtime_probe_json_not_supplied:** This gcp-tdx passport was generated from verifier/compliance evidence, not from BYOC doctor/smoke-test runtime probe JSON. Do not use it as evidence that those BYOC probes passed.
