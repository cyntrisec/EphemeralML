# Cyntrisec Runtime Passport

Passport ID: `rpass_4bd27e1d-605d-4908-a1b1-4d69d6325e36`

Status: `Pass`

> Warning: this passport has reviewer-visible limitations:
> - **unsigned_eif_internal_poc:** Doctor EIF verification passed under CYNTRISEC_DOCTOR_ALLOW_UNSIGNED_EIF_FOR_POC because the host lacks an adjacent cosign bundle. This is acceptable only for internal PoC evidence and must be closed before production buyer evidence.

Passport SHA-256: `20b69eec5fec2b905878c865c613ed31005fcb2835d22a91c5564394a99b55f9`

## Runtime

- Provider: `aws`
- Runtime type: `aws-nitro`
- Region: `us-east-1`
- Instance type: `m7i.xlarge`

## Components

- Doctor: `Pass` (6/6 doctor checks passed)
- Smoke test: `Pass` (bundle-derived smoke result: manifest_status=pass, required_files=12/12, negative_tests=3/3)

## Measurements

- measurement_type: `nitro-pcr`
- pcr0: `184b2a72e7bbe6d84dfddc586d3ce7ecc49085c044f31594e67042b6a5ff4e010f7a2052e430190b6bb54762059c4b21`
- pcr1: `4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493`
- pcr2: `46dc284c9e5c517f8a7bebf30cf041565dfb2a5682f87cab430f2ded1a235d2f599853a51f55eaa98495573471427c21`
- eif_sha384: `184b2a72e7bbe6d84dfddc586d3ce7ecc49085c044f31594e67042b6a5ff4e010f7a2052e430190b6bb54762059c4b21`

## Checks

| Layer | Check | Status | Detail |
|---|---|---|---|
| runtime | Doctor: allocator | Pass |  |
| runtime | Doctor: eif | Skip | unsigned_internal_poc=true; cosign_verified=false |
| runtime | Doctor: role | Pass |  |
| runtime | Doctor: bucket | Pass |  |
| runtime | Doctor: kms | Pass |  |
| runtime | Doctor: clock | Pass |  |
| runtime | Smoke test bundle manifest | Pass | manifest_status=pass, bundle_type_ok=true, required_files_missing=0, negative_tests=3/3 |
| platform | Platform evidence adapter | Pass | aws / aws-nitro adapter_version=1 |

## Limitations

- **not_compliance_determination:** Verification output is technical evidence, not a legal or regulatory compliance determination.
- **no_model_quality_claim:** Verification does not prove model accuracy, fairness, safety, clinical correctness, or business appropriateness.
- **no_deletion_proof:** Verification does not prove irrecoverable deletion of all possible copies.
- **raw_content_not_required:** Input and output content are represented by hashes by default; raw content is not required for receipt verification.
- **unsigned_eif_internal_poc:** Doctor EIF verification passed under CYNTRISEC_DOCTOR_ALLOW_UNSIGNED_EIF_FOR_POC because the host lacks an adjacent cosign bundle. This is acceptable only for internal PoC evidence and must be closed before production buyer evidence.
