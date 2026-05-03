# Cyntrisec Verification Report

Report ID: `vrpt_b7420760-a297-40de-9403-b263480e9fbf`

Status: `Pass`

Assurance level: `tee_provenance`

Report SHA-256: `d84be7201028379afcae6fe2c5d22523046829bfe815c10041725d7ffcf6be48`

> Warning: this report has reviewer-visible limitations:
> - **runtime_passport_unsigned_eif_internal_poc:** Runtime Passport limitation: Doctor EIF verification passed under CYNTRISEC_DOCTOR_ALLOW_UNSIGNED_EIF_FOR_POC because the host lacks an adjacent cosign bundle. This is acceptable only for internal PoC evidence and must be closed before production buyer evidence.

## Receipt

- Receipt ID: `18d1ec19-0e27-497c-b187-fc44a148249c`
- Model: `stage-0`
- Security mode: `production`
- Platform: `nitro-pcr`
- Receipt SHA-256: `c1bfd0b9f805945a3305ea57866a97bcaaf99c80a34eed91280b5353fbed7603`

## Checks

| Layer | Check | Status | Detail |
|---|---|---|---|
| parse | COSE envelope | Pass |  |
| parse | Algorithm header | Pass |  |
| parse | Content type | Pass |  |
| parse | Payload present | Pass |  |
| parse | AIR v1 profile | Pass |  |
| crypto | Signature (Ed25519) | Pass |  |
| claim | Receipt ID valid | Pass |  |
| claim | Model hash non-zero | Pass |  |
| claim | Measurements present | Pass |  |
| claim | Measurement type valid | Pass |  |
| claim | Model hash scheme | Pass |  |
| claim | Security mode valid | Pass |  |
| policy | Timestamp freshness | Pass |  |
| policy | Model hash match | Pass |  |
| policy | Request hash match | Skip |  |
| policy | Response hash match | Skip |  |
| policy | Verification check | Pass |  |
| policy | Model ID match | Pass |  |
| policy | Security mode policy | Pass |  |
| policy | Platform match | Pass |  |
| policy | Nonce match | Skip |  |
| policy | Replay detection | Skip |  |
| runtime | Platform attestation sidecar | Pass | attestation sidecar supplied; AIR ADHASH check binds the receipt to this sidecar |
| runtime | Receipt signing key binding | Pass | receipt public key matches the key carried by the attestation sidecar |
| evidence | Attestation provenance | Pass | attestation_provenance=bundle |

## Limitations

- **not_compliance_determination:** Verification output is technical evidence, not a legal or regulatory compliance determination.
- **no_model_quality_claim:** Verification does not prove model accuracy, fairness, safety, clinical correctness, or business appropriateness.
- **no_deletion_proof:** Verification does not prove irrecoverable deletion of all possible copies.
- **raw_content_not_required:** Input and output content are represented by hashes by default; raw content is not required for receipt verification.
- **runtime_passport_unsigned_eif_internal_poc:** Runtime Passport limitation: Doctor EIF verification passed under CYNTRISEC_DOCTOR_ALLOW_UNSIGNED_EIF_FOR_POC because the host lacks an adjacent cosign bundle. This is acceptable only for internal PoC evidence and must be closed before production buyer evidence.
