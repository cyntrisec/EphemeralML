# AIR Proof Boundary

This document is the customer-facing boundary for AIR verification claims. It explains what an Attested Inference Receipt proves, what it does not prove, and which verifier inputs are required for production assurance.

## Short Version

AIR is not a "100% security layer." It is a cryptographic evidence layer. It gives customers a signed, offline-verifiable record of a specific inference event, but the strength of the conclusion depends on the verification policy used.

A green AIR-local signature check proves only that a receipt was signed by the corresponding AIR signing key and that the receipt structure is valid. Stronger claims, such as "this request ran inside an accepted TEE under expected measurements using the expected model artifact set," require additional policy inputs and platform-attestation checks.

## What AIR Proves

When a verifier checks the AIR receipt signature and claim structure, AIR proves:

- The receipt bytes were signed by the AIR private key corresponding to the supplied public key.
- The signed receipt contains the model identity, request hash, response hash, timing, memory, attestation-document hash, and other AIR claims.
- Any change to the signed claims after issuance is detected.
- The receipt conforms to AIR's closed claim map, deterministic CBOR expectations, and fail-closed parsing rules.

When the verifier also checks policy inputs, AIR can additionally prove:

- The receipt's `model_hash` matches a customer-approved model artifact set or known-good model identity value.
- The receipt's `request_hash` matches the customer's submitted request.
- The receipt's `response_hash` matches the response the customer received.
- The receipt is fresh enough under verifier policy, using `iat`, `cti` deduplication, and, where used, verifier-supplied `eat_nonce`.
- The receipt's `security_mode` is acceptable for the verifier's deployment policy.

When the verifier also checks platform evidence and key binding, AIR can support an end-to-end TEE provenance conclusion:

- The platform attestation document hash in the receipt matches the independently obtained platform evidence.
- The platform evidence verifies under the platform's trust chain and expected measurements.
- The AIR signing key is cryptographically bound to the accepted platform evidence.

## What AIR Does Not Prove By Itself

AIR does not by itself prove every security property a customer may care about.

AIR-local verification alone does not prove:

- The workload actually ran in a TEE.
- The AIR signing key was generated inside a TEE.
- The model artifact set was loaded or executed correctly.
- The customer-approved model was used, unless `expected_model_hash` or an equivalent model policy is supplied.
- The receipt is fresh, unless freshness policy is applied.
- The receipt corresponds to the customer's request or response, unless those hashes are recomputed and checked.
- The cloud operator could not affect availability, scheduling, network delivery, or billing metadata.
- The underlying TEE hardware, firmware, platform verifier, or endorsement chain is flawless.

AIR also does not prove cryptographic deletion of customer data. It can provide evidence of short-lived processing, key/session handling, and signed execution metadata, but deletion and retention claims must be handled by the broader system design and operational controls.

## Minimum Production Verification Profile

A production verifier should require the following before presenting a customer-facing "TEE-backed verified inference" result:

- AIR signature verification succeeds using a trusted AIR public key.
- Receipt structure validation succeeds with no unknown claims, unknown `model_hash_scheme`, or unknown `security_mode`.
- `security_mode` is `production`; `evaluation` receipts are rejected for production trust decisions.
- `model_hash` matches the customer's approved model artifact set or known-good model identity policy.
- `request_hash` matches the original request payload if the customer has the request.
- `response_hash` matches the returned response payload if the customer has the response.
- `iat` is within the configured freshness window.
- `cti` has not been seen before by the verifier, if replay state is available.
- `eat_nonce` matches a verifier-supplied nonce for challenge/response deployments.
- `attestation_doc_hash` matches independently obtained platform evidence.
- Platform evidence is appraised by a RATS/platform verifier against expected measurements, endorsements, and reference values.
- The AIR signing key is bound to the accepted platform evidence for deployments claiming TEE provenance.

If any of these checks are skipped, the verifier result should say which assurance layer was skipped.

## Common Unsafe Configurations

The following configurations can produce a green-looking result while leaving a customer less protected than expected:

- Verifying only the AIR signature and not supplying `expected_model_hash`.
- Trusting `model_id` without checking `model_hash`.
- Accepting a receipt without checking freshness or replay state.
- Accepting `security_mode = "evaluation"` in a production verifier.
- Treating `attestation_doc_hash` as proof of TEE execution without obtaining and appraising the referenced attestation document.
- Treating a public key as TEE-backed without checking key binding.
- Displaying "hash binding" or "attestation-linked execution" in UI when the submitted verification request did not include the corresponding policy inputs or attestation evidence.

## Recommended UI Language

Use precise status labels:

- `AIR signature verified`: signature and receipt structure passed.
- `Model binding verified`: `model_hash` matched the configured model policy.
- `Request binding verified`: `request_hash` matched the submitted request.
- `Response binding verified`: `response_hash` matched the returned response.
- `Freshness verified`: `iat`, `cti`, and/or verifier-supplied `eat_nonce` policy passed.
- `TEE provenance verified`: platform evidence appraisal and AIR signing-key binding passed.

Avoid broad labels such as `100% secure`, `cryptographic deletion proof`, or `no cloud trust required`.

Preferred customer claim:

> AIR reduces reliance on cloud operators by providing signed, offline-verifiable inference evidence. Full TEE-backed assurance requires receipt verification, model/request/response policy checks, platform attestation appraisal, and AIR signing-key binding.
