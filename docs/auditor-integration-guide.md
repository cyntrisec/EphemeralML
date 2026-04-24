# AIR Receipt Guide for Auditors and Compliance Reviewers

This guide explains what an Attested Inference Receipt (AIR) helps an auditor
answer without requiring COSE, CWT, or remote-attestation expertise.

## What AIR Is

An AIR receipt is a signed record for one inference request. It is meant to be
kept with the business record for that inference, the same way an approval log
or access-control decision is kept with an operational event.

AIR answers narrow evidence questions:

| Audit question | Receipt evidence |
| --- | --- |
| Which model identity was claimed? | `model_id`, `model_version`, `model_hash`, `model_hash_scheme` |
| Which request and response were committed? | `request_hash`, `response_hash` |
| When was the receipt issued? | `iat` |
| Which execution environment was referenced? | `enclave_measurements`, `attestation_doc_hash` |
| Which policy version applied? | `policy_version` |
| Was this a production or evaluation receipt? | `security_mode` |
| Is the receipt signature valid? | COSE_Sign1 Ed25519 signature check |

AIR does not by itself prove that an AI decision was safe, fair, lawful, or
correct. It is execution evidence, not a replacement for model validation,
human review, DPIA, SOC 2 controls, HIPAA safeguards, EU AI Act obligations, or
other governance controls.

## Worked Example

The repository ships a real conformance vector at
`spec/v1/vectors/valid/v1-nitro-no-nonce.json`. It is synthetic test data, not
customer data, but it is a valid signed AIR receipt vector.

Important fields in that example:

| Field | Example value | Auditor interpretation |
| --- | --- | --- |
| `model_id` | `minilm-l6-v2` | The application claimed this model identity. |
| `model_version` | `1.0.0` | The application claimed this model version. |
| `model_hash_hex` | `aaaaaaaa...` | The claimed model artifact-set binding. In production, compare this to an approved model registry value. |
| `request_hash_hex` | `bbbbbbbb...` | A privacy-preserving commitment to the request bytes. It is not the request plaintext. |
| `response_hash_hex` | `cccccccc...` | A privacy-preserving commitment to the response bytes. It is not the response plaintext. |
| `attestation_doc_hash_hex` | `dddddddd...` | Hash reference to platform attestation evidence. The attestation document must be appraised separately for full TEE provenance. |
| `enclave_measurements.measurement_type` | `nitro-pcr` | The measurement profile used for the platform evidence reference. |
| `security_mode` | `production` | This receipt can be evaluated under production policy if all other required checks pass. |

The verifier should be run with policy inputs from the control owner, not only
with the receipt and public key. For example, when model identity matters,
provide the expected model hash. When freshness matters, provide a maximum age
or a verifier-supplied nonce policy. When hardware provenance matters, provide
the platform attestation document and reference measurements.

## Verification Layers

The AIR verifier reports checks in four layers:

| Layer | Plain-English meaning |
| --- | --- |
| Parse | The receipt is well-formed and uses the expected AIR structure. |
| Crypto | The Ed25519 signature verifies against the supplied or attestation-derived public key. |
| Claims | Required receipt claims are present, typed correctly, and not structurally unsafe. |
| Policy | Local expectations match, such as model hash, measurement type, freshness, nonce, or security mode. |

A green AIR-local result means the receipt-local structure, signature, claims,
and configured policy checks passed. Full TEE provenance is stronger: it also
requires accepted platform attestation evidence and a checked key binding
between the AIR signing key and that evidence.

## What to Ask for in an Audit Packet

Ask the system owner for:

| Artifact | Why it matters |
| --- | --- |
| AIR receipt | Per-inference signed evidence. |
| AIR verifier output | Human-readable pass/fail result with check layers. |
| Public key or attestation document | Verification material for the receipt signature. |
| Expected model hash | Reference value from the approved model registry. |
| Freshness policy | Maximum accepted age, nonce policy, or deduplication policy. |
| Platform attestation appraisal result | Evidence that the referenced TEE measurements were accepted. |
| Key-binding evidence | Evidence that the receipt signing key was generated inside or bound to the accepted TEE. |

If the verifier was run with only a receipt and public key, treat the result as
AIR-local verification. Do not treat it as proof that the workload ran under a
specific accepted TEE measurement unless platform attestation and key binding
were also checked.

## Common Failure Modes

| Failure | Auditor meaning |
| --- | --- |
| Signature failure | The receipt was not signed by the expected key, or was modified. |
| Model hash mismatch | The receipt does not match the approved model artifact-set reference. |
| Timestamp stale | The receipt is older than local policy allows. |
| Nonce mismatch | The receipt was not bound to the verifier's challenge. |
| Measurement mismatch | The referenced platform measurement is not an accepted environment. |
| Evaluation security mode | The receipt must not satisfy production trust policy. |

## Control Mapping

AIR evidence is most useful for controls that ask whether a regulated workflow
can reconstruct what happened:

| Control need | AIR contribution |
| --- | --- |
| Model inventory | Binds each inference to a model identity and artifact-set hash. |
| Change management | Shows which policy version and measurement profile were used. |
| Incident response | Provides tamper-evident request/response commitments for later correlation. |
| Third-party risk | Lets a customer verify execution evidence without trusting only vendor logs. |
| Privacy review | Avoids embedding plaintext prompt/response data in the audit artifact. |

AIR should be paired with ordinary governance evidence: model approvals,
dataset documentation, access logs, retention policy, human-review policy,
monitoring, incident response, and compliance sign-off.
