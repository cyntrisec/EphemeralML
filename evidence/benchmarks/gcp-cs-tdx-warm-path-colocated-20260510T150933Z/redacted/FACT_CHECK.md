# Fact Check: GCP Warm-Path Benchmark

Artifact: `gcp-cs-tdx-warm-path-colocated-20260510T150933Z`

## Verdict

The benchmark supports this claim:

> Full AIR v1 receipt creation on the measured GCP Confidential Space warm path was tens of microseconds and below 0.1% of measured MiniLM-class embedding inference time for the measured direct SecureChannel path.

Use the table below for exact quoteable numbers from this artifact.

## Integrity Checks

- Total records: `363`.
- Request records: `360`.
- Summary records: `3`.
- Git SHA: `4fb6df3`.
- Schema version: `2`.
- Stored summary means match recomputed request-level means.

## What Influences The Numbers

- This run bypasses the OpenAI HTTP gateway and measures the direct SecureChannel backend path.
- This run uses MiniLM-class embedding inference, not autoregressive LLM generation and not H100 GPU inference.
- Benchmark mode adds timing metadata to the response body; production responses should not expose this timing channel.
- `environment.host` in the JSONL is the benchmark runner/client host unless context explicitly records backend metadata.
- `response_encrypt` is not captured for the exact same response because the response is encrypted after the benchmark record is serialized.
- Residual wall time includes response JSON serialization, server response AEAD seal, TCP/VPC scheduling, client response JSON parse/receipt validation, server logging, and benchmark metadata overhead.
- MRTD pinning: disabled for performance measurement.

## Correct AIR Accounting

Quoteable full AIR creation:

`air_claim_validate + air_claims_cbor_encode + air_cose_create_signature + air_serialize`

| Prompt | Full AIR total us | Full AIR / wall | Full AIR / inference |
|---|---:|---:|---:|
| short | 48.008 | 0.0752% | 0.0769% |
| medium | 49.042 | 0.0746% | 0.0763% |
| long | 46.692 | 0.0664% | 0.0689% |

Lower-bound decomposition:

`air_build + air_sign + air_serialize`

This excludes COSE Sig_structure preparation around the raw Ed25519 signing callback, so it should not be used as the full AIR creation number.
