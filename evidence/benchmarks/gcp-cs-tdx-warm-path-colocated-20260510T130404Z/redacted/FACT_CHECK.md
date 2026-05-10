# Fact Check: GCP Warm-Path Benchmark

Date: 2026-05-10 UTC

Artifact: `gcp-cs-tdx-warm-path-colocated-20260510T130404Z`

## Verdict

The benchmark supports this claim:

> Full AIR v1 receipt creation on the measured GCP Confidential Space warm path was about 47-49 microseconds, or about 0.07-0.08% of MiniLM-class embedding inference time, for concurrency 1 over a same-zone private VPC path.

The previously used 42-44 microsecond figure is a lower-bound decomposition using raw Ed25519 signing only. It is useful for explaining the split, but the quoteable full AIR creation number is 47-49 microseconds.

## What Was Checked

- Handshake is excluded: `benchmark_gcp_warm_path` calls `establish_channel()` before warmup and measurement.
- Warmup is excluded: 10 warmup requests per session are sent before any measured samples are recorded.
- Sample size is 120 measured requests for each prompt size: short, medium, long.
- AIR stage timings are produced inside `enclave/src/server.rs`, not inferred from client wall time.
- Client AEAD timings are produced by `confidential-ml-transport` timing hooks and added by the benchmark runner.
- The committed JSONL has `git_sha=0bab82b` for all 363 records.
- The redacted artifact does not contain the GCP project ID, project number, public IPs, private IPs, AWS account IDs, ARNs, or private keys.

## What Influences The Numbers

- This run bypasses the OpenAI HTTP gateway and measures the direct SecureChannel backend path.
- This run uses MiniLM-class embedding inference, not autoregressive LLM generation and not H100 GPU inference.
- Benchmark mode adds timing metadata to the response body; production responses should not expose this timing channel.
- MRTD pinning was disabled for measurement convenience, so this is performance evidence, not production policy evidence.
- `environment.host` in the JSONL is the same-zone benchmark client VM. Backend metadata is recorded in `SUMMARY.md`.
- `response_encrypt` is not captured for the exact same response because the response is encrypted after the benchmark record is serialized.
- Residual wall time includes response JSON serialization, server response AEAD seal, TCP/VPC scheduling, client response JSON parse/receipt validation, server logging, and benchmark metadata overhead.

## Correct AIR Accounting

Quoteable full AIR creation:

`air_claim_validate + air_claims_cbor_encode + air_cose_create_signature + air_serialize`

| Prompt | Full AIR total us | Full AIR / wall | Full AIR / inference |
|---|---:|---:|---:|
| short | 46.809 | 0.0732% | 0.0748% |
| medium | 47.966 | 0.0731% | 0.0747% |
| long | 48.525 | 0.0690% | 0.0712% |

Lower-bound decomposition:

`air_build + air_sign + air_serialize`

This excludes about 4.9-5.0 microseconds of COSE Sig_structure preparation around the raw Ed25519 signing callback, so it should not be used as the full AIR creation number.

## Cross-Check

A local isolated AIR microbenchmark at the current head (`3b8d076`) with 10,000 iterations and a 10,240-byte synthetic payload measured:

- `air_build_full_us` mean: 46.794 microseconds
- `air_claims_cbor_encode_us` mean: 23.513 microseconds
- `air_verify_full_policy_us` mean: 49.340 microseconds

That independently supports the same tens-of-microseconds AIR cost range. Differences from the GCP run are expected because CPU host, claim set shape, and measurement placement differ.
