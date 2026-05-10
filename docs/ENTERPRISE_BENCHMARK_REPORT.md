# Enterprise Benchmark Report: AIR Receipt Cost

**Status:** current measured evidence
**Benchmark date:** 2026-05-10
**Measured code:** `4fb6df3`
**Published artifact:** `evidence/benchmarks/gcp-cs-tdx-warm-path-colocated-20260510T150933Z/redacted/`
**Artifact commit:** `e5498a2`

## Executive Answer

For the measured GCP Confidential Space warm path, full AIR v1 receipt creation
cost about **47-49 microseconds per inference**. That was below **0.1%** of
measured MiniLM-class embedding inference time across all prompt sizes in the
run.

This is the quoteable claim:

> Full AIR v1 receipt creation on the measured GCP Confidential Space direct
> SecureChannel path was tens of microseconds and below 0.1% of measured
> MiniLM-class embedding inference time.

Do not generalize this number to OpenAI-compatible HTTP gateway latency,
autoregressive LLM generation, H100 GPU inference, or concurrent multi-session
throughput. Those are separate benchmark questions.

## Measurement Boundary

The benchmark measured a direct SecureChannel request path to a GCP Confidential
Space backend, using a same-zone client VM and the backend private IP. It did
not measure the hosted OpenAI-compatible gateway.

| Field | Value |
|---|---|
| Backend | GCP Confidential Space / TDX |
| Backend machine | `c3-standard-4` |
| Backend zone | `us-central1-a` |
| Client runner | same-zone `e2-standard-2` |
| Transport | direct SecureChannel over private IP |
| Model shape | MiniLM-class embedding inference |
| Concurrency | `1` |
| Prompt sizes | 35, 1,024, and 10,240 input bytes |
| Warmup | 10 requests discarded per point |
| Measured requests | 120 per prompt size, 360 total |
| Schema | benchmark schema v2 |
| Mode | development benchmark mode |

Benchmark mode intentionally exposes per-stage timings in the response. That is
a timing side channel and must remain disabled in production responses.

## AIR Cost

The full AIR number includes:

`air_claim_validate + air_claims_cbor_encode + air_cose_create_signature + air_serialize`

This is the correct accounting boundary for receipt creation. The lower-level
`air_build + air_sign + air_serialize` decomposition excludes part of COSE
Sig_structure preparation and should not be quoted as the full AIR cost.

| Prompt | Input bytes | Full AIR total | Full AIR / wall | Full AIR / inference |
|---|---:|---:|---:|---:|
| short | 35 | 48.008 us | 0.0752% | 0.0769% |
| medium | 1,024 | 49.042 us | 0.0746% | 0.0763% |
| long | 10,240 | 46.692 us | 0.0664% | 0.0689% |

## Inference And Wall Time

| Prompt | Wall mean | Inference mean | Known measured stages | Residual |
|---|---:|---:|---:|---:|
| short | 63,826.995 us | 62,405.883 us | 62,519.508 us | 1,307.487 us |
| medium | 65,778.218 us | 64,234.742 us | 64,347.109 us | 1,431.109 us |
| long | 70,319.486 us | 67,740.433 us | 67,958.267 us | 2,361.219 us |

Residual was **2.05-3.36%** of wall time. It is not AIR overhead. It includes
untimed response JSON serialization, server-side response AEAD seal for the same
response, TCP/VPC scheduling, client response JSON parse, receipt validation,
server logging, and benchmark metadata overhead.

## Transport And Hashing

Transport and hashing scale with payload size; AIR does not materially scale
with prompt size in this run.

| Prompt | Server request decrypt | Client request encrypt | Client response decrypt | Request hash | Response hash |
|---|---:|---:|---:|---:|---:|
| short | 5.067 us | 6.067 us | 50.908 us | 0.508 us | 1.167 us |
| medium | 9.892 us | 12.642 us | 36.483 us | 3.100 us | 1.125 us |
| long | 49.067 us | 59.667 us | 33.917 us | 27.350 us | 1.133 us |

`response_encrypt` remains null in schema v2 because the exact same-response
server-side AEAD seal happens after the benchmark record is serialized.
Client-side response decrypt is measured.

## Evidence Integrity

The redacted artifact contains:

- `warm-path-records.jsonl`: 360 request records plus 3 summary records.
- `SUMMARY.md`: generated aggregate report.
- `FACT_CHECK.md`: generated consistency checks and caveats.
- `CONTEXT.md`: redacted run context.
- `run.log` and `build.log`: redacted operational logs.
- `SHA256SUMS`: checksums for committed redacted files.

The report generator recomputed request-level means from JSONL and verified that
they match stored summary records.

Relevant SHA-256 values from the artifact:

| File | SHA-256 |
|---|---|
| `SUMMARY.md` | `a359872478f6044044fb88acd1d9d8fcf98c241d6d0f8ec06dd009c04a983dea` |
| `FACT_CHECK.md` | `459a48d32dd00d574c47438f22c738bf2c712ab5ca4fd1cb2d6017296a242786` |
| `warm-path-records.jsonl` | `e72deffa4a650341796ec6dfa0e7b384b15b785788f8b38170ff43b873c8f25c` |

## What This Does Not Prove

This artifact does not prove production policy posture. MRTD pinning was
disabled for performance measurement, and benchmark mode exposed timing metadata.
Use it as performance evidence, not as a production-assurance artifact.

This artifact does not measure:

- OpenAI-compatible HTTP gateway overhead.
- Concurrency greater than one independent session.
- Autoregressive LLM generation.
- H100 GPU inference.
- Audit-side batch verification throughput.
- End-to-end customer network latency.

## Next Benchmark Gaps

The next report-blocking gaps are:

1. Run a quoteable AIR verify-side microbenchmark against cached receipts, so
   audit-scale verification cost is documented separately from receipt creation.
2. Add a small causal-generation model point, because MiniLM embedding latency is
   not representative of chat-style token generation.
3. Measure independent-session concurrency once the backend supports concurrent
   SecureChannel sessions cleanly.
4. Run an OpenAI-compatible gateway benchmark and label it separately from the
   direct SecureChannel path.

