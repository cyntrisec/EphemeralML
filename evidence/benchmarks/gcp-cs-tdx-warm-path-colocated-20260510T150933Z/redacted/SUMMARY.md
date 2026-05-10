# GCP Confidential Space Warm-Path Benchmark, Same-Zone Client

Date: 20260510T150933Z

Benchmark ID: `gcp_cs_tdx_warm_path`

Git SHA: `4fb6df3`

Schema version: `2`

Mode: `development`

Backend: `c3-standard-4`, zone `us-central1-a`.

Client/runner: `e2-standard-2`. `environment.host` in JSONL describes this runner host unless a separate backend host is explicitly recorded.

Method: concurrency `1`, prompt sizes `short, medium, long`, 10 warmup requests discarded, 120 measured requests per point.

Security caveat: this is a development benchmark run. Per-stage timings are intentionally exposed only in benchmark mode; production responses must not expose this timing channel. If MRTD pinning is disabled in context, this artifact is performance evidence, not production policy evidence.

## Headline

Full AIR receipt creation stayed effectively flat across prompt sizes at about 47-49 microseconds. That is below 0.1% of measured inference time in this run.

Residual wall time after known stage accounting was 2.05-3.36% of request wall time. Residual is not AIR overhead.

## AIR And Inference

| Prompt | Input bytes | Wall mean us | Inference mean us | Claims CBOR us | COSE create signature us | AIR serialize us | Full AIR total us | Full AIR / wall | Full AIR / inference |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| short | 35 | 63,826.995 | 62,405.883 | 17.800 | 27.900 | 2.300 | 48.008 | 0.0752% | 0.0769% |
| medium | 1,024 | 65,778.218 | 64,234.742 | 17.100 | 28.992 | 2.617 | 49.042 | 0.0746% | 0.0763% |
| long | 10,240 | 70,319.486 | 67,740.433 | 15.958 | 28.192 | 2.542 | 46.692 | 0.0664% | 0.0689% |

## Transport And Hashing

| Prompt | Server request decrypt us | Client request encrypt us | Client response decrypt us | Request hash us | Response hash us |
|---|---:|---:|---:|---:|---:|
| short | 5.067 | 6.067 | 50.908 | 0.508 | 1.167 |
| medium | 9.892 | 12.642 | 36.483 | 3.100 | 1.125 |
| long | 49.067 | 59.667 | 33.917 | 27.350 | 1.133 |

Note: `response_encrypt` remains null in schema v2 because the exact same-response server-side AEAD seal occurs after the benchmark record is serialized. Client-side response decrypt is measured.

## Residual

| Prompt | Wall mean us | Known measured stage sum us | Residual us | Residual / wall |
|---|---:|---:|---:|---:|
| short | 63,826.995 | 62,519.508 | 1,307.487 | 2.0485% |
| medium | 65,778.218 | 64,347.109 | 1,431.109 | 2.1757% |
| long | 70,319.486 | 67,958.267 | 2,361.219 | 3.3578% |

Residual includes untimed response JSON serialization, server response AEAD seal, TCP/VPC scheduling, client response JSON parse/receipt validation, per-request server logging, and benchmark metadata overhead. It should not be treated as AIR overhead.

## Files

- `warm-path-records.jsonl`: redacted schema-v2 request and summary records.
- `run.log`: redacted client run log.
- `CONTEXT.md`: redacted run context when available.
- `FACT_CHECK.md`: generated consistency checks and caveats.
- `SHA256SUMS`: checksums for committed redacted files.

Record count: `363` total = `360` request records + `3` summary records.
