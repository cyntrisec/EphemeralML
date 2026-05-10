# GCP Confidential Space Warm-Path Benchmark, Same-Zone Client

Date: 2026-05-10 UTC

Benchmark ID: `gcp_cs_tdx_warm_path`

Git SHA: `0bab82b`

Schema version: `2`

Backend: GCP Confidential Space CPU TDX, `c3-standard-4`, `us-central1-a`, image tag `bench-0bab82b`.

Client: same-zone GCP VM, `e2-standard-2`, private VPC path to backend. Backend private address is redacted in the committed JSONL.

Method: concurrency `1`, independent SecureChannel session, prompt sizes `short`, `medium`, `long`, 10 warmup requests discarded, 120 measured requests per point.

Security caveat: this is a development benchmark run. Per-stage timings are intentionally exposed only in benchmark mode; production responses must not expose this timing channel. MRTD pinning was disabled for this measurement run, so this artifact is performance evidence, not production policy evidence.

## Headline

AIR receipt creation stayed effectively flat across prompt sizes at about 42-44 microseconds. That is about 0.06-0.07% of measured inference time and about 0.06-0.07% of same-zone request wall time.

The same-zone private-IP setup reduced the previously unexplained wall-time residual to 1.95-2.79%, confirming the earlier public-Internet residual was network/gateway placement rather than AIR or core crypto overhead.

## AIR And Inference

| Prompt | Input bytes | Wall mean us | Inference mean us | AIR build us | AIR sign us | AIR serialize us | AIR total us | AIR / wall | AIR / inference |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| short | 35 | 63,907.890 | 62,562.425 | 16.542 | 23.142 | 2.167 | 41.851 | 0.0655% | 0.0669% |
| medium | 1,024 | 65,661.865 | 64,206.358 | 17.050 | 23.658 | 2.233 | 42.941 | 0.0654% | 0.0669% |
| long | 10,240 | 70,304.179 | 68,143.342 | 16.917 | 23.750 | 2.950 | 43.617 | 0.0620% | 0.0640% |

## Transport And Hashing

| Prompt | Server request decrypt us | Client request encrypt us | Client response decrypt us | Request hash us | Response hash us |
|---|---:|---:|---:|---:|---:|
| short | 5.558 | 3.467 | 47.608 | 0.042 | 1.142 |
| medium | 10.358 | 8.133 | 28.667 | 3.383 | 1.492 |
| long | 49.942 | 44.483 | 27.658 | 35.375 | 1.392 |

Note: `response_encrypt` remains null in schema v2 because the exact same-response server-side AEAD seal occurs after the benchmark record is serialized. Client-side response decrypt is measured.

## Residual

| Prompt | Wall mean us | Known measured stage sum us | Residual us | Residual / wall |
|---|---:|---:|---:|---:|
| short | 63,907.890 | 62,663.993 | 1,243.897 | 1.9464% |
| medium | 65,661.865 | 64,301.415 | 1,360.450 | 2.0719% |
| long | 70,304.179 | 68,345.892 | 1,958.287 | 2.7854% |

## Files

- `warm-path-records.jsonl`: redacted schema-v2 request and summary records.
- `run.log`: redacted client run log.
- `SHA256SUMS`: checksums for committed redacted files.

Raw artifacts are retained locally under `raw/` but are gitignored and not intended for publication.
