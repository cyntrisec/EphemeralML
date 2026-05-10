# GCP Confidential Space Warm-Path Benchmark, Same-Zone Client

Date: 2026-05-10 UTC

Benchmark ID: `gcp_cs_tdx_warm_path`

Git SHA: `0bab82b`

Schema version: `2`

Backend: GCP Confidential Space CPU TDX, `c3-standard-4`, `us-central1-a`, image tag `bench-0bab82b`.

Client: same-zone GCP VM, `e2-standard-2`, private VPC path to backend. Backend private address is redacted in the committed JSONL.

Metadata note: `environment.host` in `warm-path-records.jsonl` is the same-zone benchmark client VM, not the Confidential Space backend. Backend metadata is recorded in this summary from the deployment command.

Method: concurrency `1`, independent SecureChannel session, prompt sizes `short`, `medium`, `long`, 10 warmup requests discarded, 120 measured requests per point.

Security caveat: this is a development benchmark run. Per-stage timings are intentionally exposed only in benchmark mode; production responses must not expose this timing channel. MRTD pinning was disabled for this measurement run, so this artifact is performance evidence, not production policy evidence.

## Headline

Full AIR receipt creation stayed effectively flat across prompt sizes at about 47-49 microseconds. That is about 0.07-0.08% of measured inference time and about 0.07% of same-zone request wall time.

The smaller 42-44 microsecond number is the decomposed lower-bound path `air_build + air_sign + air_serialize`, where `air_sign` is raw Ed25519 signing only. The quoteable full AIR number uses `air_claim_validate + air_claims_cbor_encode + air_cose_create_signature + air_serialize`, where `air_cose_create_signature` includes COSE Sig_structure preparation plus the signing callback.

The same-zone private-IP setup reduced the previously unexplained wall-time residual to 1.95-2.79%, confirming the earlier public-Internet residual was network/gateway placement rather than AIR or core crypto overhead.

## AIR And Inference

| Prompt | Input bytes | Wall mean us | Inference mean us | Claims CBOR us | COSE create signature us | AIR serialize us | Full AIR total us | Full AIR / wall | Full AIR / inference |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| short | 35 | 63,907.890 | 62,562.425 | 16.542 | 28.083 | 2.167 | 46.809 | 0.0732% | 0.0748% |
| medium | 1,024 | 65,661.865 | 64,206.358 | 17.050 | 28.683 | 2.233 | 47.966 | 0.0731% | 0.0747% |
| long | 10,240 | 70,304.179 | 68,143.342 | 16.917 | 28.658 | 2.950 | 48.525 | 0.0690% | 0.0712% |

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
| short | 63,907.890 | 62,668.951 | 1,238.939 | 1.9386% |
| medium | 65,661.865 | 64,306.440 | 1,355.425 | 2.0642% |
| long | 70,304.179 | 68,350.800 | 1,953.379 | 2.7785% |

Residual includes untimed response JSON serialization, server response AEAD seal, TCP/VPC scheduling, client response JSON parse/receipt validation, per-request server logging, and benchmark metadata overhead. It should not be treated as AIR overhead.

## Files

- `warm-path-records.jsonl`: redacted schema-v2 request and summary records.
- `run.log`: redacted client run log.
- `SHA256SUMS`: checksums for committed redacted files.

Raw artifacts are retained locally under `raw/` but are gitignored and not intended for publication.
