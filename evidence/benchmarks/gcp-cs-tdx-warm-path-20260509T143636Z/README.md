# GCP CS TDX Warm-Path Benchmark — 2026-05-09

Development benchmark against a GCP Confidential Space TDX CPU backend.

- Backend image tag: `f941b87`
- Backend IP during run: `redacted-backend-ip`
- Model: `stage-0` / MiniLM local smoke model
- Mode: `EPHEMERALML_BENCHMARK_MODE=development`
- Matrix completed: concurrency `1`, prompt sizes `short`, `medium`, `long`
- Requests: 10 warmup per session, 120 measured per prompt size
- Records: 360 request records + 3 summary records

Concurrency `4` and `16` were intentionally not run in this artifact because
the current direct backend accepts one `SecureChannel` session at a time. Running
multi-session concurrency before changing the server accept loop would produce
misleading numbers.

## Summary

| prompt | input bytes | wall mean | inference mean | AIR build mean | AIR sign mean | request hash mean |
|---|---:|---:|---:|---:|---:|---:|
| short | 35 | 283.607 ms | 64.520 ms | 16.892 us | 22.742 us | 0.125 us |
| medium | 1,024 | 281.458 ms | 66.208 ms | 17.408 us | 24.350 us | 3.083 us |
| long | 10,240 | 288.695 ms | 70.509 ms | 17.417 us | 23.675 us | 27.108 us |

## Caveats

- Development-only timing channel; production responses must not expose per-stage timings.
- `request_decrypt` and `response_encrypt` are `null` until `confidential-ml-transport` exposes per-frame timing hooks.
- Client used `EPHEMERALML_REQUIRE_MRTD=false`; audience pinning was set from the GCP WIP audience.
- Wall-clock includes local client transport and network overhead. The enterprise report should quote inside-enclave stage timings separately.
- The backend image tag and embedded JSONL `git_sha` reference the local pre-redaction build used for this run; this published commit rewrites only the evidence redaction/output packaging.
