# GCP CS TDX Warm-Path Benchmark — 2026-05-09

This redacted artifact captures a schema v2 warm-path benchmark run against a
fresh GCP Confidential Space Intel TDX backend built from EphemeralML commit
`fca5b82`.

## Scope

- Backend: GCP Confidential Space CPU TDX, direct SecureChannel mode.
- Client: remote developer workstation, not co-located in GCP.
- Matrix: concurrency `1`, prompt sizes `short`, `medium`, `long`.
- Samples: `10` warmup requests discarded per point, `120` measured requests per
  point.
- Security caveat: development benchmark mode with MRTD pinning disabled; this
  run is timing evidence, not production policy evidence.

## Headline Timing

| prompt | wall mean | inference mean | AIR build | AIR sign | AIR serialize | AIR total | AIR / wall | AIR / inference |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| short | 264.202 ms | 63.292 ms | 17.367 us | 24.483 us | 2.633 us | 44.483 us | 0.017% | 0.070% |
| medium | 263.563 ms | 64.801 ms | 17.450 us | 22.858 us | 2.133 us | 42.441 us | 0.016% | 0.065% |
| long | 263.917 ms | 68.505 ms | 17.583 us | 24.633 us | 2.525 us | 44.741 us | 0.017% | 0.065% |

AIR receipt creation stayed flat across input sizes, as expected: it is bound
mostly by fixed claim-set encoding and Ed25519 signing, not prompt size.

## Transport Timing Hook Check

Schema v2 includes non-null SecureChannel AEAD timing hooks:

| prompt | client request encrypt | server request decrypt | client response decrypt |
|---|---:|---:|---:|
| short | 13.833 us | 10.042 us | 92.933 us |
| medium | 32.583 us | 13.575 us | 70.008 us |
| long | 193.883 us | 47.925 us | 68.950 us |

`response_encrypt` remains `null` by design because exact same-response
server-side sealing happens after the benchmark JSON body is serialized. The
client-side response decrypt timing is the usable same-response transport
measurement in this artifact.

## Residual Boundary

Known instrumented stage sums explain only about 24-26% of local wall-clock:

| prompt | known stage sum | residual | residual / wall |
|---|---:|---:|---:|
| short | 63.836 ms | 200.365 ms | 75.838% |
| medium | 65.347 ms | 198.215 ms | 75.206% |
| long | 69.280 ms | 194.637 ms | 73.749% |

This residual is expected for a developer-workstation client talking to a GCP
backend over the public Internet. It should not be quoted as Cyntrisec runtime
overhead. For enterprise-facing gateway overhead, rerun the same schema from a
client co-located in the same GCP region/VPC or from the production gateway
deployment path.

## Files

- `warm-path-records.jsonl`: request and summary records.
- `run.log`: redacted benchmark runner log.
- `build.log`: redacted local build log.
- `SHA256SUMS`: hashes for the redacted files.
