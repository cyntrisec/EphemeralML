# AIR v1 Publication Verification Report

**Generated:** 2026-02-28
**Evidence baseline commit:** `a33dc8b` (HEAD at time of evidence collection)
**Evidence source commits:** `f1ba30d` (image build), `a33dc8b` (doc-only changes since evidence collection)
**Code changes since evidence:** Tier 1+2 parse hardening (rejection-path only, no wire format change) + doc cleanup. Zero functional changes to inference/receipt/attestation code paths.

## E2E PASS/FAIL Matrix

| Check | AWS Nitro (m6i.xlarge) | GCP CPU TDX (c3-std-4) | GCP GPU H100 CC (a3-highgpu-1g) |
|-------|----------------------|------------------------|-------------------------------|
| **Positive inference** | PASS (76ms exec) | PASS (75ms exec) | PASS |
| **Receipt emitted** | PASS (receipt.json) | PASS (receipt.json + receipt.cbor) | PASS (receipt.json + receipt.cbor) |
| **Ed25519 signature** | PASS | PASS | PASS |
| **AIR v1 strict verify** | PASS (legacy path) | PASS (11/11 mandatory) | PASS (11/11 mandatory) |
| **Negative: wrong hash** | N/A (PCR-pinned) | PASS (rejected) | PASS (rejected) |
| **Negative: wrong key** | N/A (PCR-pinned) | PASS (rejected) | PASS (rejected) |
| **Compliance baseline** | N/A | PASS (16/16 rules) | PASS (16/16 rules) |
| **Artifact manifest** | PASS (9/9 SHA-256) | N/A | N/A |
| **PCR/MRTD measurements** | PASS (48-byte SHA-384) | PASS (tdx-mrtd-rtmr) | PASS (tdx-mrtd-rtmr) |

### Platform-Specific Notes

**AWS Nitro:**
- Evidence: `evidence/publication-airv1-20260228/aws-nitro/`
- Source run: `nitro-e2e-20260227T095832Z` → `nitro-e2e-20260228` (rerun with AIR v1 CBOR)
- E2E client latency: 113ms
- Enclave execution: 76ms
- PCR pinning enforced (PCR0/1/2, non-zero SHA-384)
- Negative tests via PCR mismatch (separate from MVP script)
- AIR v1 CBOR receipt: PASS (emitted since commit `63db588`)

**GCP CPU TDX:**
- Evidence: `evidence/publication-airv1-20260228/gcp-cpu-tdx/`
- Source run: `mvp-20260227_092628` (10/10 steps, AIR v1 CBOR verified, compliance 16/16)
- Steps: 10/10
- Negative tests: 2/2 (wrong model hash, wrong KMS key)
- AIR v1 receipt: verified via `ephemeralml-verify`
- Compliance: 16/16 baseline rules
- Machine: c3-standard-4 (Intel Sapphire Rapids, TDX)

**GCP GPU H100 CC:**
- Evidence: `evidence/publication-airv1-20260228/gcp-gpu-h100cc/`
- Source run: `mvp-20260227_095900` (10/10 steps, AIR v1 CBOR verified, compliance 16/16)
- Steps: 10/10
- Negative tests: 2/2 (wrong model hash, wrong KMS key)
- AIR v1 receipt: verified
- Compliance: 16/16 baseline rules
- Machine: a3-highgpu-1g (1x H100 80GB, TDX + H100 CC-mode)
- MiniLM inference time is NOT representative of GPU performance (CUDA JIT warmup dominates)

**Benchmark (Nitro):**
- Evidence: `evidence/publication-airv1-20260228/benchmark-nitro/`
- Source: `benchmark_results_aws_nitro_modern_20260225_clean/` (dereferenced copy)

## Benchmark Summary (AWS Nitro Canonical)

| Metric | Value | Source |
|--------|-------|--------|
| Enclave execution overhead | +3.2% (77.00 vs 74.61ms) | C-2, `evidence/publication-airv1-20260228/benchmark-nitro/` |
| Fully instrumented overhead | +12.6% (88.45 vs 78.55ms) | C-1, commit `b00bab1`, legacy pipeline |
| Host E2E latency (mean) | 117.1ms | C-3, 10-run aggregate |
| Host E2E latency (latest) | 113ms | C-3, `evidence/publication-airv1-20260228/aws-nitro/timing.json` |
| Per-inference crypto | 0.028ms | C-10, negligible |
| COSE verification | 1.92ms | One-time per session |

## Known Gaps

| Gap | Impact | Mitigation |
|-----|--------|------------|
| ~~AIR v1 CBOR receipt not emitted in Nitro E2E~~ | **RESOLVED** (commit `63db588`) | Nitro now emits AIR v1 CBOR receipts |
| Enclave memory RSS = 0 | Cannot verify memory claims | Known limitation in current host path |
| GPU benchmark uses MiniLM | Not representative of GPU perf | Pipeline validation only; 7B+ model benchmark needed (Phase 3) |
| Legacy benchmark not reproducible | +12.6% cannot be regenerated on current main | Use +3.2% for reproducible claims, reference +12.6% as historical |
| Nitro negative tests differ from GCP | Not apples-to-apples negative coverage | Nitro uses PCR mismatch; GCP uses hash/key mismatch |

## Publication Directory Structure

All evidence is self-contained under `evidence/publication-airv1-20260228/`:

```
evidence/publication-airv1-20260228/
  VERIFICATION_REPORT.md        # This file
  manifest.json                 # SHA-256 inventory
  aws-nitro/                    # Real files (Nitro rerun, Feb 28)
  gcp-cpu-tdx/                  # Real files (from mvp-20260227_092628)
  gcp-gpu-h100cc/               # Real files (from mvp-20260227_095900)
  benchmark-nitro/              # Real files (from benchmark_results_aws_nitro_modern_20260225_clean)
```

All subdirectories contain dereferenced regular files (no symlinks).
The publication bundle is portable without dependency on ad-hoc run directories.

### GCP Evidence Selection Rationale

| Platform | Selected Run | Why |
|----------|-------------|-----|
| GCP CPU TDX | `mvp-20260227_092628` | Latest complete run (10/10 steps, 2/2 negatives) with AIR v1 CBOR receipt and verification. Earlier runs (Feb 25) lacked CBOR or were incomplete (Feb 27 morning). Later runs (Feb 28) were 8/10 incomplete. |
| GCP GPU H100 CC | `mvp-20260227_095900` | Only complete GPU run (10/10 steps, 2/2 negatives) with AIR v1 CBOR receipt and verification. Earlier GPU run (Feb 25) lacked CBOR. |

## Artifact Integrity

All evidence artifacts verified via SHA-256 checksums.
See `manifest.json` in this directory for full inventory.
