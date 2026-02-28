# Claim-to-Evidence Integrity Matrix

**Date:** 2026-02-28
**Baseline commit:** `2664132` (publication tag `publication-airv1-20260228`)
**Purpose:** For every public claim, this file traces the exact value, source artifact, reproduction command, commit, and caveats. No claim without evidence. No evidence without context.

## Matrix

### Performance Claims

| # | Claim | Exact Value | Source Artifact | Script / Command | Commit | Caveats |
|---|-------|-------------|-----------------|------------------|--------|---------|
| C-1 | Nitro inference overhead (fully instrumented) | +12.6% mean (78.55→88.45ms) | `benchmark_results_multimodel_20260205/minilm-l6-run1/` through `run3/` | `scripts/run_benchmark.sh` (legacy 9-benchmark suite) | `b00bab1` | Not reproducible on current main. Includes VSock RTT. Run-1 cold-cache outlier +17.6% excluded from headline. |
| C-2 | Nitro enclave execution overhead (modern) | +3.2% mean (74.61→77.00ms) | `benchmark_results_aws_nitro_modern_20260225_clean/benchmark_report.md` | `scripts/run_benchmark_modern.sh` | `f1ba30d` | Enclave-execution-only (receipt `execution_time_ms`). Excludes VSock transport. 10 iterations only (lower statistical power than C-1). Enclave RSS not reported. |
| C-3 | Nitro host E2E latency | 113ms (single), 117.1ms (10-run mean) | `evidence/publication-airv1-20260228/aws-nitro/timing.json` (single), `benchmark_results_aws_nitro_modern_20260225_clean/` (10-run) | `scripts/nitro_e2e.sh` | `2664132`/`f1ba30d` | Full client round-trip. Not directly comparable to bare-metal baseline. |
| C-4 | Multi-model weighted overhead | +12.9% (L6 +14.0%, L12 +12.9%, BERT +11.9%) | `benchmark_results_multimodel_20260205/SUMMARY.md` | `scripts/run_benchmark.sh` × 3 models | `b00bab1` | Not reproducible on current main. Same scope as C-1. |
| C-10 | Per-inference crypto | 0.028ms (0.03% of inference) | `docs/benchmarks.md` §2.4 | `benchmark_crypto` binary (legacy) | `b00bab1` | Measured in legacy pipeline. Magnitude stable — crypto is not bottleneck. |

### Functional / Security Claims

| # | Claim | Exact Value | Source Artifact | Script / Command | Commit | Caveats |
|---|-------|-------------|-----------------|------------------|--------|---------|
| C-5a | AWS Nitro E2E PASS | 1/1 positive, receipt verified, AIR v1 CBOR | `evidence/publication-airv1-20260228/aws-nitro/` | `scripts/nitro_e2e.sh` | `2664132` | AIR v1 COSE_Sign1 receipt (585 bytes). PCR pinning verified. 113ms e2e, 77ms enclave. |
| C-5b | GCP CPU TDX E2E PASS | 10/10 steps, 2/2 negative | `evidence/publication-airv1-20260228/gcp-cpu-tdx/metadata.json` | `scripts/gcp/mvp_gpu_e2e.sh --cpu-only` | `f1ba30d` (image) | c3-standard-4, us-central1-a. AIR v1 CBOR receipt verified. Source run: `mvp-20260227_092628`. |
| C-5c | GCP GPU H100 CC E2E PASS | 10/10 steps, 2/2 negative | `evidence/publication-airv1-20260228/gcp-gpu-h100cc/metadata.json` | `scripts/gcp/mvp_gpu_e2e.sh` | `f1ba30d` (image) | a3-highgpu-1g, us-central1-a. MiniLM inference time NOT representative. Source run: `mvp-20260227_095900`. |
| C-6 | AIR v1 verification pass | 11/11 mandatory checks | `evidence/publication-airv1-20260228/gcp-{cpu-tdx,gpu-h100cc}/receipt_air_v1_verify_log.txt` | `ephemeralml-verify receipt.cbor --public-key receipt.pubkey` | `f1ba30d` | Policy-optional checks (FRESH, MHASH, MODEL, PLATFORM, NONCE, REPLAY) skipped when unconstrained. |
| C-7 | Compliance baseline pass | 16/16 rules | `evidence/publication-airv1-20260228/gcp-cpu-tdx/compliance_verify_log.txt` | `ephemeralml-compliance verify --profile baseline` | `f1ba30d` | Baseline profile only. Advanced profiles not tested. |
| C-8 | Negative test coverage | 2/2 per GCP platform | `evidence/publication-airv1-20260228/gcp-{cpu-tdx,gpu-h100cc}/negative_wrong_{hash,key}_{deploy,verify}.txt` | `scripts/gcp/mvp_gpu_e2e.sh` step 10 | `f1ba30d` | GCP only (hash + key mismatch). Nitro uses PCR mismatch separately. |
| C-9 | Test suite size | 575 tests, 0 failures | `cargo test -q` output | `cargo test -q` | `a33dc8b` | Includes unit, integration, conformance. Some tests marked `#[ignore]` for cloud-only scenarios not counted. |

### Specification Claims

| # | Claim | Exact Value | Source Artifact | Commit | Caveats |
|---|-------|-------------|-----------------|--------|---------|
| S-1 | AIR v1 spec frozen | v1.0 FROZEN, 8 normative docs | `spec/v1/RELEASE.md` | `d7c9d01` (tag `m3-spec-frozen`) | Tier 1+2 hardening (rejection paths) added post-freeze. Wire format unchanged. |
| S-2 | 18 claims (16 required + 2 optional) | 5 standard CWT/EAT + 13 private | `spec/v1/claim-mapping.md` §2-3 | `a33dc8b` | eat_nonce and model_hash_scheme are optional. |
| S-3 | 10 golden vectors (2 valid + 8 invalid) | Byte-stable post-hardening | `spec/v1/vectors/README.md` | `a33dc8b` | Vectors regenerated 2026-02-28, byte-identical to frozen vectors. |
| S-4 | RFC 9711 EAT profile compliance | §6.3 positions documented | `spec/v1/claim-mapping.md` §6 | `a33dc8b` | Profile declaration table added 2026-02-28. |

## Evidence Freshness

| Platform | Evidence Date | Days Old | Code Changes Since | Verdict |
|----------|--------------|----------|-------------------|---------|
| AWS Nitro | 2026-02-28 | 0 | AIR v1 Nitro emission + model_hash_scheme enforcement | **Valid** — tri-cloud rerun with AIR v1 CBOR |
| GCP CPU TDX | 2026-02-27 | 1 | AIR v1 Nitro emission + model_hash_scheme enforcement | **Valid** — no GCP code changes |
| GCP GPU H100 CC | 2026-02-27 | 1 | AIR v1 Nitro emission + model_hash_scheme enforcement | **Valid** — no GCP code changes |
| Benchmark (modern) | 2026-02-25 | 3 | Doc-only + parse hardening (rejection paths) | **Valid** — measurement code unchanged |
| Benchmark (legacy) | 2026-02-04 | 24 | Pipeline removed from main | **Historical** — not reproducible, still citable |

## Remaining Blockers Before IETF/NIST Submission

| Blocker | Severity | Mitigation | ETA |
|---------|----------|------------|-----|
| ~~AIR v1 CBOR not emitted in Nitro path~~ | ~~MEDIUM~~ | **RESOLVED** — commit `63db588` + verified in `evidence/publication-airv1-20260228/aws-nitro/receipt.cbor` (COSE_Sign1, 585 bytes) | Done |
| Legacy benchmark not reproducible | LOW | Documented as historical. Modern fallback is reproducible. | Accepted |
| GPU benchmark uses MiniLM only | LOW | MiniLM validates pipeline. 7B+ model needed for GPU perf claims. Do not claim GPU performance. | Phase 3 (requires H100 time) |
| Enclave memory RSS = 0 | LOW | Known host-path limitation. Do not claim memory figures. | Backlog |
| ~~`model_hash_scheme` allowlist not enforced~~ | ~~MEDIUM~~ | **RESOLVED** — commit `d7d3c97` enforces allowlist in parse path. | Done |
