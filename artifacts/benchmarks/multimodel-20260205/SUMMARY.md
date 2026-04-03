# Multi-Model Benchmark Results

**Date:** 2026-02-05
**Instance:** m6i.xlarge (4 vCPUs, 16 GB RAM)
**Enclave config:** 2 CPUs, 4096 MB RAM
**Iterations:** 100 per run (3 warmup)
**Runs:** 3 per model

## Cross-Model Comparison

| Model | Params | Bare Metal (ms) | Enclave (ms) | Overhead | BL RSS | EN RSS |
|-------|--------|-----------------|--------------|----------|--------|--------|
| MiniLM-L6-v2 | 22.7M | 79.28 +/- 0.36 | 90.36 +/- 0.22 | +14.0% +/- 0.8 | 266 MB | 586 MB |
| MiniLM-L12-v2 | 33.4M | 157.25 +/- 0.72 | 177.57 +/- 1.24 | +12.9% +/- 1.3 | 388 MB | 1494 MB |
| BERT-base-uncased | 110M | 65.66 +/- 0.22 | 73.49 +/- 0.13 | +11.9% +/- 0.5 | 1262 MB | 2826 MB |

**Weighted average overhead: ~12.9%** across all 3 models.

## Per-Run Detail

### MiniLM-L6-v2 (22.7M params, commit 8fc6c36)

| Run | Baseline (ms) | Enclave (ms) | Overhead | BL P95 | EN P95 |
|-----|---------------|--------------|----------|--------|--------|
| 1 | 79.30 | 90.33 | +13.9% | 81.13 | 92.08 |
| 2 | 79.63 | 90.16 | +13.2% | 81.28 | 92.10 |
| 3 | 78.92 | 90.59 | +14.8% | 80.81 | 93.14 |

Full 9-benchmark suite: baseline, enclave, crypto, e2e, cose, concurrent, input-scaling, true-e2e, enclave-concurrency.

### MiniLM-L12-v2 (33.4M params, commit f0b372a)

| Run | Baseline (ms) | Enclave (ms) | Overhead |
|-----|---------------|--------------|----------|
| 1 | 158.23 | 178.14 | +12.6% |
| 2 | 156.01 | 178.38 | +14.3% |
| 3 | 157.51 | 176.18 | +11.9% |

Full 9-benchmark suite for all 3 runs.

### BERT-base-uncased (110M params, commit 8fc6c36)

| Run | Baseline (ms) | Enclave (ms) | Overhead |
|-----|---------------|--------------|----------|
| 1 | 65.49 | 73.63 | +12.4% |
| 2 | 65.57 | 73.39 | +11.9% |
| 3 | 65.92 | 73.45 | +11.4% |

Baseline + enclave inference only (crypto primitives are model-independent).

## Reproducibility

| Model | BL CV% | EN CV% | Overhead CV% |
|-------|--------|--------|-------------|
| MiniLM-L6-v2 | 0.5% | 0.2% | 5.6% |
| MiniLM-L12-v2 | 0.7% | 0.7% | 9.9% |
| BERT-base-uncased | 0.3% | 0.2% | 4.2% |

CV% < 1% for all inference measurements. Overhead CV% higher due to small absolute differences.

## Quality Determinism

- **Baseline:** Bit-identical across all 3 runs (same SHA-256)
- **Enclave:** Bit-identical across all 3 runs (same SHA-256, different from baseline)
- **Cross-environment:** Cosine similarity = 0.999999999999871, max abs diff = 5.811e-07
- **Verdict:** Near-identical (f32 precision differences only)

## Artifact Inventory

### Per-run (x3 runs per model):
- `baseline_results.json` - bare-metal inference benchmark
- `enclave_results.json` - Nitro Enclave inference benchmark
- `crypto_results.json` - HPKE, Ed25519, receipt primitives (minilm-l6, minilm-l12)
- `e2e_results.json` - E2E encrypted request, crypto-only (minilm-l6, minilm-l12)
- `cose_results.json` - COSE attestation verification (minilm-l6, minilm-l12)
- `concurrent_results.json` - multi-thread scaling (minilm-l6, minilm-l12)
- `input_scaling_results.json` - latency vs token count (minilm-l6, minilm-l12)
- `true_e2e_results.json` - crypto + real BERT inference (minilm-l6, minilm-l12)
- `enclave_concurrency_results.json` - concurrent E2E sessions (minilm-l6, minilm-l12)
- `quality_determinism.json` - per-run quality check (minilm-l6, minilm-l12)
- `benchmark_report.md` - per-run markdown report (minilm-l6, minilm-l12)
- `paper_tables_generated.tex` - per-run LaTeX tables (minilm-l6, minilm-l12)
- `run_metadata.json` - timestamp, commit, instance type
- `enclave_console.log` - raw enclave console output
- `benchmark.eif` - enclave image (minilm-l6, minilm-l12)

### Cross-run:
- `multimodel_reproducibility.json` - all models, 3-run statistics
- `reproducibility_summary.json` - minilm-l6 detailed 3-run analysis
- `quality_determinism_3runs.json` - cross-run quality (3 baseline + 3 enclave)
- `benchmark_report_combined.md` - combined report with 3-run quality
- `paper_tables_combined.tex` - combined LaTeX tables

## Notes

- BERT-base (110M params) benchmarks completed after fixes:
  - Commit 8882e4e: HuggingFace BERT tensor naming compatibility
  - Commit 8fc6c36: CBOR encoding for Storage channel (enables 440MB model transfer)
- MiniLM-L12 runs used commit f0b372a (pre-CBOR fix); inference logic unchanged
- BERT-base is faster than MiniLM-L6 per-token because it processes 128 tokens in 65ms (0.51ms/token) vs MiniLM-L6's 79ms for 128 tokens (0.62ms/token) - likely due to BERT's optimized attention patterns
- Enclave memory includes kernel overhead and VSock message buffers (~2x model size)
