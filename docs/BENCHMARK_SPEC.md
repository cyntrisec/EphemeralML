# EphemeralML Benchmark Specification

**Version:** 1.0
**Date:** January 30, 2026
**Derived from:** Analysis of 11 academic/industry papers on confidential computing benchmarks

---

## 1. Purpose

This document defines the structured benchmark framework for EphemeralML. It maps
metrics from the confidential computing literature to EphemeralML's specific architecture
(AWS Nitro Enclaves, Candle/Rust, CPU-only) and prioritizes what to measure, how to
measure it, and what the results mean competitively.

---

## 2. Architecture-Aware Overhead Model

EphemeralML has **6 distinct overhead sources** in the request lifecycle. Each source
maps to different paper metrics and requires different measurement approaches.

### 2.1 Request Lifecycle

```
COLD START (once per enclave boot)
├─ 1. Enclave boot (nitro-cli run-enclave)
├─ 2. NSM attestation generation                    ~45ms
├─ 3. KMS key release (via host VSock proxy)         ~120ms P50, ~500ms P99
├─ 4. S3 model fetch (via host VSock proxy)          ~3200ms (100MB model)
├─ 5. ChaCha20-Poly1305 weight decryption            ~12ms
└─ 6. Safetensors → Candle model load                ~850ms

SESSION SETUP (once per client)
├─ 7. ClientHello / ServerHello exchange              ~1ms network
├─ 8. NSM attestation document generation             ~45ms
├─ 9. X25519 HPKE key derivation                     ~3ms
└─ 10. Client-side COSE cert chain verification      ~25ms

PER-INFERENCE (every request)
├─ 11. VSock receive                                  ~0.15ms
├─ 12. HPKE decrypt (ChaCha20-Poly1305)              ~5μs/KB
├─ 13. Tokenization                                   ~1-5ms
├─ 14. Candle forward pass                            ~10-5000ms (model-dependent)
├─ 15. Receipt generation + Ed25519 sign              ~1ms
├─ 16. HPKE encrypt                                   ~5μs/KB
└─ 17. VSock send                                     ~0.15ms
```

### 2.2 Overhead Source Mapping

| Source | Overhead type | Dominant cost | Paper reference |
|--------|--------------|---------------|-----------------|
| Enclave boot | One-time, amortized | Memory acceptance, firmware init | 10 (boot time breakdown) |
| NSM attestation | Per-session | NSM API call latency | 03 (Nitro-specific), 10 (attestation primitives) |
| KMS key release | Per-model load | AWS KMS API round-trip | EphemeralML-specific (no paper covers this) |
| S3 model fetch | Per-model load | Network + VSock relay | EphemeralML-specific |
| Weight decryption | Per-model load | ChaCha20-Poly1305 throughput | Near-zero (~800 MB/s measured) |
| Model load | Per-model load | Safetensors parse + Candle init | 03 (model copy into enclave) |
| HPKE crypto | Per-request | ChaCha20-Poly1305 AEAD | Near-zero for typical payloads |
| Inference compute | Per-request | CPU forward pass (no GPU) | 02, 03, 07 (CPU TEE inference) |
| Receipt signing | Per-request | Ed25519 + SHA-256 hashing | EphemeralML-specific |
| VSock transport | Per-request | Kernel-level socket overhead | EphemeralML-specific |

---

## 3. Tiered Metric Framework

### Tier 1: Core Performance (Must Measure)

These metrics directly determine user experience and competitive positioning.

| Metric | Unit | Measurement point | Baseline comparison | Existing? |
|--------|------|-------------------|---------------------|-----------|
| Inference latency (p50/p95/p99) | ms | Candle forward pass timing | Same model on bare EC2 | Yes |
| E2E encrypted request latency | ms | HPKE decrypt → inference → receipt → HPKE encrypt | Bare inference (no crypto) | **Yes** (0.162ms) |
| Cold start time | ms | `nitro-cli run-enclave` to first inference ready | N/A (enclave-only metric) | Yes |
| Cold start breakdown | ms | Per-stage: attestation, KMS, S3 fetch, decrypt, model load | Per-stage on bare metal | Yes |
| Throughput (inferences/sec) | req/s | Sustained rate under N concurrent sessions | Bare metal throughput | **Yes** (12.4–14.3 inf/s) |
| Memory peak RSS | MB | `/proc/self/status` VmPeak during load + inference | Bare metal RSS | Yes |
| VSock round-trip latency | ms | Payload sizes: 64B, 1KB, 64KB, 1MB | localhost TCP baseline | Yes |

### Tier 2: Cost & Competitive Positioning

These metrics support the business case and investor narrative.

| Metric | Unit | How to compute | Existing? |
|--------|------|----------------|-----------|
| Cost per 1K inferences | $ | (AWS instance $/hr) / (inferences/hr) | **Yes** ($0.0050 enclave) |
| Cost per 1M tokens (generative models) | $ | (AWS instance $/hr) / (tokens/hr) | **No** |
| TEE overhead % | % | (enclave_latency - baseline_latency) / baseline_latency | Partial |
| Enclave cost multiplier | x | enclave $/inference / bare-metal $/inference | **Yes** (1.15x) |
| Instance type comparison | table | Run benchmarks on m6i.xlarge, c6i.xlarge, c6i.2xlarge | **No** |
| vs GPU TEE crossover point | chart | At what batch size does H100 cGPU become cheaper per inference? | **No** |

### Tier 3: Model Quality Preservation

These metrics verify that the enclave + quantization pipeline does not degrade output quality.

| Metric | Unit | How to measure | Existing? |
|--------|------|----------------|-----------|
| Embedding cosine similarity | 0-1 | Compare enclave output vs bare-metal output on identical inputs | **Yes** (1.000000) |
| Classification accuracy | % | MMLU or task-specific benchmark: enclave vs bare-metal | **No** |
| Output determinism | exact match % | Same input → bitwise identical output across enclave restarts | **No** |
| Quantization quality loss | delta | Q4 vs Q8 vs BF16 on quality metric at enclave memory limits | **No** |

### Tier 4: Security & Attestation Overhead

These metrics quantify the cost of security features.

| Metric | Unit | Measurement point | Existing? |
|--------|------|-------------------|-----------|
| NSM attestation generation | ms | `nsm_process_request()` call in `attestation.rs` | Yes |
| KMS key release (P50/P99) | ms | Round-trip: enclave → host → AWS KMS → host → enclave | Yes |
| HPKE session setup | ms | X25519 ECDH + transcript hash + key derivation | **Yes** (0.10ms) |
| Receipt generation + signing | ms | SHA-256 hashing + Ed25519 sign in `receipt.rs` | **Yes** (0.022ms) |
| Client-side COSE verification | ms | Certificate chain + COSE signature verify | **Yes** (2.998ms full pipeline) |
| E2E session establishment | ms | ClientHello to first inference-ready state | **Yes** (0.176ms TCP handshake) |

### Tier 5: Stress & Limits

These metrics find breaking points and validate operational claims.

| Metric | Unit | How to measure | Existing? |
|--------|------|----------------|-----------|
| Max concurrent sessions | count | Ramp sessions until `ResourceExhausted` (limit: 100) | **No** |
| Throughput at saturation | req/s | Max sustained rate before p99 degrades >2x | **No** |
| Memory under load | MB | Peak RSS at 1/2/4/8/16 concurrent sessions | **No** |
| KMS degradation recovery | scenario | Inject KMS latency spikes, measure circuit breaker behavior | **No** |
| Session accumulation leak | MB/hr | Monitor RSS over 1hr with session churn | **No** |
| Enclave memory limit | MB | Largest model that loads without OOM | **No** |

---

## 4. Literature-Derived Overhead Expectations

### 4.1 What the Papers Predict for EphemeralML

| Overhead category | Expected range | Source | Notes |
|-------------------|---------------|--------|-------|
| CPU inference overhead (TEE vs native) | 2-10% | Papers 02, 07 | TDX/SGX single-socket; Nitro should be similar or lower |
| Cold start (enclave boot + model load) | 4-60s | Papers 03, 10 | Depends on model size; 4.2s projected for 100MB model |
| Memory overhead | 10-15% | Papers 03, 10 | Enclave runtime + crypto state |
| Attestation generation | 30-50ms | Paper 10 | NSM-specific; no direct measurement exists |
| KMS key release | 100-500ms | EphemeralML design | AWS KMS P50-P99 latency range |
| VSock overhead vs TCP | 5-33x faster | EphemeralML measured | VSock bypasses TCP/IP stack |
| HPKE per-message crypto | <0.1ms for <1MB | Papers 02, 05 | ChaCha20-Poly1305 is near-zero on modern CPUs |
| Receipt generation | <1ms | EphemeralML design | Ed25519 is fast; SHA-256 hashing dominates |

### 4.2 Cross-Platform TEE Overhead Reference

From the 11 papers analyzed, these are the published overhead numbers for ML inference:

| Platform | Model / Workload | Overhead | Source paper |
|----------|-----------------|----------|--------------|
| NVIDIA H100 cGPU (SEV-SNP) | Llama-3.1-8B throughput | 6.85% | 01 |
| NVIDIA H100 cGPU | Llama-3.1-70B throughput | ~0% | 01 |
| NVIDIA H100 cGPU | Llama-3.1-8B TTFT | 19-26% | 01 |
| Intel SGX (Gramine, 1-socket) | Llama2 throughput | 4.8-6.2% | 02 |
| Intel TDX (1-socket) | Llama2 throughput | 5.5-10.7% | 02 |
| Intel TDX (2-socket) | Llama2-70B throughput | 12-24% | 02 |
| Intel TDX | NGINX I/O throughput | 28.6% | 07 |
| AMD SEV-SNP | TensorFlow BERT inference | ~16% | 10 |
| AMD SEV-SNP | Memory bandwidth (avg) | ~2.9% | 10 |
| Gramine-SGX | PyTorch BERT/ResNet | Near-native | 07 |
| Occlum-SGX | TensorFlow inference | Up to 6x | 07 |
| SGXv2 (Ice Lake) | B-Tree (data fits EPC) | ~25% max | 11 |
| SGXv2 | Trusted NUMA access latency | +32-46% | 11 |
| Arm CCA (Realm VM) | On-device inference (GPT-2, MobileNet) | 17-22% | 08 |
| AWS Nitro Enclave (CPU) | Llama-3.1-8B-Q4 tokens/s | 100x vs GPU | 03 |
| AWS Nitro Enclave (CPU) | Cost per 100K tokens | 21.7x vs GPU | 03 |

### 4.3 Interpretation Guide

| Inference overhead | Verdict for EphemeralML |
|-------------------|------------------------|
| < 5% | Excellent -- validates "hardware native" claim; matches SGX/TDX best-case |
| 5-10% | Good -- competitive with GPU TEEs and CPU TEEs |
| 10-15% | Acceptable -- on par with AMD SEV-SNP numbers |
| > 15% | Investigate -- likely VSock bottleneck or memory pressure |

| Cold start | Verdict |
|-----------|---------|
| < 5s | Excellent -- beats all LibOS-based competitors (minutes) |
| 5-15s | Acceptable for session-based serving |
| > 30s | Problem -- investigate EIF size or model fetch path |

| Memory overhead | Verdict |
|----------------|---------|
| < 15% RSS increase | Normal (enclave runtime + crypto state) |
| 15-30% | Acceptable if model is near enclave memory limit |
| > 30% | Investigate allocation leak or double-buffering |

---

## 5. Measurement Methodology

### 5.1 Statistical Requirements

- **Iterations**: 100 per metric (minimum)
- **Warmup**: 3 iterations discarded before measurement
- **Percentiles**: p50, p95, p99 from sorted latency arrays
- **Outlier handling**: Report all values; flag Z-score > 3 (~0.64% of samples)
- **Clock**: `std::time::Instant` (monotonic, sub-microsecond)
- **Memory**: Peak RSS from `/proc/self/status` (VmPeak)
- **Repetitions**: 3 full benchmark runs; report median of medians

### 5.2 Baseline Configurations

| Configuration | Purpose | How |
|---------------|---------|-----|
| Bare metal (no enclave) | Measures pure inference cost | `benchmark_baseline` binary on parent EC2 |
| Enclave (full pipeline) | Measures TEE overhead | `benchmark` binary inside Nitro Enclave |
| Localhost TCP (no enclave) | VSock comparison baseline | TCP loopback at same payload sizes |

### 5.3 Hardware Configurations

| Instance | vCPUs | RAM | Enclave alloc | Purpose | Tested? |
|----------|-------|-----|--------------|---------|---------|
| m6i.xlarge | 4 | 16GB | 2 vCPU, 4GB | Primary benchmark target | **Yes** (all results) |
| c6i.xlarge | 4 | 8GB | 2 vCPU, 1GB | Compute-optimized comparison | Planned |
| c6i.2xlarge | 8 | 16GB | 4 vCPU, 4GB | Scaling test | Planned |

### 5.4 Models Under Test

| Model | Parameters | Size | Task | Purpose |
|-------|-----------|------|------|---------|
| MiniLM-L6-v2 | 22.7M | ~90MB | Embedding | Primary benchmark (fast, fits easily) |
| DistilBERT-base | 66M | ~260MB | Classification | Medium model test |
| Llama-3-8B (Q4) | 8B | ~4GB | Generation | Stress test, quality preservation |

---

## 6. Gaps in Existing Benchmarks

The existing `benchmark.rs` and `benchmark_baseline.rs` cover Tier 1 cold-start stages
and single-session inference latency. The following gaps must be addressed:

### 6.1 Critical Gaps (Tier 1-2)

| Gap | Status | Notes |
|-----|--------|-------|
| E2E encrypted request latency | **Done** | 0.162ms mean per-request crypto via `benchmark_e2e` |
| Concurrency scaling | **Done** | N=1,2,4,8 threads; plateaus at 14.2 inf/s via `benchmark_concurrent` |
| Cost calculation | **Done** | $4.97/1M inferences (enclave), 1.15x multiplier via `benchmark_report.py` |
| Instance comparison | **Open** | Only tested on m6i.xlarge so far |

### 6.2 Important Gaps (Tier 3-4)

| Gap | Status | Notes |
|-----|--------|-------|
| Quality preservation | **Done** | Cosine similarity = 1.000000 (first 8 dims, enclave vs bare metal) |
| HPKE session setup timing | **Done** | 0.10ms mean via `benchmark_crypto` |
| Receipt generation + signing | **Done** | 0.022ms mean (CBOR + Ed25519) via `benchmark_crypto` |
| HPKE encrypt/decrypt latency | **Done** | 0.005ms (1KB), 1.89ms (1MB) via `benchmark_crypto` |
| Client-side COSE verification | **Done** | 2.998ms full pipeline (P-384 + 3-cert chain) via `benchmark_cose` |
| Output determinism | **Partial** | <1% variance across 4 runs; exact match not yet tested across restarts |

### 6.3 Desirable Gaps (Tier 5)

| Gap | Status | Notes |
|-----|--------|-------|
| Stress test (concurrent sessions) | **Open** | Multi-threaded client sending parallel requests |
| KMS degradation test | **Open** | Mock KMS with injected latency/errors |
| Long-running memory test | **Open** | 1hr session churn monitoring RSS |

---

## 7. Competitive Benchmarking Strategy

### 7.1 EphemeralML's Unique Position

EphemeralML is the **first project to publish reproducible per-inference latency benchmarks
on AWS Nitro Enclaves**. The landscape:

| Competitor | Published benchmarks? | Platform |
|------------|----------------------|----------|
| AWS Nitro LLM sample | Implementation only, zero performance data | Nitro |
| Anjuna | "Near-native" claim, no numbers | Nitro/SGX |
| Fortanix | No published data | SGX |
| Mithril (BlindAI) | No published data | SGX |
| Secret Network / Oasis | Blockchain latency only | SGX |

### 7.2 Key Competitive Metrics to Publish

1. **Inference overhead %** -- The primary number. Target: <5% for embedding models.
2. **Cold start (seconds)** -- Differentiator vs LibOS competitors (minutes).
3. **Cost per inference ($)** -- Shows where Nitro CPU wins vs GPU TEEs.
4. **Memory efficiency** -- Rust/Candle vs Python-based alternatives.

### 7.3 Cost Crossover Analysis (from Paper 02)

Paper 02 (ETH Zurich) found CPU TEEs are up to 100% cheaper than GPU TEEs at batch=1.
This is EphemeralML's operating point. The benchmark should quantify:

- At what inference volume does H100 cGPU become cheaper?
- For embedding models (MiniLM), is GPU TEE ever cost-effective?
- For generative models (Llama-3-8B-Q4), where is the crossover?

**Expected finding**: For small models and single-request inference (EphemeralML's
target use case), Nitro Enclaves are significantly cheaper per-inference than GPU TEEs,
despite being slower in absolute throughput.

---

## 8. Paper-to-Metric Mapping

Complete mapping of which papers inform which EphemeralML metrics:

| EphemeralML Metric | Paper 01 | Paper 02 | Paper 03 | Paper 04 | Paper 05 | Paper 06 | Paper 07 | Paper 08 | Paper 09 | Paper 10 | Paper 11 |
|--------------------|----------|----------|----------|----------|----------|----------|----------|----------|----------|----------|----------|
| Inference latency | -- | Method | Method | -- | -- | -- | Method | -- | -- | -- | -- |
| Cold start | -- | -- | Direct | -- | -- | -- | -- | -- | -- | Method | -- |
| Throughput | Method | Method | Direct | -- | -- | -- | Method | -- | -- | -- | -- |
| Memory usage | -- | -- | Direct | -- | Method | -- | -- | Method | -- | -- | -- |
| VSock RTT | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |
| Cost per inference | -- | Method | Method | -- | -- | -- | Method | -- | -- | -- | -- |
| TEE overhead % | Method | Method | -- | -- | -- | -- | Method | Method | -- | Method | Method |
| Attestation time | -- | -- | -- | Qualit. | -- | -- | -- | -- | -- | Method | -- |
| Quality (accuracy) | -- | -- | Method | -- | -- | -- | -- | -- | -- | -- | -- |
| Quality (BERTScore) | -- | -- | Method | -- | -- | -- | -- | -- | -- | -- | -- |
| Concurrency | -- | Method | -- | -- | -- | Method | -- | -- | -- | -- | -- |
| Boot time | -- | -- | -- | -- | -- | -- | -- | Method | -- | Method | -- |
| NUMA/memory effects | -- | Method | -- | -- | -- | -- | -- | -- | -- | Method | Method |
| Network I/O | -- | -- | -- | -- | Method | -- | Method | -- | -- | Method | -- |
| KMS latency | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |
| Receipt signing | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |

**Legend**: "Direct" = same platform (Nitro); "Method" = methodology applicable; "Qualit." = qualitative only

---

## 9. Papers Analyzed

| ID | Title | Authors | Source | Relevance |
|----|-------|---------|--------|-----------|
| 01 | Confidential Computing on NVIDIA Hopper GPUs | Zhu et al. (Phala, Fudan, io.net) | arXiv:2409.03992 | GPU TEE overhead methodology |
| 02 | Confidential LLM Inference: Performance and Cost | Chrapek et al. (ETH Zurich) | arXiv:2509.18886 | CPU vs GPU TEE cost analysis |
| 03 | Attestable Audits: Verifiable AI Safety Benchmarks | Schnabl et al. (Cambridge) | arXiv:2506.23706 | **Direct** -- same platform (Nitro) |
| 04 | Confidential Inference Systems: Design Principles | Pattern Labs + Anthropic | Whitepaper v1.0 | Threat model alignment |
| 05 | Confidential Inter-CVM Communication (CAEC) | Abdollahi et al. (Imperial, Dartmouth) | arXiv:2512.01594 | Inter-CVM communication patterns |
| 06 | Confidential Prompting (Petridish/SPD) | Li et al. (Yale) | arXiv:2409.19134 | Split inference architecture |
| 07 | TEE Benchmarks: SGX, SEV, TDX | Coppolino et al. (Parthenope) | arXiv:2408.00443 | Cross-TEE comparative methodology |
| 08 | Arm CCA On-Device Model Protection | Abdollahi et al. (Imperial, NYU) | arXiv:2504.08508 | On-device TEE overhead patterns |
| 09 | Intel Confidential AI Whitepaper | O'Neill et al. (Intel) | Intel whitepaper | Ecosystem context (no metrics) |
| 10 | Confidential VMs Explained: SEV-SNP and TDX | Misono et al. (TUM) | ACM SIGMETRICS 2024 | Comprehensive microbenchmark methodology |
| 11 | Benchmarking SGXv2 Hardware | El-Hindi et al. (TU Darmstadt) | DaMoN 2022 | SGX memory/paging overhead patterns |

---

## 10. Implementation Priority

### Completed (Feb 2026)

- [x] Core inference latency (p50/p95/p99) — bare metal vs enclave
- [x] Cold start breakdown (attestation, KMS, S3, decrypt, model load, tokenizer)
- [x] VSock RTT at 64B/1KB/64KB/1MB + upload throughput
- [x] Memory peak RSS comparison
- [x] Output quality verification (cosine similarity = 1.000000)
- [x] HPKE session setup timing (0.10ms)
- [x] HPKE encrypt/decrypt at 64B–1MB
- [x] Ed25519 keygen, receipt sign/verify timing
- [x] Per-inference crypto budget (0.027ms)
- [x] Reproducibility validation (4 runs, <1% variance)

### Phase 1: ~~Remaining Critical Gaps~~ (Completed)

- [x] E2E encrypted request latency — `benchmark_e2e` (0.162ms/req crypto overhead)
- [x] Concurrency scaling — `benchmark_concurrent` (plateaus at 14.2 inf/s, CPU-bound)
- [x] Cost calculation — `benchmark_report.py` ($4.97/1M inferences enclave)

### Phase 2: Remaining Important Gaps

4. ~~Client-side COSE verification timing~~ — **Done** (2.998ms, P-384 + 3-cert chain)
5. Output determinism across enclave restarts
6. Multi-instance-type comparison (c6i.xlarge, c6i.2xlarge)

### Phase 3: Stress & Operational

7. KMS degradation scenario testing
8. Long-running memory monitoring
9. Quantization quality ablation (Q4 vs Q8 vs BF16)

---

*This specification is derived from analysis of 11 papers in `docs/papers_llm/` and
the EphemeralML architecture. Last updated at commit `4cfe606`, February 2026.*
