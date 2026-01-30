# Literature Review: TEE Benchmark Metrics for Confidential ML Inference

**Date:** January 30, 2026
**Scope:** 11 papers analyzed for benchmark metrics, methodologies, and overhead findings
**Target:** AWS Nitro Enclaves (EphemeralML)

---

## 1. Paper Classification

| Type | Papers | Notes |
|------|--------|-------|
| Empirical benchmarks | 01, 02, 03, 05, 06, 07, 08, 10, 11 | Quantitative metrics with measured data |
| Design whitepapers | 04 (Anthropic), 09 (Intel) | Qualitative; no benchmark data |

---

## 2. Complete Metric Taxonomy

All unique metrics identified across the 11 papers, organized by category.

### 2.1 Inference Latency

| Metric | Definition | Papers |
|--------|-----------|--------|
| TTFT (Time To First Token) | Time from request to first output token | 01, 02 |
| ITL (Inter-Token Latency) | Time between successive output tokens | 01 |
| Next-token latency | Per-token generation time (ms) | 02 |
| Per-decoder-block duration | Time within each transformer layer (us) | 02 |
| Prompt/response decoding latency | Time to decode prompt and response separately | 03 |
| Inference time | Total forward pass time (ms/s) | 07, 08, 10 |
| E2E request latency | Full request-to-response pipeline time | 01, 06 |

### 2.2 Throughput

| Metric | Definition | Papers |
|--------|-----------|--------|
| TPS (Tokens Per Second) | Token generation rate | 01, 02, 03 |
| QPS (Queries Per Second) | Maximum request rate meeting latency targets | 01 |
| RPS (Requests Per Second) | Sustained request throughput | 07, 10 |
| Operations per second (IOPS) | Storage I/O throughput | 10, 11 |
| Network throughput (Gbps) | TCP/UDP bandwidth | 10 |
| Inter-CVM throughput (MB/s) | Data transfer between confidential VMs | 05 |

### 2.3 Cost

| Metric | Definition | Papers |
|--------|-----------|--------|
| Cost per hour ($/hr) | Cloud instance rental cost | 02, 03, 07 |
| Cost per million tokens ($/M) | Economic cost of token generation | 02 |
| Cost per 100K tokens ($/100K) | Cost at smaller scale | 03 |
| Cloud cost to target performance | Hourly cost to achieve RPS/latency target | 07 |

### 2.4 TEE Overhead

| Metric | Definition | Papers |
|--------|-----------|--------|
| Throughput overhead (%) | Throughput reduction vs bare metal | 01, 02, 07, 10 |
| Latency overhead (%) | Latency increase vs bare metal | 01, 02, 08, 10 |
| Virtualization tax (%) | VM overhead independent of TEE | 02 |
| Hugepage penalty (%) | Impact of 2MB vs 1GB hugepages | 02 |
| Sub-NUMA clustering penalty (%) | Impact of SNC on TEE overhead | 02 |
| PCIe bounce buffer overhead | CPU-GPU encrypted transfer cost | 01, 02, 04 |
| VMEXIT latency increase (%) | VM exit instruction overhead | 10 |
| Boot time overhead (%) | CVM boot time vs standard VM | 08, 10 |
| Paging overhead (cycles, P99.9) | EPC paging tail latency | 11 |

### 2.5 Memory & Resources

| Metric | Definition | Papers |
|--------|-----------|--------|
| Memory bandwidth (GB/s) | MLC, STREAM, RAMSpeed benchmarks | 10, 11 |
| Memory random read latency (ns/cycles) | Random access latency | 10, 11 |
| NUMA access penalty (%) | Cross-node vs local access overhead | 11 |
| EPC paging overhead | Enclave page cache pressure | 02, 11 |
| GPU VRAM utilization (%) | GPU memory usage | 03 |
| CPU utilization (%) | Compute resource consumption | 07, 10 |
| Memory footprint reduction (%) | Savings from shared models | 05 |
| Enclave creation time (minutes) | Time to initialize enclave by heap size | 11 |
| Peak RSS (MB) | Maximum resident set size | 03 |

### 2.6 Model Quality & Safety

| Metric | Definition | Papers |
|--------|-----------|--------|
| MMLU accuracy (%) | Zero-shot classification accuracy | 03 |
| BERTScore (cosine similarity) | Summarization quality metric | 03 |
| Toxicity rate (%) | Fraction of toxic responses | 03 |
| Valid response rate | Fraction of parseable model outputs | 03 |
| MIA success rate reduction (%) | Membership inference attack mitigation | 08 |
| Output invariance | Lossless computation guarantee | 06 |

### 2.7 Security & Attestation

| Metric | Definition | Papers |
|--------|-----------|--------|
| Security level (SL1-SL5) | RAND classification for model protection | 04 |
| TCB size (KLoC, binary bytes) | Trusted computing base complexity | 10, 04 |
| CVE count by attack vector | Vulnerability classification | 10 |
| Attestation report generation (ms) | Time to produce attestation document | 10 |
| Certificate verification (ms) | Time to verify attestation certificates | 10 |
| Firmware code size increase (LoC, %) | TCB expansion metric | 05 |

---

## 3. Per-Paper Detailed Analysis

### Paper 01: NVIDIA Hopper cGPU Benchmark

**Source:** Zhu et al. (Phala Network, Fudan, io.net), arXiv:2409.03992v4

**Metrics:** TTFT, ITL, TPS, QPS, total latency, throughput overhead (%)

**Methodology:**
- vLLM v0.5.4 benchmark suite
- ShareGPT dataset for sequence length sampling
- TEE-on vs TEE-off direct comparison
- Batch sizes: 1, 4, 16, dynamic
- Models: Llama-3.1-8B, Phi-3-14B, Llama-3.1-70B (4-bit)

**Hardware:**
- H100 NVL (94GB) + AMD EPYC 9V84 + SEV-SNP
- H200 NVL (141GB) + Intel Xeon 8558 + TDX

**Key findings:**
- Average throughput overhead: <9%
- Overhead decreases with larger models and longer sequences
- Bottleneck: CPU-GPU PCIe data transfer, not GPU computation
- For 70B models: overhead approaches 0%
- TTFT overhead: 19-26% (dominated by I/O)

---

### Paper 02: Confidential LLM Inference — CPU and GPU TEEs

**Source:** Chrapek et al. (ETH Zurich), arXiv:2509.18886v1

**Metrics:** Throughput (tokens/s), next-token latency, per-decoder-block duration, overhead (%), cost per million tokens, cost per hour, RAG pipeline time, TLB/NUMA overhead

**Methodology:**
- Frameworks: IPEX (selected), vLLM, HF Transformers, llama.cpp
- Data types: bfloat16, int8, float32
- Batch sizes: 1 to 512; input sizes: 32 to 2048 tokens
- Models: Llama2-7B/13B/70B; verified on Llama3-8B, GPT-J-6B, Falcon-7B, Baichuan2-7B, Qwen-7B
- Configurations: bare metal, raw VM, TDX VM, SGX (Gramine v1.7), cGPU (H100)
- Cost analysis: GCP spot pricing

**Hardware:**
- Intel Xeon Gold 6530 (32 cores/socket), Intel Xeon Platinum 8580 (60 cores/socket)
- CPU TEEs: Intel SGX, Intel TDX
- GPU TEE: NVIDIA H100 NVL on Azure

**Key findings:**
- CPU TEE single-socket: SGX 4.8-6.2%, TDX 5.5-10.7%
- GPU TEE (cGPU): 4-8% throughput penalty
- CPU TEEs up to 100% cheaper than cGPUs at batch=1
- At batch=128, cost equalizes between CPU and GPU TEEs
- RAG pipeline overhead in TDX: 6-7%
- Sub-NUMA clustering can increase overhead from 5% to 42%
- AMX reduces TDX latency overhead by up to 30%

---

### Paper 03: Attestable Audits — Nitro Enclaves

**Source:** Schnabl et al. (Cambridge), arXiv:2506.23706v1

**Metrics:** Tokens/s, price/hr, price/100K tokens, BERTScore, toxicity rate, MMLU accuracy, valid response rate, memory overhead

**Methodology:**
- Rust + llama.cpp bindings
- AWS Nitro Enclaves
- Model: Llama-3.1-8B-Instruct (Q4_K_M)
- Benchmarks: MMLU, XSum (BERTScore), ToxicChat
- 500 prompts per benchmark, zero-shot
- Compared: Nitro (m5.2xlarge) vs GPU (L40S)

**Key findings:**
- Enclave throughput: 1.84 tokens/s vs 202 tokens/s (GPU) — 100x gap
- Cost: $5.80/100K tokens (enclave) vs $0.12/100K tokens (GPU) — 21.7x
- MMLU: 51.4% (enclave) vs 58.9% (GPU) — quantization penalty
- BERTScore: 0.47 (enclave) vs 0.58 (GPU)
- Toxicity: 2.4% (enclave) vs 2.6% (GPU) — comparable

**EphemeralML relevance:** **HIGHEST** — same platform, same constraints

---

### Paper 04: Confidential Inference Systems (Anthropic)

**Source:** Pattern Labs + Anthropic, Whitepaper v1.0

**Metrics:** None quantitative. Defines security levels SL1-SL5, PCR measurements, attack surface evaluation, confidential boundary scope.

**EphemeralML relevance:** Threat model alignment, design principles validation

---

### Paper 05: Inter-CVM Communication (CAEC)

**Source:** Abdollahi et al. (Imperial, Dartmouth), arXiv:2512.01594v2

**Metrics:** CPU cycles/message, median latency (us), throughput (MB/s), memory footprint (MB), firmware size increase (LoC)

**Key findings:**
- CAEC achieves up to 209x reduction in CPU cycles vs OpenSSL inter-CVM communication
- Memory footprint reduction: 16.6-28.3% via shared model memory
- Zero inference-time overhead from shared memory architecture
- Firmware size increase: 4% (1,062 LoC)

**EphemeralML relevance:** Low (single enclave; no inter-CVM in v1)

---

### Paper 06: Confidential Prompting (Petridish/SPD)

**Source:** Li et al. (Yale), arXiv:2409.19134v5

**Metrics:** Normalized end-to-end latency, per-token latency, latency breakdown by component, GPU memory footprint, communication overhead

**Key findings:**
- SPD achieves 5x better latency than per-user CVM isolation
- GPU CC communication overhead dominates (disabling CC reduces latency to ~1/3)
- Output invariance maintained (mathematically lossless)
- Input/output token count has negligible impact on per-token latency

**EphemeralML relevance:** Low (GPU-specific split inference architecture)

---

### Paper 07: TEE Benchmarks — SGX, SEV, TDX

**Source:** Coppolino et al. (Parthenope), arXiv:2408.00443

**Metrics:** Inference time (ms), throughput (RPS), normalized latency, CPU utilization (%), cloud cost/hour, overhead %

**Methodology:**
- CPU normalization (AMD 40.7% slower baseline)
- Workloads: CPU-intensive (PyTorch, TensorFlow), memory-intensive (Redis, Vault), I/O-intensive (NGINX, NodeJS)
- Tools: redis-benchmark, wrk2, vault-benchmark
- 10 reps, 95% CI

**Hardware:** TDX (Xeon 8480C), SEV (EPYC 7763), SGX (Gramine v1.6, Occlum v0.30.0)

**Key findings:**
- TDX closest to native; SEV ~22% worse than TDX (after CPU normalization)
- Gramine-SGX: near-native for CPU-intensive; 67.6% overhead for I/O-intensive
- Occlum-SGX: worst performer across most workloads
- SGX VMs most expensive; TDX middle; SEV cheapest

---

### Paper 08: Arm CCA On-Device

**Source:** Abdollahi et al. (Imperial, NYU), arXiv:2504.08508

**Metrics:** Instructions executed (millions), per-stage overhead %, boot/termination overhead %, MIA success rate reduction

**Key findings:**
- Inference overhead: 17-22% (AlexNet through TinyLlama-1.1B)
- Boot overhead: 867-1,902% (one-time cost)
- MIA success rate reduction: 8.3% average
- Main overhead source: Realm Monitor (RMM) at EL2

**EphemeralML relevance:** Low (different platform; simulation only)

---

### Paper 09: Intel Confidential AI Whitepaper

**Source:** Intel (O'Neill, Hopkins, Schrater)

**No quantitative metrics.** Strategic overview of Intel TDX, SGX, AMX, TDX Connect.

---

### Paper 10: SEV-SNP and TDX — SIGMETRICS 2024

**Source:** Misono et al. (TUM), ACM Meas. Anal. Comput. Syst. 8(3)

**Most comprehensive benchmarking paper.** Covers boot time, VMEXIT latency, memory performance, compute benchmarks, network I/O, storage I/O, attestation, TCB/CVE analysis.

**Key findings:**
- Boot overhead: SEV-SNP +102%, TDX +394%
- VMEXIT latency: SEV-SNP +240%, TDX +472%
- Memory bandwidth: SEV-SNP +2.9%, TDX +7.9%
- TensorFlow BERT (with idle polling): SEV-SNP +2.3%, TDX +4.3%
- Attestation report: SEV-SNP 6.19ms, TDX 2.75ms
- CVEs: 49 for AMD SEV, 9 for TDX

---

### Paper 11: SGXv2 Benchmarks — DaMoN 2022

**Source:** El-Hindi et al. (TU Darmstadt)

**Metrics:** B-Tree throughput, NUMA access latency (cycles), paging tail latency (P99.9), sequential scan bandwidth, I/O cost (cycles/byte), enclave creation time

**Key findings:**
- Trusted local NUMA: +32.2% latency; cross NUMA: +46.3%
- Overall trusted execution: ~25% max overhead when data fits EPC
- SGXv2 EPC: 64GB/socket vs SGXv1 128MB — 500x improvement
- Paging tail latency: 2 orders of magnitude increase outside EPC

---

## 4. Relevance Ranking for EphemeralML

| Rank | Paper | Relevance | Reason |
|------|-------|-----------|--------|
| 1 | 03 (Nitro Audits) | **Direct** | Same platform, same constraints |
| 2 | 02 (ETH CPU/GPU) | **High** | CPU TEE cost analysis, methodology |
| 3 | 04 (Anthropic) | **High** | Threat model alignment |
| 4 | 07 (SGX/SEV/TDX) | **Medium** | Cross-TEE methodology reference |
| 5 | 10 (SIGMETRICS) | **Medium** | Microbenchmark methodology |
| 6 | 01 (NVIDIA cGPU) | **Low** | GPU-specific; overhead methodology useful |
| 7 | 11 (SGXv2) | **Low** | SGX-specific memory patterns |
| 8 | 05 (Inter-CVM) | **Low** | Different architecture (multi-CVM) |
| 9 | 06 (Petridish) | **Low** | GPU split inference |
| 10 | 08 (Arm CCA) | **Low** | Different platform, simulation only |
| 11 | 09 (Intel WP) | **Minimal** | No metrics; ecosystem context only |

---

## 5. Key Takeaways for EphemeralML

1. **No prior work publishes per-inference latency on Nitro Enclaves.** Paper 03 measures
   throughput (1.84 t/s) and cost (21.7x vs GPU) but not overhead % vs bare-metal CPU.
   EphemeralML can be first.

2. **CPU TEE overhead is 5-10% for inference** (papers 02, 07). Nitro Enclaves should be
   in this range or better (lighter isolation model than TDX/SGX).

3. **CPU TEEs are cheaper than GPU TEEs at batch=1** (paper 02). This is EphemeralML's
   operating point — single-request confidential inference.

4. **Cold start is a real differentiator** (papers 03, 10). LibOS containers take minutes;
   EphemeralML targets <5 seconds.

5. **Quality preservation needs measurement** (paper 03). Quantization to fit enclave
   memory degrades MMLU by ~7pp and BERTScore by ~0.11. EphemeralML must quantify this.

6. **Memory is the binding constraint** (papers 03, 11). Nitro enclaves are fixed-memory;
   models must fit entirely. SGXv2 showed paging causes 2 orders of magnitude latency spike.
