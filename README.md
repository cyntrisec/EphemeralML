```
 ▄████▄    ███████╗██████╗ ██╗  ██╗███████╗███╗   ███╗███████╗██████╗  █████╗ ██╗     ███╗   ███╗██╗
██▀██▀██   ██╔════╝██╔══██╗██║  ██║██╔════╝████╗ ████║██╔════╝██╔══██╗██╔══██╗██║     ████╗ ████║██║
██ ██ ██   █████╗  ██████╔╝███████║█████╗  ██╔████╔██║█████╗  ██████╔╝███████║██║     ██╔████╔██║██║
████████   ██╔══╝  ██╔═══╝ ██╔══██║██╔══╝  ██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║██║     ██║╚██╔╝██║██║
██▄██▄██   ███████╗██║     ██║  ██║███████╗██║ ╚═╝ ██║███████╗██║  ██║██║  ██║███████╗██║ ╚═╝ ██║███████╗
 ▀ ▀▀ ▀    ╚══════╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚══════╝
```

[![CI](https://github.com/cyntrisec/EphemeralML/actions/workflows/ci.yml/badge.svg)](https://github.com/cyntrisec/EphemeralML/actions/workflows/ci.yml)
[![Status](https://img.shields.io/badge/Status-v3.1%20GPU%20Confidential-brightgreen?style=for-the-badge)](https://github.com/cyntrisec/EphemeralML/releases/tag/v3.1.0)
[![Tests](https://img.shields.io/badge/Tests-105%20Passing-success?style=for-the-badge)](https://github.com/cyntrisec/EphemeralML/actions/workflows/ci.yml)
[![Platform](https://img.shields.io/badge/Platform-AWS%20Nitro%20|%20GCP%20TDX%20|%20GPU%20H100-orange?style=for-the-badge&logo=amazon-aws)](https://aws.amazon.com/ec2/nitro/nitro-enclaves/)
[![Language](https://img.shields.io/badge/Language-Rust-b7410e?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/Apache%202.0-blue?style=for-the-badge)](LICENSE)

# EphemeralML

**Confidential AI inference with hardware-backed attestation — multi-cloud**

> Run AI models where prompts and weights stay encrypted — even if the host is compromised. Deploys on AWS Nitro Enclaves, GCP Confidential Space (Intel TDX), and GPU TEEs (NVIDIA H100 CC-mode).

---

## Why EphemeralML?

| Problem | Solution |
|---------|----------|
| Cloud hosts can see your data | **TEE isolation** — data decrypted only inside the enclave |
| "Trust me" isn't enough | **Cryptographic attestation** — verify code before sending secrets |
| No audit trail | **Execution receipts** — proof of what code processed your data |

**Built for**: Defense, GovCloud, Finance, Healthcare — anywhere "good enough" security isn't.

---

## Architecture

### AWS Nitro Enclaves

```
                        ┌──────────────────────────────────────────┐
                        │           Pipeline Orchestrator           │
┌─────────┐  HPKE      │  ┌─────────┐  SecureChannel  ┌────────┐ │
│  Client │◄───────────►│  │  Host   │◄──────────────►│Enclave │ │
└─────────┘  encrypted  │  │ (blind  │   attestation-  │Stage 0 │ │
                        │  │  relay) │   bound AEAD    └────────┘ │
                        │  └─────────┘                            │
                        └──────────────────────────────────────────┘
                               │                          │ NSM
                               │ S3                       ▼
                        ┌──────┴──────┐            ┌───────────────┐
                        │  Encrypted  │            │    AWS KMS    │
                        │   Models    │            │ (key release) │
                        └─────────────┘            └───────────────┘
```

### GCP Confidential Space (Intel TDX)

```
┌─────────┐  TDX-attested   ┌─────────────────────────────────────────┐
│  Client │◄────────────────►│  GCP Confidential Space CVM (TDX)      │
└─────────┘  SecureChannel   │  ┌───────────────────────────────────┐  │
                             │  │  EphemeralML Container             │  │
                             │  │  - TDX attestation (configfs-tsm)  │  │
                             │  │  - Inference + receipt signing      │  │
                             │  │  - Direct HTTPS to GCS / Cloud KMS │  │
                             │  └───────────────────────────────────┘  │
                             └─────────────────────────────────────────┘
                                     │                    │ TDX quote
                                     │ GCS               ▼
                              ┌──────┴──────┐     ┌──────────────────┐
                              │  Encrypted  │     │ Cloud KMS (WIP)  │
                              │   Models    │     │ (key release)    │
                              └─────────────┘     └──────────────────┘
```

### GCP Confidential Space — GPU (a3-highgpu-1g + H100 CC)

```
┌─────────┐  TDX-attested   ┌──────────────────────────────────────────────┐
│  Client │◄────────────────►│  GCP Confidential Space CVM (TDX + H100 CC) │
└─────────┘  SecureChannel   │  ┌────────────────────────────────────────┐  │
                             │  │  EphemeralML Container (CUDA 12.2)     │  │
                             │  │  - TDX attestation (configfs-tsm)      │  │
                             │  │  - GGUF model loaded from GCS          │  │
                             │  │  - GPU inference (candle-cuda, H100)   │  │
                             │  │  - Receipt signing (Ed25519)           │  │
                             │  └────────────────────────────────────────┘  │
                             └──────────────────────────────────────────────┘
                                     │                    │ TDX quote
                                     │ GCS               ▼
                              ┌──────┴──────┐     ┌──────────────────┐
                              │  GGUF Model │     │ Cloud KMS (WIP)  │
                              │  (≤16 GB)   │     │ (key release)    │
                              └─────────────┘     └──────────────────┘
```

**Key insight**: Host never has keys. On AWS, it just forwards ciphertext. On GCP, the entire CVM is the trust boundary — no host/enclave split, no VSock. GPU deployments use NVIDIA H100 in CC-mode (attestation confirms `nvidia_gpu.cc_mode: ON`). The pipeline layer (`confidential-ml-pipeline`) orchestrates multi-stage inference with per-stage attestation.

---

## Security Model

### What's Protected
- ✅ **Model weights** (IP protection)
- ✅ **Prompts & outputs** (PII / classified data)
- ✅ **Execution integrity** (verified code)

### How
1. **Attestation-gated key release** — KMS releases DEK only if enclave measurements match policy (PCRs on Nitro, MRTD/RTMRs on TDX)
2. **HPKE encrypted sessions** — end-to-end encryption, host sees only ciphertext
3. **Ed25519 signed receipts** — cryptographic proof of execution
4. **Cross-platform transport** — `confidential-ml-transport` handles attestation-bound channels on both VSock (Nitro) and TCP (TDX)

### Threat Model
- ✓ Compromised host OS → **Protected** (enclave isolation)
- ✓ Malicious cloud admin → **Protected** (can't decrypt)
- ✓ Supply chain attack → **Detected** (PCR verification)
- ✓ Model swap attack → **Prevented** (signed manifests)

---

## Features

### Core (Production Ready)
- **AWS Nitro Enclave integration** with real NSM attestation and PCR-bound KMS key release
- **GCP Confidential Space integration** with Intel TDX attestation, MRTD/RTMR measurement pinning, and Cloud KMS key release (`GcpKmsClient` implemented, not yet wired into runtime model-loading path)
- **Pipeline orchestration** via `confidential-ml-pipeline` — multi-stage inference with per-stage attestation, health checks, and graceful shutdown
- **Cross-platform transport** via `confidential-ml-transport` — attestation-bound SecureChannel with pluggable TCP/VSock backends
- **S3 model storage** (AWS) and **GCS model storage** (GCP) with client-side encryption

### Inference Engine
- **Candle-based** transformer inference (MiniLM, BERT, Llama)
- **GGUF support** for quantized models (int4, int8) — used for GPU inference (Llama 3 8B Q4_K_M)
- **CUDA 12.2 GPU inference** via candle-cuda on NVIDIA H100 CC-mode (a3-highgpu-1g)
- **BF16/safetensors** format enforcement (CPU path)
- Memory-optimized for TEE constraints

### Security & Compliance
- **Attested Execution Receipts** (AER) — Ed25519-signed, CBOR-canonical, binding input/output hashes to enclave attestation
- **Policy update system** with signature verification and hot-reload
- **Model format validation** (safetensors, dtype enforcement)
- **105 tests** across 4 workspace crates (including pipeline integration and GCP tests)
- **Deterministic builds** for reproducibility

---

## Performance

Measured on AWS EC2 m6i.xlarge (4 vCPU, 16GB RAM) with MiniLM-L6-v2 (22.7M params), 3 independent runs of 100 iterations each. Commit `b00bab1`. Paper (\S7) uses canonical release-gate data from commit `057a85a`. Raw JSON available in [GitHub Releases](https://github.com/cyntrisec/EphemeralML/releases).

### Inference Overhead

| Metric | Bare Metal | Nitro Enclave | Overhead |
|--------|-----------|---------------|----------|
| Mean latency | 78.55ms | 88.45ms | **+12.6%** |
| P95 latency | 79.09ms | 89.58ms | +13.3% |
| Throughput | 12.73 inf/s | 11.31 inf/s | -11.2% |

### Cold Start Breakdown

| Stage | Time |
|-------|------|
| NSM Attestation | 88ms |
| KMS Key Release | 76ms |
| Model Fetch (S3→VSock) | 6,716ms |
| Model Decrypt + Load | 139ms |
| **Total** | **7,052ms** |

### Security Primitives

| Operation | Latency | Frequency |
|-----------|---------|-----------|
| COSE attestation verification | 3.012ms | Once per session |
| HPKE session setup | 0.10ms | Once per session |
| HPKE encrypt + decrypt (1KB) | 0.006ms | Per inference |
| Receipt sign (CBOR + Ed25519) | 0.022ms | Per inference |
| **Total per-inference crypto** | **0.028ms** | Per inference |

### E2E Encrypted Request Overhead

| Component | Latency |
|-----------|---------|
| Per-request crypto (encrypt+decrypt+receipt) | 0.164ms |
| Session setup (keygen+HPKE) | 0.138ms |
| TCP handshake (ClientHello→ServerHello→HPKE) | 0.153ms |

### Concurrency Scaling (bare metal, m6i.xlarge)

| Threads | Throughput | Mean Latency | Scaling Efficiency |
|---------|-----------|-------------|-------------------|
| 1 | 12.75 inf/s | 78ms | 100% |
| 2 | 14.73 inf/s | 136ms | 57.8% |
| 4 | 14.66 inf/s | 270ms | 28.8% |
| 8 | 14.57 inf/s | 546ms | 14.3% |

### Cost Analysis (m6i.xlarge @ $0.192/hr)

| Metric | Bare Metal | Enclave |
|--------|-----------|---------|
| Cost per 1M inferences | $4.19 | $4.72 |
| Enclave cost multiplier | — | 1.13x |

### Key Findings

- **~12.6% inference overhead** — on par with AMD SEV-SNP BERT numbers (~16%), competitive with SGX/TDX
- **Latest 3-model campaign (2026-02-05)** — weighted mean overhead **+12.9%** (MiniLM-L6 +14.0%, MiniLM-L12 +12.9%, BERT-base +11.9%)
- **Embedding quality preserved** — near-identical embeddings (cosine similarity ≈ 1.0; tiny FP-level differences expected across CPU allocations)
- **Per-inference crypto cost negligible** — 0.028ms vs 88ms inference (0.03%)
- **E2E crypto overhead** — 0.164ms per request (0.19% of inference time)
- **Throughput plateaus at ~14.7 inf/s** — CPU-bound on 2 vCPUs; latency scales linearly with concurrency
- **$4.72 per 1M inferences** in enclave (1.13x bare metal cost)
- **First published per-inference latency benchmark on AWS Nitro Enclaves**

### GPU Performance (GCP Confidential Space, H100 CC-mode)

Measured on GCP a3-highgpu-1g (1x NVIDIA H100, TDX CC-mode ON) with Llama 3 8B Q4_K_M GGUF (4.6GB fetched from GCS at runtime).

| Metric | Value |
|--------|-------|
| Model | Llama 3 8B Q4_K_M (GGUF, 4.6GB) |
| Machine | a3-highgpu-1g (1x H100, TDX) |
| Boot to ready | ~3.5 min |
| 50 tokens generated | 12s (241ms/token) |
| Attestation | TDX quote, `nvidia_gpu.cc_mode: ON` |
| Receipt | Ed25519-signed, CBOR-canonical |

**Critical**: GCP Confidential Space GPU uses cos-gpu-installer v2.5.3, which installs driver 535.247.01. This driver supports CUDA <= 12.2 only. Using CUDA 12.6+ fails with `CUDA_ERROR_UNSUPPORTED_PTX_VERSION`. The `Dockerfile.gpu` must use `nvidia/cuda:12.2.2-devel-ubuntu22.04` as the base image.

See [`docs/benchmarks.md`](docs/benchmarks.md) for methodology, competitive analysis, and literature comparison.

### KMS Attestation Audit Results

Verified on real Nitro hardware (m6i.xlarge, Feb 2026) using a KMS key with `kms:RecipientAttestation:ImageSha384` condition and key-policy-only evaluation (no root account statement, no IAM bypass path).

**Debug vs non-debug mode:** Enclaves launched with `--debug-mode` have all PCR values zeroed in their attestation documents. PCR-conditioned KMS policies cannot match in debug mode — the condition compares the policy's PCR0 hash against all-zeros, which never matches. Production (non-debug) enclaves carry real PCR values derived from the EIF contents.

**PCR0 enforcement evidence (non-debug mode):**

| Scenario | Result |
|----------|--------|
| Correct PCR0, valid attestation | Success (key released) |
| Wrong PCR0, valid attestation | `AccessDeniedException` |
| No attestation (recipient absent) | `AccessDeniedException` |
| Malformed attestation (random bytes) | `ValidationException` |
| Bit-flipped attestation (1 byte changed) | `ValidationException` |

CloudTrail confirms non-zero `attestationDocumentEnclaveImageDigest` for successful calls and no recipient data for denied calls.

**Replay semantics:** KMS accepts replayed attestation documents — resubmitting a previously successful attestation doc produces another successful key release. KMS validates the COSE_Sign1 signature and PCR values but does not enforce freshness (no nonce binding or timestamp check on the attestation document itself).

### Final Benchmark Release Gate (KMS-Enforced)

Use the single-command gate on your Nitro EC2 instance:

```bash
./scripts/final_release_gate.sh --runs 3 --model-id minilm-l6
```

This chains:
1. `scripts/run_final_kms_validation.sh` with `--require-kms`
2. `scripts/check_kms_integrity.sh` against produced `run_*` directories
3. Final manifest + summary output

For ad-hoc auditing of existing result directories:

```bash
./scripts/check_kms_integrity.sh benchmark_results_final/kms_validation_*/run_*
```

### Publish Public Artifact (Reader-Friendly)

To publish benchmark evidence without requiring reader AWS access:

```bash
# 1) Package + scan for sensitive markers
./scripts/prepare_public_artifact.sh \
  --input-dir benchmark_results_final/kms_validation_20260205_234917 \
  --name kms_validation_20260205_234917.tar.gz

# 2) Upload to a GitHub Release tag
./scripts/publish_public_artifact.sh \
  --tag v1.0.0 \
  --artifact artifacts/public/kms_validation_20260205_234917.tar.gz
```

See [`docs/ARTIFACT_PUBLICATION.md`](docs/ARTIFACT_PUBLICATION.md) for full details.

---

## Quick Start

### Local Demo (Mock Mode)

Run a working end-to-end demo locally — loads MiniLM-L6-v2, sends text, gets 384-dim embeddings + a signed Attested Execution Receipt:

```bash
bash scripts/demo.sh
```

Or manually:

```bash
# Terminal 1: Start enclave with model
cargo run --release --features mock --bin ephemeral-ml-enclave -- \
    --model-dir test_assets/minilm --model-id stage-0

# Terminal 2: Run host inference
cargo run --release --features mock --bin ephemeral-ml-host
```

### Production (AWS Nitro Enclaves)

Prerequisites: AWS account with Nitro Enclave support, Rust 1.75+, Terraform.

```bash
# 1. Provision infrastructure
cd infra/hello-enclave
terraform init && terraform apply

# 2. Build enclave image
docker build -f enclave/Dockerfile.enclave -t ephemeral-ml-enclave .
nitro-cli build-enclave --docker-uri ephemeral-ml-enclave:latest --output-file enclave.eif

# 3. Run
nitro-cli run-enclave --eif-path enclave.eif --cpu-count 2 --memory 4096
```

### Production (GCP Confidential Space — CPU)

Prerequisites: GCP project with Confidential Computing API enabled, c3-standard-4 (TDX), Rust 1.75+.

```bash
# Build for GCP (no mock, no default features)
cargo build --release --no-default-features --features gcp -p ephemeral-ml-enclave

# Run on CVM (--gcp flag required to enter GCP code path)
./target/release/ephemeral-ml-enclave \
    --gcp --model-dir /app/model --model-id stage-0
```

### Production (GCP Confidential Space — GPU)

Prerequisites: GCP project with a3-highgpu-1g quota, NVIDIA H100 CC-mode. Requires CUDA 12.2 (not 12.6+).

```bash
# Build GPU container (CUDA 12.2 base — required for CS driver 535.x)
docker build -f Dockerfile.gpu -t ephemeral-ml-gpu .

# Deploy to Confidential Space with GPU
bash scripts/gcp/deploy.sh --gpu \
    --model-source gcs \
    --model-format gguf
```

Expected boot timeline: ~3.5 min (image pull + cos-gpu-installer + model fetch from GCS). Llama 3 8B Q4_K_M generates 50 tokens in 12s.

See [`QUICKSTART.md`](QUICKSTART.md) and [`docs/build-matrix.md`](docs/build-matrix.md) for detailed instructions.

---

## Project Status

| Component | Status | Tests |
|-----------|--------|-------|
| Pipeline Orchestrator | ✅ Production | 10 |
| Stage Executor | ✅ Production | 1 |
| NSM Attestation (AWS) | ✅ Production | 11 |
| TDX Attestation (GCP) | ✅ Production | — |
| KMS Integration (AWS) | ✅ Production | — |
| GCP KMS / WIP | ⚠ Code exists, not wired into runtime | — |
| Inference Engine (Candle) | ✅ Production | 4 |
| Receipt Signing (Ed25519) | ✅ Production | 6 |
| Common / Types | ✅ Production | 42 |
| Host / Client | ✅ Production | 4 |
| Degradation Policies | ✅ Production | 3 |
| GCS Model Loader | ✅ Implemented | — |
| GPU Inference (H100 CC, CUDA 12.2) | ✅ Verified on hardware | — |
| TDX Verifier Bridge (Client) | ✅ Implemented | — |

**v3.1 GPU Confidential** — GPU inference on GCP Confidential Space (a3-highgpu-1g, NVIDIA H100 CC-mode) with Llama 3 8B Q4_K_M GGUF, CUDA 12.2, TDX attestation, and Ed25519-signed receipts. GCS loader supports up to 16GB models with Content-Length pre-check. 105 tests passing.

---

## Documentation

- [`docs/design.md`](docs/design.md) — Architecture & threat model
- [`docs/build-matrix.md`](docs/build-matrix.md) — Deployment modes, feature flags & build commands (AWS, GCP, mock)
- [`docs/benchmarks.md`](docs/benchmarks.md) — Benchmark methodology, results & competitive analysis
- [`docs/BENCHMARK_SPEC.md`](docs/BENCHMARK_SPEC.md) — Benchmark specification (11-paper literature review)
- [`QUICKSTART.md`](QUICKSTART.md) — Deployment guide
- [`SECURITY_DEMO.md`](SECURITY_DEMO.md) — Security walkthrough
- [`scripts/run_final_kms_validation.sh`](scripts/run_final_kms_validation.sh) — Multi-run KMS-enforced benchmark validation
- [`scripts/check_kms_integrity.sh`](scripts/check_kms_integrity.sh) — Post-run KMS/commit/hardware integrity audit
- [`scripts/final_release_gate.sh`](scripts/final_release_gate.sh) — Single-command release gate for benchmark artifacts

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

---

<div align="center">

**Run inference like the host is already hacked.**

[Documentation](docs/) • [Benchmarks](docs/benchmarks.md) • [Issues](https://github.com/cyntrisec/EphemeralML/issues)

</div>
