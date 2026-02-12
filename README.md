[![CI](https://github.com/cyntrisec/EphemeralML/actions/workflows/ci.yml/badge.svg)](https://github.com/cyntrisec/EphemeralML/actions/workflows/ci.yml)
[![Status](https://img.shields.io/badge/Status-v1.0%20Complete-brightgreen?style=for-the-badge)](https://github.com/cyntrisec/EphemeralML/releases/tag/v1.0.0)
[![Tests](https://img.shields.io/badge/Tests-99%20Passing-success?style=for-the-badge)](https://github.com/cyntrisec/EphemeralML/actions/workflows/ci.yml)
[![Platform](https://img.shields.io/badge/Platform-AWS%20Nitro%20Enclaves-orange?style=for-the-badge&logo=amazon-aws)](https://aws.amazon.com/ec2/nitro/nitro-enclaves/)
[![Language](https://img.shields.io/badge/Language-Rust-b7410e?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/Apache%202.0-blue?style=for-the-badge)](LICENSE)

# 🔒 EphemeralML

**Confidential AI inference with hardware-backed attestation**

> Run AI models where prompts and weights stay encrypted — even if the host is compromised.

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

**Key insight**: Host never has keys. It just forwards ciphertext. The pipeline layer (`confidential-ml-pipeline`) orchestrates multi-stage inference with per-stage attestation.

---

## Security Model

### What's Protected
- ✅ **Model weights** (IP protection)
- ✅ **Prompts & outputs** (PII / classified data)
- ✅ **Execution integrity** (verified code)

### How
1. **Attestation-gated key release** — KMS releases DEK only if enclave PCRs match policy
2. **HPKE encrypted sessions** — end-to-end encryption, host sees only ciphertext
3. **Ed25519 signed receipts** — cryptographic proof of execution

### Threat Model
- ✓ Compromised host OS → **Protected** (enclave isolation)
- ✓ Malicious cloud admin → **Protected** (can't decrypt)
- ✓ Supply chain attack → **Detected** (PCR verification)
- ✓ Model swap attack → **Prevented** (signed manifests)

---

## Features

### Core (Production Ready)
- **Nitro Enclave integration** with real NSM attestation
- **AWS KMS** key release via RSA-2048 SPKI handshake
- **Pipeline orchestration** via `confidential-ml-pipeline` — multi-stage inference with per-stage attestation, health checks, and graceful shutdown
- **Cross-platform transport** via `confidential-ml-transport` — attestation-bound SecureChannel with pluggable TCP/VSock backends
- **S3 model storage** with client-side encryption

### Inference Engine
- **Candle-based** transformer inference (MiniLM, BERT, Llama)
- **GGUF support** for quantized models (int4, int8)
- **BF16/safetensors** format enforcement
- Memory-optimized for TEE constraints

### Security & Compliance
- **Attested Execution Receipts** (AER) — Ed25519-signed, CBOR-canonical, binding input/output hashes to enclave attestation
- **Policy update system** with signature verification and hot-reload
- **Model format validation** (safetensors, dtype enforcement)
- **99 unit tests** across 6 crates (including pipeline integration tests)
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

See [`QUICKSTART.md`](QUICKSTART.md) for detailed instructions.

---

## Project Status

| Component | Status | Tests |
|-----------|--------|-------|
| Pipeline Orchestrator | ✅ Production | 10 |
| Stage Executor | ✅ Production | 1 |
| NSM Attestation | ✅ Production | 11 |
| KMS Integration | ✅ Production | — |
| Inference Engine (Candle) | ✅ Production | 4 |
| Receipt Signing (Ed25519) | ✅ Production | 6 |
| Common / Types | ✅ Production | 42 |
| Host / Client | ✅ Production | 4 |
| Degradation Policies | ✅ Production | 3 |

**v2.0 Pipeline Integration** — End-to-end inference working with `confidential-ml-pipeline` + `confidential-ml-transport`. 99 tests passing.

---

## Documentation

- [`docs/design.md`](docs/design.md) — Architecture & threat model
- [`docs/benchmarks.md`](docs/benchmarks.md) — Benchmark methodology, results & competitive analysis
- [`docs/BENCHMARK_SPEC.md`](docs/BENCHMARK_SPEC.md) — Benchmark specification (11-paper literature review)
- [`docs/tasks.md`](docs/tasks.md) — Implementation progress
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
