[![CI](https://github.com/cyntrisec/EphemeralML/actions/workflows/ci.yml/badge.svg)](https://github.com/cyntrisec/EphemeralML/actions/workflows/ci.yml)

# EphemeralML

Confidential AI inference with per-inference cryptographic receipts.

Every inference runs inside a hardware-isolated enclave. Every inference produces a signed receipt — model identity, data hashes, hardware attestation — verifiable offline.

`AWS Nitro` · `GCP Confidential Space (TDX)` · `NVIDIA H100 CC` · `Rust` · `Apache 2.0`

---

**[cyntrisec.com](https://cyntrisec.com)** · **[Docs](https://cyntrisec.com/docs)** · **[Trust Center](https://verify.cyntrisec.com)** · **[AIR v1 Spec](spec/v1/README.md)**

---

## What exists

| | |
|---|---|
| Runtime | Multi-cloud E2E paths, OpenAI-compatible gateway, per-inference AIR receipts |
| Validated | AWS Nitro, GCP TDX, GCP H100 CC — 500+ tests, CI green |
| Moat | Receipt format + verifier + compliance layer — not raw TEE infra |
| Missing | External AIR implementors, design-partner revenue, pipeline-proof chaining |

Start here:

1. [`spec/v1/README.md`](spec/v1/README.md) — AIR v1 frozen spec
2. [`QUICKSTART.md`](QUICKSTART.md) — fastest proof path
3. [`docs/benchmarks.md`](docs/benchmarks.md) — performance
4. [`docs/design.md`](docs/design.md) — threat model

## Repository Layout

The repository is intentionally split between product crates, standards artifacts, deployment tooling, and publication-grade evidence:

| Path | Purpose |
|------|---------|
| `common/`, `client/`, `host/`, `enclave/`, `gateway-api/`, `verifier-api/`, `compliance/` | Main Rust workspace crates for runtime, gateway, verifier, and compliance flows |
| `spec/v1/` | Frozen AIR v1 normative specification and vectors |
| `docs/` | Architecture, benchmark methodology, production notes, and publication-facing documentation |
| `scripts/`, `infra/`, `manifests/` | Operational helpers and deployment scaffolding |
| `site/pages-root/` | GitHub Pages source for the legacy repo-domain redirect to `https://cyntrisec.com/docs` |
| `evidence/`, `artifacts/benchmarks/`, `demo-artifacts/` | Reproducibility artifacts and public benchmark/evaluation bundles |

Open-source boundary note:
- verifier logic, AIR v1, public demos, and reproducible evidence stay public
- managed-service operations, live infrastructure inventory, and pre-interface moat work stay private
- the static `cyntrisec.com` marketing/docs site now lives in a separate private web repo
- see [`docs/OPEN_SOURCE_BOUNDARY.md`](docs/OPEN_SOURCE_BOUNDARY.md)

## Local Disk Hygiene

The Git repository is small, but a working checkout can grow quickly because local build and model caches live next to the source tree.

Typical large directories:
- `target/` — Rust build output; safe to delete at any time
- `test_assets/` — local model weights and test fixtures; mostly ignored and re-downloadable
- `infra/**/.terraform/` — Terraform provider/plugin cache created by local infra work

Recommended local workflow:
- use [`scripts/cargo-local.sh`](scripts/cargo-local.sh) for day-to-day builds and tests so Cargo writes to `/tmp/ephemeralml-target` instead of the repo root
- treat `target/`, local model weights, and Terraform caches as disposable workspace state, not product source
- only keep large local assets you are actively using for a demo or pilot

For what to actively maintain versus freeze, see [`docs/REPO_MAINTENANCE_SCOPE.md`](docs/REPO_MAINTENANCE_SCOPE.md).

---

## Why EphemeralML?

| Problem | Solution |
|---------|----------|
| Cloud hosts can see your data | TEE isolation — data decrypted only inside the enclave |
| "Trust me" isn't enough | Cryptographic attestation — verify code before sending secrets |
| No audit trail | Per-inference receipts — signed proof of what ran and what it touched |

Built for: healthcare, finance, legal — anywhere audit evidence matters more than promises.

---

## AIR v1 (Open Receipt Format)

EphemeralML now includes **AIR v1 (Attested Inference Receipt)**, a standards-aligned receipt format
for proving a single AI inference happened in an attested confidential environment.

Naming / standards note:
- **AIR** here means **Attested Inference Receipt** (EphemeralML), not the IHE Radiology **AI Results (AIR)** profile.
- AIR v1 is an application-specific COSE/CWT + EAT-profile receipt format for confidential AI inference, including AI provenance claims such as `model_id`/`model_hash` and request/response hash binding.
- AIR v1 is **not** an implementation of IETF EAR. AIR v1 is workload-emitted execution evidence; EAR is verifier-emitted attestation results. They are complementary in a RATS-based architecture.

- Spec entrypoint: [`spec/v1/README.md`](spec/v1/README.md)
- Interop quick start: [`spec/v1/interop-kit.md`](spec/v1/interop-kit.md)
- CDDL schema: [`spec/v1/cddl/air-v1.cddl`](spec/v1/cddl/air-v1.cddl)
- Conformance vectors: [`spec/v1/vectors/`](spec/v1/vectors/)
- Implementation status / known gaps: [`spec/v1/implementation-status.md`](spec/v1/implementation-status.md)

AIR v1 is **single-inference only** (pipeline proof chaining is planned for vNEXT).

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

Three-layer trust model: environment attestation, workload identity, model integrity.

**Protected:** model weights, prompts/outputs, execution integrity.

**How:**
- Attestation-gated key release — KMS releases DEK only if enclave measurements match policy
- Attestation-bound encrypted sessions — X25519 + ChaCha20-Poly1305, host sees ciphertext only
- Ed25519 signed receipts — per-inference cryptographic proof
- Cross-platform transport — `confidential-ml-transport` on VSock (Nitro) and TCP (TDX)

**Threat model:**

| Threat | Outcome |
|--------|---------|
| Compromised host OS | Protected (enclave isolation) |
| Malicious cloud admin | Protected (can't decrypt) |
| Supply chain attack | Detected (measurement verification) |
| Model swap | Prevented (signed manifests) |

---

## Features

### Core (E2E-Validated, Hardening Ongoing)
- **AWS Nitro Enclave integration** with real NSM attestation and PCR-bound KMS key release
- **GCP Confidential Space integration** with Intel TDX attestation, MRTD/RTMR measurement pinning, and Cloud KMS key release
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
- **Attested Inference Receipts (AIR)** — Ed25519-signed, CBOR-canonical, binding input/output hashes to enclave attestation
- **Policy update system** with signature verification and hot-reload
- **Model format validation** (safetensors, dtype enforcement)
- **500+ tests** across the workspace and CI (including pipeline integration, GCP tests, and AIR v1 conformance vectors)
- **Deterministic builds** for reproducibility

---

## Performance

All benchmarks use MiniLM-L6-v2 (22.7M params) on AWS EC2 m6i.xlarge (4 vCPU, 16 GiB). Two measurement campaigns exist — see `docs/publication/claim_definitions.md` for full methodology and disambiguation.

### Inference Overhead

| Measurement | Bare Metal | Enclave | Overhead | Scope |
|-------------|-----------|---------|----------|-------|
| Fully instrumented (commit `b00bab1`, 100 iters) | 78.55ms | 88.45ms | **+12.6%** | Host-observed, includes VSock transport |
| Enclave execution (commit `f1ba30d`, 10 iters) | 74.61ms | 77.00ms | **+3.2%** | Enclave-side only, excludes transport |
| Host E2E latency (10-run mean) | — | 117.1ms | — | Full client round-trip |

The +12.6% and +3.2% measure different boundaries. The ~10ms gap is VSock transport overhead. See `docs/publication/claim_definitions.md` §4 for the full disambiguation diagram.

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

- **+3–13% inference overhead** depending on measurement boundary (enclave-execution-only vs host-observed-with-transport). On par with AMD SEV-SNP BERT numbers (~16%), competitive with SGX/TDX.
- **Multi-model campaign (2026-02-05, commit `b00bab1`)** — weighted mean +12.9% (MiniLM-L6 +14.0%, MiniLM-L12 +12.9%, BERT-base +11.9%). Historical; not reproducible on current main.
- **Per-inference crypto cost negligible** — 0.028ms per request (< 0.04% of inference time)
- **Throughput plateaus at ~14.7 inf/s** — CPU-bound on 2 vCPUs; latency scales linearly with concurrency
- **$4.11–4.72 per 1M inferences** in enclave (1.03–1.13x bare metal cost, depending on measurement)
- **3/3 cross-cloud E2E PASS** — AWS Nitro + GCP CPU TDX + GCP GPU H100 CC (functional + security validation, not cross-provider overhead comparison)

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
./scripts/check_kms_integrity.sh path/to/generated/kms_validation_*/run_*
```

### Publish Public Artifact (Reader-Friendly)

To publish benchmark evidence without requiring reader AWS access:

```bash
# 1) Package + scan for sensitive markers
./scripts/prepare_public_artifact.sh \
  --input-dir path/to/generated/kms_validation_<timestamp> \
  --name kms_validation_<timestamp>.tar.gz

# 2) Upload to a GitHub Release tag
./scripts/publish_public_artifact.sh \
  --tag v1.0.0 \
  --artifact artifacts/public/kms_validation_<timestamp>.tar.gz
```

See [`docs/ARTIFACT_PUBLICATION.md`](docs/ARTIFACT_PUBLICATION.md) for full details.

Public/private repo boundary note: [`docs/OPEN_SOURCE_BOUNDARY.md`](docs/OPEN_SOURCE_BOUNDARY.md).

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
| Pipeline Orchestrator | Production | 10 |
| Stage Executor | Production | 1 |
| NSM Attestation (AWS) | Production | 11 |
| TDX Attestation (GCP) | Production | — |
| KMS Integration (AWS) | Production | — |
| GCP KMS / WIP | Code exists, not wired into runtime | — |
| Inference Engine (Candle) | Production | 4 |
| Receipt Signing (Ed25519) | Production | 6 |
| Common / Types | Production | 42 |
| Host / Client | Production | 4 |
| Degradation Policies | Production | 3 |
| GCS Model Loader | Implemented | — |
| GPU Inference (H100 CC, CUDA 12.2) | Verified on hardware | — |
| TDX Verifier Bridge (Client) | Implemented | — |

**v3.1 GPU Confidential** — GPU inference on GCP Confidential Space (a3-highgpu-1g, NVIDIA H100 CC-mode) with Llama 3 8B Q4_K_M GGUF, CUDA 12.2, TDX attestation, and Ed25519-signed receipts. GCS loader supports up to 16GB models with Content-Length pre-check. CI green.

---

## Documentation

- [`docs/README.md`](docs/README.md) — Documentation index and audience-oriented entry points
- [`docs/design.md`](docs/design.md) — Architecture & threat model
- [`docs/build-matrix.md`](docs/build-matrix.md) — Deployment modes, feature flags & build commands (AWS, GCP, mock)
- [`docs/benchmarks.md`](docs/benchmarks.md) — Benchmark methodology, results & competitive analysis
- [`docs/BENCHMARK_SPEC.md`](docs/BENCHMARK_SPEC.md) — Benchmark specification (11-paper literature review)
- [`QUICKSTART.md`](QUICKSTART.md) — Deployment guide
- [`docs/OPEN_SOURCE_BOUNDARY.md`](docs/OPEN_SOURCE_BOUNDARY.md) — What stays public vs private in this repo
- [`docs/security-demo.md`](docs/security-demo.md) — Security walkthrough
- [`docs/infra.md`](docs/infra.md) — Infrastructure notes and Nitro deployment loop
- [`scripts/run_final_kms_validation.sh`](scripts/run_final_kms_validation.sh) — Multi-run KMS-enforced benchmark validation
- [`scripts/check_kms_integrity.sh`](scripts/check_kms_integrity.sh) — Post-run KMS/commit/hardware integrity audit
- [`scripts/final_release_gate.sh`](scripts/final_release_gate.sh) — Single-command release gate for benchmark artifacts

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

---

<div align="center">

[cyntrisec.com](https://cyntrisec.com) · [Documentation](docs/) · [Benchmarks](docs/benchmarks.md) · [Issues](https://github.com/cyntrisec/EphemeralML/issues)

</div>
