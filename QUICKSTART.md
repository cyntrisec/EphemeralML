# EphemeralML Quick Start Guide

## Install (one command)

```bash
curl -fsSL https://github.com/cyntrisec/EphemeralML/releases/latest/download/install.sh | bash
```

This installs `ephemeralml`, `ephemeralml-verify`, `ephemeralml-compliance`, and `ephemeralml-orchestrator` to `~/.ephemeralml/bin/`. Set `EPHEMERALML_INSTALL_DIR` to override the install location.

## Verify a Receipt

```bash
ephemeralml-verify receipt.json --public-key-file receipt.pubkey
```

## 5-Minute Local Demo (build from source)

```bash
git clone https://github.com/cyntrisec/EphemeralML && cd EphemeralML
bash scripts/demo.sh
```

This builds everything in mock mode, loads MiniLM-L6-v2 (22.7M params), runs inference, and returns a signed receipt.

## Full GCP GPU Deployment (one command)

```bash
export EPHEMERALML_GCP_PROJECT=your-project
bash scripts/gcp/mvp_gpu_e2e.sh --project $EPHEMERALML_GCP_PROJECT
```

This runs the complete 10-step golden path: KMS setup, model packaging, GPU deployment (a3-highgpu-1g + H100 CC), inference, receipt verification, compliance bundle, negative tests, and teardown. Add `--cpu-only` for c3-standard-4 (no GPU).

---

## Prerequisites

> **Tip**: Run `bash scripts/doctor.sh` to validate your environment before getting started.

1. **Install Rust**: Visit [rustup.rs](https://rustup.rs/) and follow the installation instructions.
2. **AWS CLI & Nitro CLI**: (For AWS production) Required to build EIF and run on Nitro instances.
3. **gcloud CLI**: (For GCP production) Required for Confidential Space deployment on c3-standard-4 TDX CVMs.
4. **CUDA 12.2**: (For GPU builds only) Must use CUDA 12.2 — GCP Confidential Space GPU ships driver 535.x which does not support CUDA 12.6+.

## Building the Project

### Mock Mode (Local Development)
```bash
cargo build --features mock
```

### Production Mode (AWS Nitro Enclaves)
```bash
cargo build --no-default-features --features production
```

### GCP Mode (Confidential Space / TDX)
```bash
cargo build --no-default-features --features gcp -p ephemeral-ml-enclave
cargo build --no-default-features --features gcp -p ephemeral-ml-client
```

### GCP GPU Mode (Confidential Space / TDX + H100 CC)
```bash
# Build via Dockerfile.gpu (recommended — pins CUDA 12.2.2)
docker build -f Dockerfile.gpu -t ephemeral-ml-gpu .

# Or build locally (requires CUDA 12.2 toolkit)
cargo build --release --no-default-features --features gcp,cuda -p ephemeral-ml-enclave
```

## Running the Demo

### One-command demo
```bash
bash scripts/demo.sh
```

This will:
1. Ensure MiniLM-L6-v2 model weights are present (symlinks or downloads from HuggingFace)
2. Build enclave and host binaries in release mode
3. Start the enclave stage worker (loads 87MB model, binds TCP ports)
4. Run the host orchestrator (connects, sends text, receives embeddings + receipt)
5. Print the Attested Execution Receipt with cryptographic bindings

### Manual Mode

**Terminal 1 — Start Enclave:**
```bash
cargo run --release --features mock --bin ephemeral-ml-enclave -- \
    --model-dir test_assets/minilm --model-id stage-0
```

**Terminal 2 — Run Host:**
```bash
cargo run --release --features mock --bin ephemeral-ml-host
```

### Expected Output

- Model loads in ~150-200ms
- Inference completes in ~70-120ms
- 384-dimensional embedding vector returned
- Signed Attested Execution Receipt with:
  - SHA-256 request/response/attestation hashes
  - PCR0/1/2 enclave measurements
  - Ed25519 signature

## Production Mode (GCP)

> For the complete 10-step golden path, see [`docs/PRODUCTION_GCP.md`](docs/PRODUCTION_GCP.md).

### Deploy with KMS-Gated Model (Recommended)

```bash
# 1. Setup infrastructure
bash scripts/gcp/setup.sh
bash scripts/gcp/setup_kms.sh

# 2. Package model (encrypts, signs manifest, uploads to GCS)
bash scripts/gcp/package_model.sh test_assets/minilm models/minilm \
    --model-id minilm-l6-v2 --version v1.0.0

# 3. Deploy to Confidential Space
bash scripts/gcp/deploy.sh \
    --model-source gcs-kms \
    --kms-key "$EPHEMERALML_GCP_KMS_KEY" \
    --wip-audience "$EPHEMERALML_GCP_WIP_AUDIENCE" \
    --model-hash "$EXPECTED_MODEL_HASH"
```

### Deploy GPU (a3-highgpu-1g + H100 CC)

```bash
# 1. Build GPU container (CUDA 12.2 — required for CS driver 535.x)
docker build -f Dockerfile.gpu -t ephemeral-ml-gpu .

# 2. Tag and push to Artifact Registry
docker tag ephemeral-ml-gpu "$REGION-docker.pkg.dev/$PROJECT/ephemeralml/ephemeral-ml-gpu:latest"
docker push "$REGION-docker.pkg.dev/$PROJECT/ephemeralml/ephemeral-ml-gpu:latest"

# 3. Deploy with GPU flag
bash scripts/gcp/deploy.sh --gpu \
    --model-source gcs \
    --model-format gguf
```

Boot timeline: ~3.5 min (image pull -> cos-gpu-installer -> model fetch from GCS).

Expected output with Llama 3 8B Q4_K_M (4.6GB GGUF):
- 50 tokens generated in ~12s (241ms/token)
- TDX attestation with `nvidia_gpu.cc_mode: ON`
- Ed25519-signed receipt returned to client

**CUDA version warning**: Confidential Space GPU uses cos-gpu-installer v2.5.3 which installs driver 535.247.01. This driver supports CUDA <= 12.2 only. Using CUDA 12.6+ produces `CUDA_ERROR_UNSUPPORTED_PTX_VERSION`. Always use `nvidia/cuda:12.2.2-devel-ubuntu22.04` as the base image.

## Production Mode (AWS)

See `infra/hello-enclave/HELLO_ENCLAVE_RUNBOOK.md` for a step-by-step guide to deploying on AWS Nitro Enclaves.

## Security Defaults (Fail-Closed)

EphemeralML defaults to **fail-closed** for all security-sensitive settings. Production deployments require real attestation; dev-only overrides must be explicitly opted in.

| Setting | Default | Dev override | What it controls |
|---------|---------|-------------|-----------------|
| MRTD peer pinning | Required (`EPHEMERALML_EXPECTED_MRTD`) | `EPHEMERALML_REQUIRE_MRTD=false` | Client-side TDX measurement verification |
| `--synthetic` flag | Rejected in release builds | Debug builds only | Entire attestation stack uses fake quotes |
| KMS IAM binding | Image digest condition required | `--allow-broad-binding` in `setup_kms.sh` | Which containers can decrypt model keys |

**Transport attestation vs KMS attestation**: These are separate trust anchors. The Launcher JWT (KMS attestation) is always hardware-backed in Confidential Space. Transport attestation (SecureChannel handshake) uses configfs-tsm TDX quotes when available, or the Launcher JWT via `CsTransportAttestationBridge` in Confidential Space containers where configfs-tsm is not exposed.

## GCP Architecture Differences

| Aspect | AWS Nitro | GCP TDX CVM |
|--------|-----------|-------------|
| Trust boundary | Enclave process (VSock isolated) | Entire CVM |
| Host process | Required (blind relay) | Not needed |
| Network | None (VSock only) | Full TCP/HTTPS |
| KMS auth | NSM attestation + RecipientInfo | WIP + Cloud KMS (attestation-bound) |
| Model loading | Host fetches S3, relays via VSock | CVM fetches GCS directly |
| Attestation | COSE_Sign1 (NSM) | TDX quote (configfs-tsm) |

## Verification

### Run all tests
```bash
cargo test --features mock
```

### Run specific test suites
```bash
# Pipeline integration tests
cargo test --features mock -p ephemeral-ml-enclave --test pipeline_integration_test

# Common crate tests (receipts, types, attestation)
cargo test --features mock -p ephemeral-ml-common
```

## Further Reading

- [`docs/build-matrix.md`](docs/build-matrix.md) — Feature flag compatibility matrix
- [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) — Trust model and HIPAA mapping
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) — Error codes and diagnostics
- [`docs/PRODUCTION_GCP.md`](docs/PRODUCTION_GCP.md) — Full GCP deployment guide
