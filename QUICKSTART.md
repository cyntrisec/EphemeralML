# EphemeralML Quick Start Guide

## Prerequisites

> **Tip**: Run `bash scripts/doctor.sh` to validate your environment before getting started.

1. **Install Rust**: Visit [rustup.rs](https://rustup.rs/) and follow the installation instructions.
2. **AWS CLI & Nitro CLI**: (For AWS production) Required to build EIF and run on Nitro instances.
3. **gcloud CLI**: (For GCP production) Required for Confidential Space deployment on c3-standard-4 TDX CVMs.

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

### CLI Options (Enclave)

| Flag | Default | Description |
|------|---------|-------------|
| `--model-dir` | `test_assets/minilm` | Directory containing config.json, tokenizer.json, model.safetensors |
| `--model-id` | `stage-0` | Model ID to register (maps to pipeline stage) |

## Production Mode (AWS)

See `infra/hello-enclave/HELLO_ENCLAVE_RUNBOOK.md` for a step-by-step guide to deploying on AWS Nitro Enclaves.

## Production Mode (GCP)

> For the complete 10-step golden path, see [`docs/PRODUCTION_GCP.md`](docs/PRODUCTION_GCP.md).

### Build

```bash
# Enclave binary (runs inside Confidential Space CVM)
cargo build --release --no-default-features --features gcp -p ephemeral-ml-enclave

# Client binary (runs outside the CVM)
cargo build --release --no-default-features --features gcp -p ephemeral-ml-client
```

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

The manifest (`manifest.json`) is automatically fetched and verified by the enclave
alongside the encrypted model artifacts. See [`docs/MODEL_PACKAGING.md`](docs/MODEL_PACKAGING.md)
for manifest schema and signing key management.

### Deploy with Local Model (Quick Start)

```bash
bash scripts/gcp/deploy.sh --model-source local
```

### GCP Architecture Differences

| Aspect | AWS Nitro | GCP TDX CVM |
|--------|-----------|-------------|
| Trust boundary | Enclave process (VSock isolated) | Entire CVM |
| Host process | Required (blind relay) | Not needed |
| Network | None (VSock only) | Full TCP/HTTPS |
| KMS auth | NSM attestation + RecipientInfo | WIP + Cloud KMS (attestation-bound) |
| Model loading | Host fetches S3, relays via VSock | CVM fetches GCS directly |
| Attestation | COSE_Sign1 (NSM) | TDX quote (configfs-tsm) |

See [`docs/build-matrix.md`](docs/build-matrix.md) for the full feature flag compatibility matrix.
See [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) for the trust model and HIPAA mapping.
See [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) for error codes and diagnostics.

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
