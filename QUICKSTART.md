# EphemeralML Quick Start Guide

## Prerequisites

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

### Build

```bash
# Enclave binary (runs inside Confidential Space CVM)
cargo build --release --no-default-features --features gcp -p ephemeral-ml-enclave

# Client binary (runs outside the CVM)
cargo build --release --no-default-features --features gcp -p ephemeral-ml-client
```

### Deploy on GCP Confidential Space

```bash
# 1. Create a c3-standard-4 TDX CVM
gcloud compute instances create ephemeralml-cvm \
    --zone=us-central1-a --machine-type=c3-standard-4 \
    --confidential-compute-type=TDX \
    --min-cpu-platform="Intel Sapphire Rapids" \
    --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
    --maintenance-policy=TERMINATE

# 2. Copy binary and model, run on CVM (--gcp flag required)
./target/release/ephemeral-ml-enclave \
    --gcp --model-dir /app/model --model-id stage-0
```

### GCP Architecture Differences

| Aspect | AWS Nitro | GCP TDX CVM |
|--------|-----------|-------------|
| Trust boundary | Enclave process (VSock isolated) | Entire CVM |
| Host process | Required (blind relay) | Not needed |
| Network | None (VSock only) | Full TCP/HTTPS |
| KMS auth | NSM attestation + RecipientInfo | Local files / GCS (Cloud KMS not yet wired) |
| Model loading | Host fetches S3, relays via VSock | CVM fetches GCS directly |
| Attestation | COSE_Sign1 (NSM) | TDX quote (configfs-tsm) |

See [`docs/build-matrix.md`](docs/build-matrix.md) for the full feature flag compatibility matrix.

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
