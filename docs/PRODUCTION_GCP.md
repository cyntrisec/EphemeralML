# EphemeralML Production Deployment on GCP

The full golden path: from zero to a running confidential AI inference endpoint
on GCP Confidential Space with KMS-gated model decryption and verifiable receipts.

## Prerequisites

- GCP project with billing enabled
- `gcloud` CLI authenticated (`gcloud auth login`)
- Docker installed and running
- Rust toolchain (`rustup`, stable channel)
- `python3` with `cryptography` package (`pip3 install cryptography`)
- `jq` installed

## Architecture

```
Client
  │
  │  TCP :9000 (SecureChannel)
  ▼
┌──────────────────────────────────────────────────────────┐
│  GCP Confidential Space (c3-standard-4, Intel TDX)       │
│  ┌────────────────────────────────────────────────────┐  │
│  │  EphemeralML Container                              │  │
│  │  1. Boot → get CS attestation token                 │  │
│  │  2. STS exchange → federated access token           │  │
│  │  3. Cloud KMS decrypt → DEK                         │  │
│  │  4. Decrypt model weights → load into candle        │  │
│  │  5. Accept SecureChannel clients → inference        │  │
│  │  6. Return result + signed receipt                  │  │
│  └────────────────────────────────────────────────────┘  │
│                    │                                      │
│                    ▼                                      │
│  GCS Bucket: config.json, tokenizer.json,                │
│              model.safetensors.enc, wrapped_dek.bin,      │
│              manifest.json                                │
└──────────────────────────────────────────────────────────┘
```

## Step 1: Doctor Preflight

```bash
bash scripts/doctor.sh
```

Expected: all checks pass. Fix any missing tools before proceeding.

## Step 2: Initialize GCP Configuration

Interactive mode:
```bash
bash scripts/init_gcp.sh
```

CI / non-interactive mode:
```bash
EPHEMERALML_GCP_PROJECT=my-project \
EPHEMERALML_MODEL_SOURCE=gcs-kms \
EPHEMERALML_GCP_KMS_KEY=projects/my-project/locations/global/keyRings/ephemeralml/cryptoKeys/model-key \
EPHEMERALML_GCP_WIP_AUDIENCE="//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/ephemeralml-pool/providers/ephemeralml-provider" \
  bash scripts/init_gcp.sh --non-interactive
```

This generates `.env.gcp` with all configuration.

## Step 3: Setup GCP Infrastructure

```bash
source .env.gcp
bash scripts/gcp/setup.sh
```

Creates:
- Artifact Registry repository
- Service account (`ephemeralml-cvm@PROJECT.iam.gserviceaccount.com`)
- IAM roles (AR reader, logging, monitoring, confidential computing, GCS reader)
- Firewall rule (TCP 9000-9002)

## Step 4: Setup KMS

```bash
bash scripts/gcp/setup_kms.sh
```

Creates:
- Cloud KMS key ring and crypto key
- Workload Identity Pool and Provider
- IAM binding: WIP → KMS decrypter role

## Step 5: Package Model

```bash
bash scripts/gcp/package_model.sh test_assets/minilm models/minilm \
    --model-id minilm-l6-v2 --version v1.0.0
```

This:
1. Computes SHA-256 of plaintext weights
2. Generates DEK, encrypts with ChaCha20-Poly1305
3. Wraps DEK with Cloud KMS
4. Generates and signs `manifest.json`
5. Uploads 5 files to GCS

Save the printed `--expected-model-hash` value.

## Step 6: Deploy

```bash
bash scripts/gcp/deploy.sh \
    --model-source gcs-kms \
    --kms-key "$EPHEMERALML_GCP_KMS_KEY" \
    --wip-audience "$EPHEMERALML_GCP_WIP_AUDIENCE" \
    --model-hash "$EXPECTED_MODEL_HASH"
```

CI mode:
```bash
bash scripts/gcp/deploy.sh --yes \
    --model-source gcs-kms \
    --kms-key "$EPHEMERALML_GCP_KMS_KEY" \
    --wip-audience "$EPHEMERALML_GCP_WIP_AUDIENCE" \
    --model-hash "$EXPECTED_MODEL_HASH"
```

Wait ~60s for the container to start. The Launcher pulls the image, verifies it, then starts the workload.

## Step 7: Run Inference

```bash
EXTERNAL_IP=$(gcloud compute instances describe ephemeralml-cvm \
    --zone=us-central1-a --format='value(networkInterfaces[0].accessConfigs[0].natIP)')

cargo run --release --no-default-features --features gcp -p ephemeral-ml-client -- \
    infer --server "$EXTERNAL_IP:9000" --text "Hello world"
```

Expected output: 384-dimensional embedding vector + signed receipt.

## Step 8: Verify Receipt

```bash
cargo run --release -p ephemeral-ml-client --bin ephemeralml_verify -- receipt.json
```

The verifier checks:
- Ed25519 signature validity
- Model hash matches expected
- Attestation hash chains to boot evidence
- Sequence number monotonicity

## Step 9: Negative Test

Test that hash mismatch is detected:

```bash
# Deploy with wrong hash — should fail to start
bash scripts/gcp/deploy.sh \
    --model-source gcs-kms \
    --kms-key "$EPHEMERALML_GCP_KMS_KEY" \
    --wip-audience "$EPHEMERALML_GCP_WIP_AUDIENCE" \
    --model-hash 0000000000000000000000000000000000000000000000000000000000000000
```

Check logs: `gcloud compute ssh ephemeralml-cvm --command='sudo journalctl -u tee-container-runner -n 50'`

Expected: `E1003: Input validation failed` or model hash mismatch error.

## Step 10: Teardown

```bash
bash scripts/gcp/teardown.sh
# Or for CI: bash scripts/gcp/teardown.sh --yes
```

Deletes the CVM instance. Preserves reusable infrastructure (AR, SA, firewall).

To delete everything:
```bash
bash scripts/gcp/teardown.sh --delete-image
# Then manually: delete KMS key, SA, AR repo, firewall rule
```

## Data Destruction Checklist

For production deployments, verify each layer of data destruction:

| Layer | Action | How to Verify |
|-------|--------|--------------|
| Session keys | Automatic (`ZeroizeOnDrop`) | Included in destroy evidence receipt event |
| DEK | Automatic (`Zeroizing<Vec<u8>>`) | Included in destroy evidence receipt event |
| Inference buffers | Automatic (`.zeroize()` on request/response) | Included in destroy evidence receipt event |
| CVM termination | Run `teardown.sh` | `gcloud compute instances list` shows no instance |
| CS image | Use `confidential-space` (NOT `-debug`) | `--image-family=confidential-space` in deploy.sh |
| Cloud Logging | Production CS image: no container stdout in Cloud Logging | Verify no log entries in Cloud Console |
| GCS artifacts | Delete after deployment if model rotation is not needed | `gsutil rm -r gs://BUCKET/models/` |

**Important**: Always use the production Confidential Space image (`confidential-space`),
not the debug image (`confidential-space-debug`). The debug image enables SSH and Cloud
Logging of container output, which may expose inference data.

## Supported Configuration

| Component | CPU Value | GPU Value |
|-----------|-----------|-----------|
| Machine type | c3-standard-4 | a3-highgpu-1g (1x H100) |
| Zone | us-central1-a | us-central1-a |
| TEE type | Intel TDX | Intel TDX + NVIDIA H100 CC-mode |
| CS image | confidential-space (production) | confidential-space (production) |
| Model | MiniLM-L6-v2 (22.7M params, safetensors) | Llama 3 8B Q4_K_M (4.6GB, GGUF) |
| CUDA | N/A | 12.2 (driver 535.247.01) |
| Encryption | ChaCha20-Poly1305 (model), Cloud KMS (DEK) | ChaCha20-Poly1305 (model), Cloud KMS (DEK) |
| Transport | SecureChannel (HPKE + ChaCha20) | SecureChannel (HPKE + ChaCha20) |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `EPHEMERALML_GCP_PROJECT` | Yes | GCP project ID |
| `EPHEMERALML_MODEL_SOURCE` | Yes | `local`, `gcs`, or `gcs-kms` |
| `EPHEMERALML_GCS_BUCKET` | gcs/gcs-kms | GCS bucket name |
| `EPHEMERALML_GCP_MODEL_PREFIX` | gcs/gcs-kms | GCS path prefix |
| `EPHEMERALML_GCP_KMS_KEY` | gcs-kms | Cloud KMS key resource name |
| `EPHEMERALML_GCP_WIP_AUDIENCE` | gcs-kms | WIP audience for STS exchange |
| `EPHEMERALML_EXPECTED_MODEL_HASH` | gcs/gcs-kms | SHA-256 of plaintext weights |
| `EPHEMERALML_MODEL_SIGNING_PUBKEY` | Optional | Ed25519 public key (hex, 64 chars) for manifest signature verification |
| `EPHEMERALML_LOG_FORMAT` | Optional | Set to `json` for structured JSON logs |
| `EPHEMERALML_MODEL_FORMAT` | GPU only | `gguf` for GGUF models (default: `safetensors`) |
| `EPHEMERALML_DIRECT` | Optional | `true` for single-server mode |

## GPU Deployment Variant

Deploy EphemeralML with GPU inference on GCP Confidential Space using NVIDIA H100 in CC-mode (confidential computing). This enables large model inference (e.g., Llama 3 8B) inside a TDX-attested CVM with GPU acceleration.

### Requirements

| Component | Value |
|-----------|-------|
| Machine type | a3-highgpu-1g (1x NVIDIA H100 80GB) |
| CUDA version | **12.2** (must match CS driver 535.x) |
| Model format | GGUF (Q4_K_M, Q8_0, etc.) |
| Max model size | 16GB (GCS loader limit) |
| Base image | `nvidia/cuda:12.2.2-devel-ubuntu22.04` |

### CUDA Version Requirement (Critical)

GCP Confidential Space GPU instances use cos-gpu-installer v2.5.3, which installs NVIDIA driver **535.247.01**. This driver supports CUDA **<= 12.2** only.

Using CUDA 12.6 or newer will fail at runtime with:
```
CUDA_ERROR_UNSUPPORTED_PTX_VERSION
```

The `Dockerfile.gpu` pins `nvidia/cuda:12.2.2-devel-ubuntu22.04` to avoid this.

### Build

```bash
# Build GPU container image
docker build -f Dockerfile.gpu -t ephemeral-ml-gpu .

# Tag for Artifact Registry
docker tag ephemeral-ml-gpu \
    "$REGION-docker.pkg.dev/$PROJECT/ephemeralml/ephemeral-ml-gpu:latest"

# Push
docker push \
    "$REGION-docker.pkg.dev/$PROJECT/ephemeralml/ephemeral-ml-gpu:latest"
```

### Deploy

```bash
bash scripts/gcp/deploy.sh --gpu \
    --model-source gcs \
    --model-format gguf
```

The `--gpu` flag selects:
- Machine type: `a3-highgpu-1g` (instead of `c3-standard-4`)
- Container image: `ephemeral-ml-gpu` (instead of `ephemeral-ml`)
- Scheduling: SPOT (preemptible) for a3-highgpu availability

### Boot Timeline

| Stage | Approximate Time |
|-------|-----------------|
| Image pull | ~60s |
| cos-gpu-installer (driver 535.x) | ~45s |
| Container start | ~15s |
| GCS model fetch (4.6GB GGUF) | ~30s |
| Model load to GPU | ~20s |
| **Total boot to ready** | **~3.5 min** |

### Expected Output

With Llama 3 8B Q4_K_M (4.6GB GGUF from GCS):

```
[INFO] GPU detected: NVIDIA H100 80GB HBM3
[INFO] CUDA 12.2, driver 535.247.01
[INFO] Loading model from GCS: gs://BUCKET/models/llama3-8b-q4km.gguf (4.6GB)
[INFO] Model loaded to GPU in 20.3s
[INFO] Listening on 0.0.0.0:9000
[INFO] TDX attestation: nvidia_gpu.cc_mode: ON
```

- 50 tokens generated in ~12s (241ms/token)
- TDX attestation confirms `nvidia_gpu.cc_mode: ON`
- Ed25519-signed receipt returned to client with model hash, attestation hash, and I/O hashes
