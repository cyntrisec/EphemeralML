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

## Supported Configuration

| Component | Value |
|-----------|-------|
| Machine type | c3-standard-4 |
| Zone | us-central1-a |
| TEE type | Intel TDX |
| CS image | confidential-space (production) |
| Model | MiniLM-L6-v2 (22.7M params) |
| Encryption | ChaCha20-Poly1305 (model), Cloud KMS (DEK) |
| Transport | SecureChannel (HPKE + ChaCha20) |

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
| `EPHEMERALML_DIRECT` | Optional | `true` for single-server mode |
