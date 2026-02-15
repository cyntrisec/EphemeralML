# EphemeralML Design Partner Pilot

**Estimated time: 30 minutes**

This guide walks you through deploying EphemeralML on GCP Confidential Space, running a confidential inference, and collecting compliance evidence.

## Prerequisites

- GCP project with billing enabled
- `gcloud` CLI authenticated (`gcloud auth login`)
- Docker installed and running
- Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)

## Step 1: Validate Environment

```bash
bash scripts/doctor.sh
```

Fix any failures before continuing. Warnings for optional tools (jq, Docker) are acceptable for local testing.

## Step 2: Configure GCP

```bash
bash scripts/init_gcp.sh
```

This generates `.env.gcp` with your project, zone, and model source settings. For the pilot, use `gcs-kms` model source to test the full KMS-gated path.

## Step 3: Deploy

```bash
source .env.gcp
bash pilot/deploy.sh
```

This builds the container, pushes to Artifact Registry, and launches a Confidential Space CVM (c3-standard-4, Intel TDX). The container takes ~60s to start after the VM is RUNNING.

## Step 4: Verify

```bash
bash pilot/verify.sh
```

This sends an inference request, receives the result + signed receipt, and verifies the receipt cryptographically. Evidence is saved to `pilot/evidence/`.

## Step 5: Review Evidence

Check the `pilot/evidence/` directory:

| File | Contents |
|------|----------|
| `receipt.cbor` | Signed Attested Execution Receipt |
| `verify_output.txt` | Receipt verification CLI output |
| `metadata.json` | Deployment metadata (project, zone, image digest) |

Fill in `pilot/audit_evidence.md` with the evidence paths for your compliance review.

## Step 6: Clean Up

```bash
bash scripts/gcp/teardown.sh
```

## What You Just Proved

1. **TEE isolation** — inference ran inside an Intel TDX Confidential VM
2. **KMS-gated key release** — model decryption key released only to attested workload
3. **Cryptographic receipt** — Ed25519-signed proof binding input/output hashes to attestation
4. **Fail-closed** — wrong model hash is rejected (see `pilot/audit_evidence.md`)

## Deep Dives

- Architecture & threat model: [`docs/design.md`](../docs/design.md)
- Build modes & feature flags: [`docs/build-matrix.md`](../docs/build-matrix.md)
- Benchmarks: [`docs/benchmarks.md`](../docs/benchmarks.md)
- Full deployment guide: [`QUICKSTART.md`](../QUICKSTART.md)

## Support

- Issues: [github.com/cyntrisec/EphemeralML/issues](https://github.com/cyntrisec/EphemeralML/issues)
- Email: pilot@cyntrisec.com
