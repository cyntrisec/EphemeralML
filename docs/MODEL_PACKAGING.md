# Model Packaging Guide

## Overview

EphemeralML uses a signed manifest (`manifest.json`) alongside encrypted model artifacts
to verify model provenance inside the enclave before loading. The `package_model.sh` script
handles encryption, signing, and upload in one step.

## Manifest Schema

```json
{
  "model_id": "minilm-l6-v2",
  "version": "v1.0.0",
  "model_hash": [/* 32 bytes: SHA-256 of plaintext model.safetensors */],
  "hash_algorithm": "sha256",
  "key_id": "projects/P/locations/L/keyRings/KR/cryptoKeys/K",
  "gcs_uris": {
    "config": "gs://bucket/prefix/config.json",
    "tokenizer": "gs://bucket/prefix/tokenizer.json",
    "weights_enc": "gs://bucket/prefix/model.safetensors.enc",
    "wrapped_dek": "gs://bucket/prefix/wrapped_dek.bin"
  },
  "created_at": "2026-02-16T12:00:00Z",
  "signature": [/* 64 bytes: Ed25519 signature */]
}
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `model_id` | string | Unique identifier for the model |
| `version` | string | Semantic version (e.g., "v1.0.0") |
| `model_hash` | byte array | SHA-256 of the plaintext `model.safetensors` file |
| `hash_algorithm` | string | Always "sha256" |
| `key_id` | string | Cloud KMS key resource name used to wrap the DEK |
| `gcs_uris` | object | Map of artifact names to GCS URIs |
| `created_at` | string | ISO 8601 creation timestamp |
| `signature` | byte array | Ed25519 signature over the signing payload |

### Signing Payload

The signature covers a JSON-serialized payload containing all fields **except** `signature`.
The payload is serialized with compact separators (no spaces) using `serde_json`.

## Usage

### Basic

```bash
export GCP_KMS_KEY=projects/my-project/locations/global/keyRings/ephemeralml/cryptoKeys/model-key
export GCP_BUCKET=ephemeralml-models

bash scripts/gcp/package_model.sh test_assets/minilm models/minilm
```

### With Model ID and Version

```bash
bash scripts/gcp/package_model.sh test_assets/minilm models/minilm \
    --model-id minilm-l6-v2 --version v1.0.0
```

### Dry Run (No GCS Upload)

```bash
bash scripts/gcp/package_model.sh test_assets/minilm models/minilm --dry-run
```

Prints the manifest content without uploading. Useful for testing.

## Signing Key Management

### Generate a New Key

If `EPHEMERALML_MODEL_SIGNING_KEY` is not set, `package_model.sh` generates a new
Ed25519 keypair. The private key is written to a secure file (`<model_dir>/.signing_key.hex`,
mode 0600) — it is **never** printed to stdout.

```
Generated new signing key: test_assets/minilm/.signing_key.hex (0600)
IMPORTANT: Save this key. To reuse:
  export EPHEMERALML_MODEL_SIGNING_KEY=$(cat test_assets/minilm/.signing_key.hex)
Public key (EPHEMERALML_MODEL_SIGNING_PUBKEY): ef567890...
```

### Reuse an Existing Key

```bash
export EPHEMERALML_MODEL_SIGNING_KEY=$(cat test_assets/minilm/.signing_key.hex)
# or set directly:
export EPHEMERALML_MODEL_SIGNING_KEY=<64-hex-char-private-key>
bash scripts/gcp/package_model.sh test_assets/minilm models/minilm
```

### Trust Anchor in Enclave

Set the **public key** hex as `EPHEMERALML_MODEL_SIGNING_PUBKEY` in the enclave environment.
The enclave uses it to verify the manifest signature before loading the model.
When this variable is set, the manifest **must** be present and valid — missing or
corrupt manifests are treated as hard errors.

## Model Hash

The model hash is the SHA-256 of the **plaintext** `model.safetensors` file, computed
before encryption. This guarantees that:

1. The same model always produces the same hash (deterministic)
2. The hash can be verified after decryption inside the enclave
3. The hash is bound into the manifest signature

### Computing the Hash Manually

```bash
sha256sum test_assets/minilm/model.safetensors
```

## GCS Artifacts

After packaging, the GCS bucket contains:

```
gs://bucket/prefix/
  ├── config.json          # Model configuration (plaintext)
  ├── tokenizer.json       # Tokenizer vocabulary (plaintext)
  ├── model.safetensors.enc  # Encrypted weights (nonce || ciphertext+tag)
  ├── wrapped_dek.bin      # KMS-wrapped Data Encryption Key
  └── manifest.json        # Signed manifest
```

## Migration from encrypt_model.sh

If you previously used `encrypt_model.sh`:

1. Your existing 4 artifacts remain valid
2. Run `package_model.sh` with the same model directory — it re-encrypts and adds `manifest.json`
3. The enclave is backwards-compatible: if `manifest.json` is missing in GCS, it logs a warning but continues

To add a manifest to an existing deployment without re-encrypting:
1. Compute the plaintext hash: `sha256sum model.safetensors`
2. Create `manifest.json` manually with the hash and sign it
3. Upload: `gcloud storage cp manifest.json gs://bucket/prefix/manifest.json`

## Encryption Format

- **Algorithm**: ChaCha20-Poly1305
- **DEK**: 32 random bytes, wrapped with Cloud KMS
- **Wire format**: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
- **DEK wrapping**: `gcloud kms encrypt` (symmetric encryption)
