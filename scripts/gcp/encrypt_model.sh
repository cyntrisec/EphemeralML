#!/usr/bin/env bash
# encrypt_model.sh — Encrypt model weights and upload to GCS for KMS-gated release.
#
# Steps:
#   1. Generate random 32-byte DEK
#   2. Encrypt model.safetensors with ChaCha20-Poly1305 → model.safetensors.enc
#   3. Wrap DEK with Cloud KMS → wrapped_dek.bin
#   4. Upload config.json, tokenizer.json, model.safetensors.enc, wrapped_dek.bin to GCS
#   5. Print --expected-model-hash and server command
#
# Usage:
#   bash scripts/gcp/encrypt_model.sh <model_dir> <gcs_prefix>
#
# Example:
#   bash scripts/gcp/encrypt_model.sh test_assets/minilm models/minilm
#
# Requires:
#   - openssl, xxd, python3
#   - GCP_KMS_KEY, GCP_BUCKET env vars (from setup_kms.sh)

set -euo pipefail

MODEL_DIR="${1:?Usage: encrypt_model.sh <model_dir> <gcs_prefix>}"
GCS_PREFIX="${2:?Usage: encrypt_model.sh <model_dir> <gcs_prefix>}"

KMS_KEY="${GCP_KMS_KEY:?Set GCP_KMS_KEY (from setup_kms.sh)}"
BUCKET="${GCP_BUCKET:?Set GCP_BUCKET (from setup_kms.sh)}"

WEIGHTS="${MODEL_DIR}/model.safetensors"
CONFIG="${MODEL_DIR}/config.json"
TOKENIZER="${MODEL_DIR}/tokenizer.json"

# Validate inputs
for f in "${WEIGHTS}" "${CONFIG}" "${TOKENIZER}"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: File not found: $f"
        exit 1
    fi
done

TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

echo "=== EphemeralML Model Encryption ==="
echo "  Model dir:  ${MODEL_DIR}"
echo "  GCS target: gs://${BUCKET}/${GCS_PREFIX}/"
echo "  KMS key:    ${KMS_KEY}"
echo ""

# 1. Compute model hash (pre-encryption)
echo "[1/5] Computing model hash..."
MODEL_HASH=$(sha256sum "${WEIGHTS}" | cut -d' ' -f1)
echo "  SHA-256: ${MODEL_HASH}"

# 2. Generate random 32-byte DEK
echo "[2/5] Generating DEK..."
DEK_FILE="${TMPDIR}/dek.bin"
openssl rand -out "${DEK_FILE}" 32
echo "  DEK generated (32 bytes)"

# 3. Encrypt model.safetensors with ChaCha20-Poly1305
# Format: nonce (12 bytes) || ciphertext+tag
echo "[3/5] Encrypting model weights..."
NONCE_FILE="${TMPDIR}/nonce.bin"
ENCRYPTED_FILE="${TMPDIR}/model.safetensors.enc"
openssl rand -out "${NONCE_FILE}" 12

# Use Python for ChaCha20-Poly1305 encryption (openssl enc doesn't support it directly)
python3 -c "
import sys, os

# Read inputs
with open('${DEK_FILE}', 'rb') as f:
    dek = f.read()
with open('${NONCE_FILE}', 'rb') as f:
    nonce = f.read()
with open('${WEIGHTS}', 'rb') as f:
    plaintext = f.read()

# ChaCha20-Poly1305 encryption via cryptography library
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    cipher = ChaCha20Poly1305(dek)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
except ImportError:
    # Fallback: use openssl via subprocess
    import subprocess
    dek_hex = dek.hex()
    nonce_hex = nonce.hex()
    result = subprocess.run(
        ['openssl', 'enc', '-chacha20', '-e', '-K', dek_hex, '-iv', nonce_hex],
        input=plaintext, capture_output=True
    )
    if result.returncode != 0:
        print('ERROR: openssl chacha20 encryption failed', file=sys.stderr)
        print('Install python3-cryptography: pip3 install cryptography', file=sys.stderr)
        sys.exit(1)
    ciphertext = result.stdout

# Write: nonce || ciphertext+tag
with open('${ENCRYPTED_FILE}', 'wb') as f:
    f.write(nonce)
    f.write(ciphertext)

enc_size = os.path.getsize('${ENCRYPTED_FILE}')
print(f'  Encrypted: {enc_size} bytes ({enc_size / 1024 / 1024:.1f} MB)')
"

# 4. Wrap DEK with Cloud KMS
echo "[4/5] Wrapping DEK with Cloud KMS..."
WRAPPED_DEK="${TMPDIR}/wrapped_dek.bin"
gcloud kms encrypt \
    --key="${KMS_KEY}" \
    --plaintext-file="${DEK_FILE}" \
    --ciphertext-file="${WRAPPED_DEK}"
echo "  Wrapped DEK: $(wc -c < "${WRAPPED_DEK}") bytes"

# 5. Upload to GCS
echo "[5/5] Uploading to GCS..."
gcloud storage cp "${CONFIG}" "gs://${BUCKET}/${GCS_PREFIX}/config.json"
gcloud storage cp "${TOKENIZER}" "gs://${BUCKET}/${GCS_PREFIX}/tokenizer.json"
gcloud storage cp "${ENCRYPTED_FILE}" "gs://${BUCKET}/${GCS_PREFIX}/model.safetensors.enc"
gcloud storage cp "${WRAPPED_DEK}" "gs://${BUCKET}/${GCS_PREFIX}/wrapped_dek.bin"

echo ""
echo "=== Encryption Complete ==="
echo ""
echo "Model hash (for --expected-model-hash):"
echo "  ${MODEL_HASH}"
echo ""
echo "Server command:"
echo "  sudo ./ephemeral-ml-enclave --gcp --direct --model-source gcs-kms \\"
echo "      --gcp-bucket ${BUCKET} --gcp-model-prefix ${GCS_PREFIX} \\"
echo "      --gcp-kms-key ${KMS_KEY} \\"
echo "      --gcp-wip-audience \${GCP_WIP_AUDIENCE} \\"
echo "      --expected-model-hash ${MODEL_HASH}"
