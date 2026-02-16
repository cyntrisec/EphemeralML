#!/usr/bin/env bash
# package_model.sh — Encrypt, sign, and upload model with manifest to GCS.
#
# Wraps encrypt_model.sh and adds a signed manifest.json for model provenance
# verification inside the enclave.
#
# Steps:
#   1. Compute plaintext model hash (SHA-256)
#   2. Generate DEK, encrypt model, wrap DEK via KMS
#   3. Generate manifest.json (model_id, version, hash, key_id, GCS URIs, created_at)
#   4. Sign manifest with Ed25519
#   5. Upload 5 files to GCS: config.json, tokenizer.json, model.safetensors.enc,
#      wrapped_dek.bin, manifest.json
#
# Usage:
#   bash scripts/gcp/package_model.sh <model_dir> <gcs_prefix> [--model-id ID] [--version VER] [--format FMT]
#   bash scripts/gcp/package_model.sh test_assets/minilm models/minilm
#   bash scripts/gcp/package_model.sh test_assets/minilm models/minilm --dry-run
#   bash scripts/gcp/package_model.sh /path/to/llama models/llama --format gguf --model-id llama-8b
#
# Requires:
#   - openssl, python3 (with cryptography), jq
#   - GCP_KMS_KEY, GCP_BUCKET env vars (from setup_kms.sh)
#   - EPHEMERALML_MODEL_SIGNING_KEY (hex Ed25519 private key) — generates if not set
#
# Outputs:
#   - manifest.json uploaded alongside the 4 model artifacts
#   - Prints --expected-model-hash and server command
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODEL_DIR="${1:?Usage: package_model.sh <model_dir> <gcs_prefix> [--model-id ID] [--version VER] [--dry-run]}"
GCS_PREFIX="${2:?Usage: package_model.sh <model_dir> <gcs_prefix>}"
shift 2

# Defaults
MODEL_ID="minilm-l6-v2"
MODEL_VERSION="v1.0.0"
MODEL_FORMAT="safetensors"
DRY_RUN=false

# Parse optional args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --model-id)  MODEL_ID="$2"; shift 2 ;;
        --version)   MODEL_VERSION="$2"; shift 2 ;;
        --format)    MODEL_FORMAT="$2"; shift 2 ;;
        --dry-run)   DRY_RUN=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ "${MODEL_FORMAT}" != "safetensors" && "${MODEL_FORMAT}" != "gguf" ]]; then
    echo "ERROR: --format must be 'safetensors' or 'gguf', got '${MODEL_FORMAT}'"
    exit 1
fi

# File names depend on model format
if [[ "${MODEL_FORMAT}" == "gguf" ]]; then
    WEIGHTS="${MODEL_DIR}/model.gguf"
    WEIGHTS_ENC_NAME="model.gguf.enc"
else
    WEIGHTS="${MODEL_DIR}/model.safetensors"
    WEIGHTS_ENC_NAME="model.safetensors.enc"
fi

TOKENIZER="${MODEL_DIR}/tokenizer.json"

# Validate inputs — config.json only required for safetensors
if [[ "${MODEL_FORMAT}" == "safetensors" ]]; then
    CONFIG="${MODEL_DIR}/config.json"
    for f in "${WEIGHTS}" "${CONFIG}" "${TOKENIZER}"; do
        if [ ! -f "$f" ]; then
            echo "ERROR: File not found: $f"
            exit 1
        fi
    done
else
    CONFIG=""
    for f in "${WEIGHTS}" "${TOKENIZER}"; do
        if [ ! -f "$f" ]; then
            echo "ERROR: File not found: $f"
            exit 1
        fi
    done
fi

if ! $DRY_RUN; then
    KMS_KEY="${GCP_KMS_KEY:?Set GCP_KMS_KEY (from setup_kms.sh)}"
    BUCKET="${GCP_BUCKET:?Set GCP_BUCKET (from setup_kms.sh)}"
else
    KMS_KEY="${GCP_KMS_KEY:-projects/test/locations/global/keyRings/kr/cryptoKeys/key}"
    BUCKET="${GCP_BUCKET:-dry-run-bucket}"
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

CREATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

echo "=== EphemeralML Model Packaging ==="
echo "  Model dir:   ${MODEL_DIR}"
echo "  Model ID:    ${MODEL_ID}"
echo "  Version:     ${MODEL_VERSION}"
echo "  Format:      ${MODEL_FORMAT}"
echo "  GCS target:  gs://${BUCKET}/${GCS_PREFIX}/"
echo "  KMS key:     ${KMS_KEY}"
echo "  Dry run:     ${DRY_RUN}"
echo ""

# 1. Compute model hash (pre-encryption)
echo "[1/6] Computing model hash..."
MODEL_HASH=$(sha256sum "${WEIGHTS}" | cut -d' ' -f1)
echo "  SHA-256: ${MODEL_HASH}"

# 2. Generate random 32-byte DEK
echo "[2/6] Generating DEK..."
DEK_FILE="${TMPDIR}/dek.bin"
openssl rand -out "${DEK_FILE}" 32
echo "  DEK generated (32 bytes)"

# 3. Encrypt model weights with ChaCha20-Poly1305
echo "[3/6] Encrypting model weights..."
NONCE_FILE="${TMPDIR}/nonce.bin"
ENCRYPTED_FILE="${TMPDIR}/${WEIGHTS_ENC_NAME}"
openssl rand -out "${NONCE_FILE}" 12

_PY_DEK_FILE="${DEK_FILE}" \
_PY_NONCE_FILE="${NONCE_FILE}" \
_PY_WEIGHTS="${WEIGHTS}" \
_PY_ENCRYPTED_FILE="${ENCRYPTED_FILE}" \
python3 -c "
import sys, os

dek_file = os.environ['_PY_DEK_FILE']
nonce_file = os.environ['_PY_NONCE_FILE']
weights_file = os.environ['_PY_WEIGHTS']
encrypted_file = os.environ['_PY_ENCRYPTED_FILE']

with open(dek_file, 'rb') as f:
    dek = f.read()
with open(nonce_file, 'rb') as f:
    nonce = f.read()
with open(weights_file, 'rb') as f:
    plaintext = f.read()

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    cipher = ChaCha20Poly1305(dek)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
except ImportError:
    print('ERROR: python3-cryptography required. Install: pip3 install cryptography', file=sys.stderr)
    sys.exit(1)

with open(encrypted_file, 'wb') as f:
    f.write(nonce)
    f.write(ciphertext)

enc_size = os.path.getsize(encrypted_file)
print(f'  Encrypted: {enc_size} bytes ({enc_size / 1024 / 1024:.1f} MB)')
"

# 4. Wrap DEK with Cloud KMS (skip in dry-run)
echo "[4/6] Wrapping DEK with Cloud KMS..."
WRAPPED_DEK="${TMPDIR}/wrapped_dek.bin"
if $DRY_RUN; then
    # In dry-run, create a dummy wrapped DEK
    cp "${DEK_FILE}" "${WRAPPED_DEK}"
    echo "  Wrapped DEK: $(wc -c < "${WRAPPED_DEK}") bytes (dry-run, unencrypted)"
else
    gcloud kms encrypt \
        --key="${KMS_KEY}" \
        --plaintext-file="${DEK_FILE}" \
        --ciphertext-file="${WRAPPED_DEK}"
    echo "  Wrapped DEK: $(wc -c < "${WRAPPED_DEK}") bytes"
fi

# 5. Generate and sign manifest.json
echo "[5/6] Generating signed manifest..."

# Ed25519 signing key from env or generate new
# All values are passed via environment variables to prevent shell injection
# into the Python interpreter.
_PY_MODEL_HASH="${MODEL_HASH}" \
_PY_SIGNING_KEY="${EPHEMERALML_MODEL_SIGNING_KEY:-}" \
_PY_MODEL_DIR="${MODEL_DIR}" \
_PY_MODEL_ID="${MODEL_ID}" \
_PY_MODEL_VERSION="${MODEL_VERSION}" \
_PY_MODEL_FORMAT="${MODEL_FORMAT}" \
_PY_WEIGHTS_ENC_NAME="${WEIGHTS_ENC_NAME}" \
_PY_KMS_KEY="${KMS_KEY}" \
_PY_BUCKET="${BUCKET}" \
_PY_GCS_PREFIX="${GCS_PREFIX}" \
_PY_CREATED_AT="${CREATED_AT}" \
_PY_MANIFEST_OUT="${TMPDIR}/manifest.json" \
python3 -c "
import json, sys, os

model_hash_hex = os.environ['_PY_MODEL_HASH']
model_hash_bytes = bytes.fromhex(model_hash_hex)

signing_key_hex = os.environ.get('_PY_SIGNING_KEY', '')

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    print('ERROR: python3-cryptography required. Install: pip3 install cryptography', file=sys.stderr)
    sys.exit(1)

# Load or generate signing key
if signing_key_hex:
    sk_bytes = bytes.fromhex(signing_key_hex)
    if len(sk_bytes) != 32:
        print(f'ERROR: EPHEMERALML_MODEL_SIGNING_KEY must be exactly 32 bytes (64 hex chars), got {len(sk_bytes)}', file=sys.stderr)
        sys.exit(1)
    private_key = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    print('  Using signing key from EPHEMERALML_MODEL_SIGNING_KEY')
else:
    import stat
    model_dir = os.environ['_PY_MODEL_DIR']
    key_file = os.path.join(model_dir, '.signing_key.hex')
    # Reuse existing key file if present (prevents accidental key rotation)
    if os.path.isfile(key_file):
        with open(key_file, 'r') as kf:
            existing_hex = kf.read().strip()
        sk_bytes = bytes.fromhex(existing_hex)
        if len(sk_bytes) != 32:
            print(f'ERROR: Existing {key_file} has wrong length ({len(sk_bytes)} bytes). Delete it to regenerate.', file=sys.stderr)
            sys.exit(1)
        private_key = Ed25519PrivateKey.from_private_bytes(sk_bytes)
        print(f'  Reusing existing signing key from {key_file}')
    else:
        private_key = Ed25519PrivateKey.generate()
        sk_raw = private_key.private_bytes_raw()
        # Write private key to a persistent secure file — NEVER print to stdout
        with open(key_file, 'w') as kf:
            kf.write(sk_raw.hex())
        os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        print(f'  Generated new signing key: {key_file} (0600)')
        print(f'  IMPORTANT: Save this key. To reuse:')
        print(f'    export EPHEMERALML_MODEL_SIGNING_KEY=\$(cat {key_file})')

pk_raw = private_key.public_key().public_bytes_raw()
print(f'  Public key (EPHEMERALML_MODEL_SIGNING_PUBKEY): {pk_raw.hex()}')

# Build signing payload (matches Rust ManifestSigningPayload serde)
# serde_bytes serializes Vec<u8> as a list of integers in JSON
bucket = os.environ['_PY_BUCKET']
prefix = os.environ['_PY_GCS_PREFIX']
payload = {
    'model_id': os.environ['_PY_MODEL_ID'],
    'version': os.environ['_PY_MODEL_VERSION'],
    'model_hash': list(model_hash_bytes),
    'hash_algorithm': 'sha256',
    'key_id': os.environ['_PY_KMS_KEY'],
    'gcs_uris': {
        **({'config': f'gs://{bucket}/{prefix}/config.json'} if os.environ['_PY_MODEL_FORMAT'] == 'safetensors' else {}),
        'tokenizer': f'gs://{bucket}/{prefix}/tokenizer.json',
        'weights_enc': f\"gs://{bucket}/{prefix}/{os.environ['_PY_WEIGHTS_ENC_NAME']}\",
        'wrapped_dek': f'gs://{bucket}/{prefix}/wrapped_dek.bin',
    },
    'created_at': os.environ['_PY_CREATED_AT'],
}

# Sign the canonical JSON payload
payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True)
signature = private_key.sign(payload_json.encode())

# Build manifest (includes signature)
manifest = dict(payload)
manifest['signature'] = list(signature)

# Write manifest.json (pretty-printed for readability)
manifest_out = os.environ['_PY_MANIFEST_OUT']
with open(manifest_out, 'w') as f:
    json.dump(manifest, f, indent=2)

print(f'  Manifest written ({len(signature)} byte signature)')
"

# 6. Upload to GCS (skip in dry-run)
echo "[6/6] Uploading to GCS..."
if $DRY_RUN; then
    echo "  (dry-run) Would upload:"
    if [[ -n "${CONFIG}" ]]; then
        echo "    gs://${BUCKET}/${GCS_PREFIX}/config.json"
    fi
    echo "    gs://${BUCKET}/${GCS_PREFIX}/tokenizer.json"
    echo "    gs://${BUCKET}/${GCS_PREFIX}/${WEIGHTS_ENC_NAME}"
    echo "    gs://${BUCKET}/${GCS_PREFIX}/wrapped_dek.bin"
    echo "    gs://${BUCKET}/${GCS_PREFIX}/manifest.json"
    echo ""
    echo "  Manifest content:"
    cat "${TMPDIR}/manifest.json"
else
    if [[ -n "${CONFIG}" ]]; then
        gcloud storage cp "${CONFIG}" "gs://${BUCKET}/${GCS_PREFIX}/config.json"
    fi
    gcloud storage cp "${TOKENIZER}" "gs://${BUCKET}/${GCS_PREFIX}/tokenizer.json"
    gcloud storage cp "${ENCRYPTED_FILE}" "gs://${BUCKET}/${GCS_PREFIX}/${WEIGHTS_ENC_NAME}"
    gcloud storage cp "${WRAPPED_DEK}" "gs://${BUCKET}/${GCS_PREFIX}/wrapped_dek.bin"
    gcloud storage cp "${TMPDIR}/manifest.json" "gs://${BUCKET}/${GCS_PREFIX}/manifest.json"
fi

echo ""
echo "=== Packaging Complete ==="
echo ""
echo "Model hash (for --expected-model-hash):"
echo "  ${MODEL_HASH}"
echo ""
echo "Server command:"
echo "  sudo ./ephemeral-ml-enclave --gcp --direct --model-source gcs-kms \\"
echo "      --model-format ${MODEL_FORMAT} \\"
echo "      --gcp-bucket ${BUCKET} --gcp-model-prefix ${GCS_PREFIX} \\"
echo "      --gcp-kms-key ${KMS_KEY} \\"
echo "      --gcp-wip-audience \${GCP_WIP_AUDIENCE} \\"
echo "      --expected-model-hash ${MODEL_HASH}"
