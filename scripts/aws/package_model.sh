#!/usr/bin/env bash
# package_model.sh - Prepare the AWS-native PoC model release.
#
# Produces the exact layout expected by enclave/Dockerfile.enclave.aws-poc:
#   docker-stage/model/config.json
#   docker-stage/model/tokenizer.json
#   docker-stage/model/manifest.json
#   docker-stage/model/wrapped_dek.bin
#
# Uploads encrypted weights to S3 under key == manifest.model_id. The enclave
# asks kms_proxy_host for that key, then unwraps wrapped_dek.bin through AWS KMS
# RecipientInfo inside the Nitro Enclave.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  scripts/aws/package_model.sh <model_dir> <s3_bucket> --kms-key ARN [options]

Options:
  --model-id ID       S3 key and AIR model identity (default: stage-0)
  --version VERSION   Manifest version (default: v1.0.0)
  --sse-kms-key ARN   Optional S3 SSE-KMS key for the encrypted weights object

Environment:
  EPHEMERALML_MODEL_SIGNING_KEY  32-byte Ed25519 private key as hex.
                                 If unset, <model_dir>/.signing_key.hex is reused
                                 or generated.

Example:
  scripts/aws/package_model.sh test_assets/minilm "$BUCKET" \
    --kms-key "$MODEL_KMS_KEY_ARN" \
    --sse-kms-key "$EVIDENCE_KMS_KEY_ARN"
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 2 ]]; then
  usage
  exit 1
fi

MODEL_DIR="$1"
BUCKET="$2"
shift 2

MODEL_ID="stage-0"
MODEL_VERSION="v1.0.0"
KMS_KEY=""
SSE_KMS_KEY="${CYNTRISEC_EVIDENCE_KMS_KEY_ARN:-${EPHEMERALML_EVIDENCE_KMS_KEY_ARN:-}}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --model-id) MODEL_ID="$2"; shift 2 ;;
    --version) MODEL_VERSION="$2"; shift 2 ;;
    --kms-key) KMS_KEY="$2"; shift 2 ;;
    --sse-kms-key) SSE_KMS_KEY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "${KMS_KEY}" ]]; then
  echo "ERROR: --kms-key is required" >&2
  exit 1
fi

CONFIG="${MODEL_DIR}/config.json"
TOKENIZER="${MODEL_DIR}/tokenizer.json"
WEIGHTS="${MODEL_DIR}/model.safetensors"

for f in "${CONFIG}" "${TOKENIZER}" "${WEIGHTS}"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: required file not found: $f" >&2
    exit 1
  fi
done

command -v aws >/dev/null || { echo "ERROR: aws CLI not found" >&2; exit 1; }
command -v python3 >/dev/null || { echo "ERROR: python3 not found" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "ERROR: sha256sum not found" >&2; exit 1; }

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

MODEL_HASH="$(sha256sum "${WEIGHTS}" | cut -d' ' -f1)"
TOKENIZER_HASH="$(sha256sum "${TOKENIZER}" | cut -d' ' -f1)"
CONFIG_HASH="$(sha256sum "${CONFIG}" | cut -d' ' -f1)"
CREATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

echo "=== Cyntrisec AWS Model Package ==="
echo "  model_dir: ${MODEL_DIR}"
echo "  model_id:  ${MODEL_ID}"
echo "  bucket:    s3://${BUCKET}/${MODEL_ID}"
echo "  kms_key:   ${KMS_KEY}"
echo "  sha256:    ${MODEL_HASH}"

echo "[1/5] Generate data key with AWS KMS"
aws kms generate-data-key \
  --key-id "${KMS_KEY}" \
  --key-spec AES_256 \
  --encryption-context "model_id=${MODEL_ID},version=${MODEL_VERSION}" \
  --output json > "${TMPDIR}/generate-data-key.json"

_PY_GDK="${TMPDIR}/generate-data-key.json" \
_PY_DEK="${TMPDIR}/dek.bin" \
_PY_WRAPPED="${TMPDIR}/wrapped_dek.bin" \
python3 - <<'PY'
import base64, json, os

with open(os.environ["_PY_GDK"], "r", encoding="utf-8") as f:
    data = json.load(f)

for key, path in (("Plaintext", "_PY_DEK"), ("CiphertextBlob", "_PY_WRAPPED")):
    value = data.get(key)
    if not value:
        raise SystemExit(f"KMS response missing {key}")
    raw = base64.b64decode(value)
    with open(os.environ[path], "wb") as out:
        out.write(raw)
PY

echo "[2/5] Encrypt model.safetensors with ChaCha20-Poly1305"
openssl rand -out "${TMPDIR}/nonce.bin" 12

_PY_DEK="${TMPDIR}/dek.bin" \
_PY_NONCE="${TMPDIR}/nonce.bin" \
_PY_WEIGHTS="${WEIGHTS}" \
_PY_OUT="${TMPDIR}/model.safetensors.enc" \
python3 - <<'PY'
import os, sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:
    print("ERROR: python3 cryptography package is required", file=sys.stderr)
    sys.exit(1)

with open(os.environ["_PY_DEK"], "rb") as f:
    dek = f.read()
with open(os.environ["_PY_NONCE"], "rb") as f:
    nonce = f.read()
with open(os.environ["_PY_WEIGHTS"], "rb") as f:
    plaintext = f.read()

if len(dek) != 32:
    raise SystemExit(f"DEK length is {len(dek)}, expected 32")

ciphertext = ChaCha20Poly1305(dek).encrypt(nonce, plaintext, None)
with open(os.environ["_PY_OUT"], "wb") as f:
    f.write(nonce)
    f.write(ciphertext)
PY

echo "[3/5] Build and sign manifest"

_PY_MODEL_DIR="${MODEL_DIR}" \
_PY_SIGNING_KEY="${EPHEMERALML_MODEL_SIGNING_KEY:-}" \
_PY_MODEL_ID="${MODEL_ID}" \
_PY_MODEL_VERSION="${MODEL_VERSION}" \
_PY_MODEL_HASH="${MODEL_HASH}" \
_PY_TOKENIZER_HASH="${TOKENIZER_HASH}" \
_PY_CONFIG_HASH="${CONFIG_HASH}" \
_PY_KMS_KEY="${KMS_KEY}" \
_PY_BUCKET="${BUCKET}" \
_PY_CREATED_AT="${CREATED_AT}" \
_PY_OUT="${TMPDIR}/manifest.json" \
python3 - <<'PY'
import json, os, stat, sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("ERROR: python3 cryptography package is required", file=sys.stderr)
    sys.exit(1)

model_dir = os.environ["_PY_MODEL_DIR"]
signing_key_hex = os.environ.get("_PY_SIGNING_KEY", "")
key_file = os.path.join(model_dir, ".signing_key.hex")

if signing_key_hex:
    sk = bytes.fromhex(signing_key_hex)
elif os.path.isfile(key_file):
    with open(key_file, "r", encoding="utf-8") as f:
        sk = bytes.fromhex(f.read().strip())
else:
    private = Ed25519PrivateKey.generate()
    sk = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(key_file, "w", encoding="utf-8") as f:
        f.write(sk.hex())
    os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)

if len(sk) != 32:
    raise SystemExit("Ed25519 signing key must be exactly 32 bytes")

private = Ed25519PrivateKey.from_private_bytes(sk)
public_hex = private.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
).hex()

model_hash = bytes.fromhex(os.environ["_PY_MODEL_HASH"])
tokenizer_hash = bytes.fromhex(os.environ["_PY_TOKENIZER_HASH"])
config_hash = bytes.fromhex(os.environ["_PY_CONFIG_HASH"])
bucket = os.environ["_PY_BUCKET"]
model_id = os.environ["_PY_MODEL_ID"]

payload = {
    "config_hash": list(config_hash),
    "created_at": os.environ["_PY_CREATED_AT"],
    "gcs_uris": {
        "weights_enc": f"s3://{bucket}/{model_id}",
        "wrapped_dek": "eif-local:/app/test_assets/minilm/wrapped_dek.bin",
        "config": "eif-local:/app/test_assets/minilm/config.json",
        "tokenizer": "eif-local:/app/test_assets/minilm/tokenizer.json",
    },
    "hash_algorithm": "sha256",
    "key_id": os.environ["_PY_KMS_KEY"],
    "model_hash": list(model_hash),
    "model_id": model_id,
    "tokenizer_hash": list(tokenizer_hash),
    "version": os.environ["_PY_MODEL_VERSION"],
}
payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
manifest = dict(payload)
manifest["signature"] = list(private.sign(payload_json.encode("utf-8")))

with open(os.environ["_PY_OUT"], "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)

print(public_hex)
PY

MODEL_SIGNING_PUBKEY="$(tail -n 1 "${TMPDIR}/manifest.json" >/dev/null; _PY_MANIFEST="${TMPDIR}/manifest.json" _PY_MODEL_DIR="${MODEL_DIR}" _PY_SIGNING_KEY="${EPHEMERALML_MODEL_SIGNING_KEY:-}" python3 - <<'PY'
import os, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

key_hex = os.environ.get("_PY_SIGNING_KEY", "")
if not key_hex:
    with open(os.path.join(os.environ["_PY_MODEL_DIR"], ".signing_key.hex"), "r", encoding="utf-8") as f:
        key_hex = f.read().strip()
private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex))
print(private.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
).hex())
PY
)"

echo "  EPHEMERALML_MODEL_SIGNING_PUBKEY ${MODEL_SIGNING_PUBKEY}"

echo "[4/5] Upload encrypted weights to S3"
PUT_ARGS=(
  s3api put-object
  --bucket "${BUCKET}"
  --key "${MODEL_ID}"
  --body "${TMPDIR}/model.safetensors.enc"
  --server-side-encryption aws:kms
)
if [[ -n "${SSE_KMS_KEY}" ]]; then
  PUT_ARGS+=(--ssekms-key-id "${SSE_KMS_KEY}")
fi
aws "${PUT_ARGS[@]}" >/dev/null

echo "[5/5] Stage EIF model metadata"
mkdir -p "${PROJECT_DIR}/docker-stage/model"
cp "${CONFIG}" "${PROJECT_DIR}/docker-stage/model/config.json"
cp "${TOKENIZER}" "${PROJECT_DIR}/docker-stage/model/tokenizer.json"
cp "${TMPDIR}/manifest.json" "${PROJECT_DIR}/docker-stage/model/manifest.json"
cp "${TMPDIR}/wrapped_dek.bin" "${PROJECT_DIR}/docker-stage/model/wrapped_dek.bin"

echo ""
echo "=== Complete ==="
echo "Encrypted weights: s3://${BUCKET}/${MODEL_ID}"
echo "Model hash:        ${MODEL_HASH}"
echo "Signing pubkey:    ${MODEL_SIGNING_PUBKEY}"
echo ""
echo "Next build step:"
echo "  cargo build --release --no-default-features --features production -p ephemeral-ml-enclave -p ephemeral-ml-host"
echo "  cp target/release/ephemeral-ml-enclave docker-stage/ephemeral-ml-enclave"
echo "  docker build -f enclave/Dockerfile.enclave.aws-poc \\"
echo "    --build-arg MODEL_SIGNING_PUBKEY=${MODEL_SIGNING_PUBKEY} \\"
echo "    -t cyntrisec-aws-poc-enclave:latest ."
