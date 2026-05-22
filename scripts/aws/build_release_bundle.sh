#!/usr/bin/env bash
# build_release_bundle.sh - assemble the Cyntrisec AWS pilot AMI payload.
#
# The output directory is intentionally shaped like the target filesystem so it
# can be copied into a Packer build with one upload step. The EIF is treated as
# a fixed release artifact: AMI version, EIF measurement, KMS policy, and
# verifier expected measurements must move together.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

VERSION="${CYNTRISEC_RELEASE_VERSION:-$(git -C "${PROJECT_DIR}" rev-parse --short HEAD 2>/dev/null || date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="${PROJECT_DIR}/dist/aws-ami/cyntrisec-aws-pilot-${VERSION}"
EIF_PATH="${CYNTRISEC_EIF_PATH:-}"
BUILD_EIF=0
MEASUREMENTS_JSON="${CYNTRISEC_EIF_MEASUREMENTS_JSON:-}"
MODEL_DIR="${CYNTRISEC_MODEL_DIR:-}"
SKIP_BUILD=0
SKIP_EIF=0
DOCKERFILE="${PROJECT_DIR}/enclave/Dockerfile.enclave.aws-poc"

usage() {
  cat <<'EOF'
Usage:
  scripts/aws/build_release_bundle.sh [options]

Assembles the filesystem payload consumed by infra/aws-ami/packer.

Options:
  --version VERSION        Release version label. Default: git short SHA.
  --out-dir PATH           Output directory. Default: dist/aws-ami/cyntrisec-aws-pilot-$VERSION
  --eif PATH               Fixed EIF artifact to copy into the bundle.
  --measurements-json PATH Nitro measurements JSON/text captured from nitro-cli
                           build-enclave or nitro-cli describe-eif. Required
                           with --eif unless nitro-cli describe-eif works locally.
  --build-eif              Build the EIF from enclave/Dockerfile.enclave.aws-poc.
  --model-dir PATH         Model staging dir used when --build-eif is set. Must contain
                           config.json, tokenizer.json, manifest.json, wrapped_dek.bin.
  --skip-build             Do not run cargo builds; package existing target/release binaries.
  --skip-eif               Do not require or package an EIF. For dry AMI plumbing tests only.
  -h, --help               Show this help.

Release discipline:
  For a real pilot, do not use --skip-eif. Build or provide one fixed EIF, record
  the Nitro PCR0/1/2 measurements, and update the CloudFormation KMS
  RecipientAttestation parameters for that same release. The EIF file hash is
  recorded only as an inventory hash; it is not the KMS ImageSha384/PCR0 value.
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

info() {
  echo "==> $*"
}

need_cmd() {
  command -v "$1" >/dev/null || die "$1 not found"
}

sha384_file() {
  sha384sum "$1" | awk '{print $1}'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; OUT_DIR="${PROJECT_DIR}/dist/aws-ami/cyntrisec-aws-pilot-${VERSION}"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --eif) EIF_PATH="$2"; shift 2 ;;
    --measurements-json) MEASUREMENTS_JSON="$2"; shift 2 ;;
    --build-eif) BUILD_EIF=1; shift ;;
    --model-dir) MODEL_DIR="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --skip-eif) SKIP_EIF=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

need_cmd install
need_cmd sha256sum
need_cmd sha384sum

if [[ "${SKIP_BUILD}" -eq 0 ]]; then
  info "Building AWS pilot binaries"
  cargo build --release -p ephemeral-ml-host --features production --bin ephemeral-ml-host --bin kms_proxy_host
  cargo build --release -p ephemeralml-gateway --features production --bin ephemeralml-gateway
  cargo build --release -p ephemeral-ml-smoke-test
  cargo build --release -p ephemeralml-doctor
  cargo build --release -p ephemeral-ml-client --bin ephemeralml-verify
fi

if [[ "${BUILD_EIF}" -eq 1 ]]; then
  need_cmd docker
  need_cmd nitro-cli
  [[ -n "${MODEL_DIR}" ]] || die "--model-dir is required with --build-eif"
  for file in config.json tokenizer.json manifest.json wrapped_dek.bin; do
    [[ -f "${MODEL_DIR}/${file}" ]] || die "missing model staging file: ${MODEL_DIR}/${file}"
  done

  info "Building enclave binary for EIF"
  cargo build --release -p ephemeral-ml-enclave --features production --bin ephemeral-ml-enclave

  stage_dir="${PROJECT_DIR}/docker-stage"
  rm -rf "${stage_dir}"
  install -d "${stage_dir}/model"
  install -m 0755 "${PROJECT_DIR}/target/release/ephemeral-ml-enclave" "${stage_dir}/ephemeral-ml-enclave"
  install -m 0644 "${MODEL_DIR}/config.json" "${stage_dir}/model/config.json"
  install -m 0644 "${MODEL_DIR}/tokenizer.json" "${stage_dir}/model/tokenizer.json"
  install -m 0644 "${MODEL_DIR}/manifest.json" "${stage_dir}/model/manifest.json"
  install -m 0644 "${MODEL_DIR}/wrapped_dek.bin" "${stage_dir}/model/wrapped_dek.bin"

  image_tag="cyntrisec-aws-pilot-enclave:${VERSION}"
  EIF_PATH="${PROJECT_DIR}/dist/aws-ami/cyntrisec-aws-pilot-${VERSION}.eif"
  MEASUREMENTS_JSON="${EIF_PATH}.measurements.json"
  install -d "$(dirname "${EIF_PATH}")"
  info "Building Docker image ${image_tag}"
  docker build -f "${DOCKERFILE}" -t "${image_tag}" "${PROJECT_DIR}"
  info "Building EIF ${EIF_PATH}"
  nitro-cli build-enclave --docker-uri "${image_tag}" --output-file "${EIF_PATH}" | tee "${MEASUREMENTS_JSON}"
fi

if [[ "${SKIP_EIF}" -eq 0 ]]; then
  [[ -n "${EIF_PATH}" ]] || die "provide --eif PATH, set CYNTRISEC_EIF_PATH, or use --build-eif"
  [[ -f "${EIF_PATH}" ]] || die "EIF not found: ${EIF_PATH}"
fi

info "Assembling release bundle: ${OUT_DIR}"
rm -rf "${OUT_DIR}"
install -d \
  "${OUT_DIR}/opt/cyntrisec/bin" \
  "${OUT_DIR}/opt/cyntrisec/eif" \
  "${OUT_DIR}/opt/cyntrisec/systemd" \
  "${OUT_DIR}/opt/cyntrisec/share" \
  "${OUT_DIR}/etc/cyntrisec"

install -m 0755 "${PROJECT_DIR}/target/release/ephemeral-ml-host" "${OUT_DIR}/opt/cyntrisec/bin/ephemeral-ml-host"
install -m 0755 "${PROJECT_DIR}/target/release/kms_proxy_host" "${OUT_DIR}/opt/cyntrisec/bin/kms_proxy_host"
install -m 0755 "${PROJECT_DIR}/target/release/ephemeralml-gateway" "${OUT_DIR}/opt/cyntrisec/bin/ephemeralml-gateway"
install -m 0755 "${PROJECT_DIR}/target/release/ephemeralml-smoke-test" "${OUT_DIR}/opt/cyntrisec/bin/ephemeralml-smoke-test"
install -m 0755 "${PROJECT_DIR}/target/release/ephemeralml-doctor" "${OUT_DIR}/opt/cyntrisec/bin/ephemeralml-doctor"
install -m 0755 "${PROJECT_DIR}/target/release/ephemeralml-verify" "${OUT_DIR}/opt/cyntrisec/bin/ephemeralml-verify"
install -m 0755 "${PROJECT_DIR}/infra/aws-ami/files/cyntrisec-bootstrap" "${OUT_DIR}/opt/cyntrisec/bin/cyntrisec-bootstrap"
install -m 0644 "${PROJECT_DIR}/infra/aws-ami/files/cyntrisec-bootstrap.service" "${OUT_DIR}/opt/cyntrisec/systemd/cyntrisec-bootstrap.service"
install -m 0644 "${PROJECT_DIR}/infra/aws-ami/files/deployment.env.example" "${OUT_DIR}/etc/cyntrisec/deployment.env.example"

if [[ "${SKIP_EIF}" -eq 0 ]]; then
  install -m 0644 "${EIF_PATH}" "${OUT_DIR}/opt/cyntrisec/eif/ephemeralml-pilot.eif"
  if [[ -n "${MEASUREMENTS_JSON}" && -f "${MEASUREMENTS_JSON}" ]]; then
    install -m 0644 "${MEASUREMENTS_JSON}" "${OUT_DIR}/opt/cyntrisec/eif/ephemeralml-pilot.measurements.json"
  elif command -v nitro-cli >/dev/null 2>&1; then
    nitro-cli describe-eif --eif-path "${OUT_DIR}/opt/cyntrisec/eif/ephemeralml-pilot.eif" \
      >"${OUT_DIR}/opt/cyntrisec/eif/ephemeralml-pilot.measurements.json"
  else
    die "Nitro measurements unavailable. Provide --measurements-json or run on a host with nitro-cli describe-eif."
  fi
fi

manifest="${OUT_DIR}/opt/cyntrisec/release-manifest.json"
python3 - "$manifest" "$VERSION" "$OUT_DIR" "$SKIP_EIF" <<'PY'
import json
import re
import subprocess
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
version = sys.argv[2]
out_dir = Path(sys.argv[3])
skip_eif = sys.argv[4] == "1"

HEX_384 = re.compile(r"^[0-9a-fA-F]{96}$")


def digest(algorithm: str, path: Path) -> str:
    output = subprocess.check_output([f"{algorithm}sum", str(path)], text=True)
    return output.split()[0]


def find_measurements(obj):
    values = {}

    def visit(key, value):
        key_l = str(key).lower()
        if isinstance(value, str) and HEX_384.fullmatch(value):
            if key_l in {"pcr0", "image_sha384", "imagesha384", "imagehash"}:
                values.setdefault("pcr0", value.lower())
            elif key_l == "pcr1":
                values.setdefault("pcr1", value.lower())
            elif key_l == "pcr2":
                values.setdefault("pcr2", value.lower())
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                visit(child_key, child_value)
        elif isinstance(value, list):
            for child_value in value:
                visit(key, child_value)

    visit("root", obj)
    return values


def parse_measurements(path: Path) -> dict[str, str]:
    raw = path.read_text(encoding="utf-8")
    try:
        parsed = json.loads(raw)
        values = find_measurements(parsed)
    except json.JSONDecodeError:
        values = {}
        for name in ("PCR0", "PCR1", "PCR2"):
            match = re.search(rf"{name}[^0-9a-fA-F]*([0-9a-fA-F]{{96}})", raw, re.IGNORECASE)
            if match:
                values[name.lower()] = match.group(1).lower()
        image = re.search(r"ImageSha384[^0-9a-fA-F]*([0-9a-fA-F]{96})", raw, re.IGNORECASE)
        if image:
            values.setdefault("pcr0", image.group(1).lower())
    missing = [name for name in ("pcr0", "pcr1", "pcr2") if name not in values]
    if missing:
        raise SystemExit(f"missing Nitro measurements in {path}: {', '.join(missing)}")
    return values

files = {}
for path in sorted((out_dir / "opt/cyntrisec/bin").iterdir()):
    if path.is_file():
        files[path.name] = {"sha256": digest("sha256", path)}

payload = {
    "schema_version": "cyntrisec.aws_ami_release.v1",
    "version": version,
    "binaries": files,
    "eif": None,
}

if not skip_eif:
    bundled_eif = out_dir / "opt/cyntrisec/eif/ephemeralml-pilot.eif"
    measurements_path = out_dir / "opt/cyntrisec/eif/ephemeralml-pilot.measurements.json"
    measurements = parse_measurements(measurements_path)
    payload["eif"] = {
        "path": "/opt/cyntrisec/eif/ephemeralml-pilot.eif",
        "file_sha384": digest("sha384", bundled_eif),
        "measurements": measurements,
    }

manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

info "Release bundle ready"
echo "  bundle:   ${OUT_DIR}"
echo "  manifest: ${manifest}"
if [[ "${SKIP_EIF}" -eq 0 ]]; then
  echo "  eif_file_sha384: $(sha384_file "${OUT_DIR}/opt/cyntrisec/eif/ephemeralml-pilot.eif")"
  python3 - "${manifest}" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    eif = json.load(f)["eif"]
measurements = eif["measurements"]
print(f"  cfn_EnclaveImageSha384: {measurements['pcr0']}")
print(f"  cfn_EnclavePcr1Sha384: {measurements['pcr1']}")
print(f"  cfn_EnclavePcr2Sha384: {measurements['pcr2']}")
PY
fi
