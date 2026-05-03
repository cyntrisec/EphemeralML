#!/usr/bin/env bash
# run_native_poc.sh - Repeatable AWS-native Nitro PoC runner.
#
# This script operates an existing aws-native-poc CloudFormation stack. It does
# not create infrastructure or build an EIF; the stack must already contain a
# Nitro host and the approved EIF hash must already be pinned in KMS policy.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

STACK_NAME="${CYNTRISEC_STACK_NAME:-}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
INSTANCE_ID=""
EVIDENCE_BUCKET=""
EVIDENCE_KMS_KEY=""
MODEL_BUCKET=""
SMOKE_TEST_BIN="${PROJECT_DIR}/target/release/ephemeralml-smoke-test"
REMOTE_BIN="/opt/cyntrisec/bin/ephemeralml-smoke-test"
REMOTE_KMS_PROXY_BIN="/opt/cyntrisec/bin/kms_proxy_host"
REMOTE_HOST_BIN="/opt/cyntrisec/bin/ephemeral-ml-host"
REMOTE_DOCTOR_BIN="/opt/cyntrisec/bin/ephemeralml-doctor"
REMOTE_VERIFIER_BIN="/opt/cyntrisec/bin/ephemeralml-verify"
EIF_PATH="/opt/cyntrisec/eif/ephemeralml-pilot.eif"
BUNDLE_BASE="/tmp/cyntrisec-aws-poc"
EXPECTED_MODEL_HASH=""
EXPECTED_HOST_PROFILE=""
REPETITIONS=1
NO_BUILD=0
NO_UPLOAD_BINARY=0
LEAVE_RUNNING=0
STOP_AFTER_RUN=0
ALLOW_UNSIGNED_EIF_FOR_POC=0
BINARY_UPLOAD_SSE_MODE="kms"
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage:
  scripts/aws/run_native_poc.sh --stack-name NAME [options]

Runs the AWS-native Nitro PoC smoke test on an existing CloudFormation stack
host through AWS Systems Manager. The script can start a stopped host, upload a
fresh smoke-test binary, run one or more benchmark repetitions, and stop only a
host it started unless --stop-after-run is set.

Required:
  --stack-name NAME            CloudFormation stack name, or CYNTRISEC_STACK_NAME

Options:
  --region REGION             AWS region (default: AWS_REGION/AWS_DEFAULT_REGION/us-east-1)
  --instance-id ID            Override HostInstanceId stack output discovery
  --evidence-bucket NAME      Override EvidenceBucketName stack output discovery
  --evidence-kms-key ARN      Override EvidenceKmsKeyArn stack output discovery
  --model-bucket NAME         Override model bucket; defaults to evidence bucket
  --smoke-test-bin PATH       Local binary to upload (default: target/release/ephemeralml-smoke-test)
  --remote-bin PATH           Remote smoke-test path (default: /opt/cyntrisec/bin/ephemeralml-smoke-test)
  --eif-path PATH             Remote EIF path (default: /opt/cyntrisec/eif/ephemeralml-pilot.eif)
  --bundle-base PATH          Remote bundle base dir (default: /tmp/cyntrisec-aws-poc)
  --expected-model-hash HEX   Enforce expected AIR model hash
  --expected-host-profile NAME
                              Override doctor role check's expected instance profile
  --allow-unsigned-eif-for-poc
                              Internal PoC only: let doctor pass if EIF cosign bundle
                              is absent; report details will show cosign_verified=false
  --binary-upload-sse-s3      Use SSE-S3 for the temporary _codex binary upload.
                              Evidence bundle uploads still use the smoke-test's
                              normal SSE-KMS path from the host role.
  --repetitions N             Number of smoke-test repetitions (default: 1)
  --no-build                  Do not run cargo build before upload
  --no-upload-binary          Use the already-installed remote smoke-test binary
  --leave-running             Do not stop a host this script started
  --stop-after-run            Stop the host after the run even if it was already running
  --dry-run                   Resolve inputs and print planned actions without mutating AWS
  -h, --help                  Show this help

Notes:
  This script intentionally does not solve the EIF/KMS bootstrap loop. Build the
  EIF and update the stack's EnclaveImageSha384 parameter first, then use this
  runner for repeatable evidence and benchmark capture.
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

info() {
  echo "==> $*"
}

warn() {
  echo "WARN: $*" >&2
}

need_cmd() {
  command -v "$1" >/dev/null || die "$1 not found"
}

shell_quote() {
  printf "%q" "$1"
}

stack_output() {
  local key="$1"
  aws cloudformation describe-stacks \
    --region "${REGION}" \
    --stack-name "${STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='${key}'].OutputValue | [0]" \
    --output text
}

make_ssm_parameters() {
  local script_file="$1"
  local params_file="$2"
  python3 - "$script_file" "$params_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    script = f.read()
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump({"commands": [script]}, f)
PY
}

send_ssm_script() {
  local label="$1"
  local script_file="$2"
  local params_file invocation_file command_id status response_code

  params_file="$(mktemp)"
  invocation_file="$(mktemp)"
  make_ssm_parameters "${script_file}" "${params_file}"

  info "SSM: ${label}"
  command_id="$(aws ssm send-command \
    --region "${REGION}" \
    --instance-ids "${INSTANCE_ID}" \
    --document-name "AWS-RunShellScript" \
    --comment "cyntrisec-aws-native-poc ${label}" \
    --parameters "file://${params_file}" \
    --query "Command.CommandId" \
    --output text)"

  set +e
  aws ssm wait command-executed \
    --region "${REGION}" \
    --command-id "${command_id}" \
    --instance-id "${INSTANCE_ID}"
  local wait_status=$?
  set -e

  aws ssm get-command-invocation \
    --region "${REGION}" \
    --command-id "${command_id}" \
    --instance-id "${INSTANCE_ID}" \
    --output json > "${invocation_file}"

  python3 - "${invocation_file}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

stdout = data.get("StandardOutputContent") or ""
stderr = data.get("StandardErrorContent") or ""
if stdout:
    print(stdout.rstrip())
if stderr:
    print(stderr.rstrip(), file=sys.stderr)
PY

  status="$(python3 - "${invocation_file}" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    print(json.load(f).get("Status", ""))
PY
)"
  response_code="$(python3 - "${invocation_file}" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    print(json.load(f).get("ResponseCode", ""))
PY
)"

  rm -f "${params_file}" "${invocation_file}"

  if [[ "${wait_status}" -ne 0 || "${status}" != "Success" || "${response_code}" != "0" ]]; then
    die "SSM command '${label}' failed: status=${status} response_code=${response_code}"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stack-name) STACK_NAME="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --instance-id) INSTANCE_ID="$2"; shift 2 ;;
    --evidence-bucket) EVIDENCE_BUCKET="$2"; shift 2 ;;
    --evidence-kms-key) EVIDENCE_KMS_KEY="$2"; shift 2 ;;
    --model-bucket) MODEL_BUCKET="$2"; shift 2 ;;
    --smoke-test-bin) SMOKE_TEST_BIN="$2"; shift 2 ;;
    --remote-bin) REMOTE_BIN="$2"; shift 2 ;;
    --eif-path) EIF_PATH="$2"; shift 2 ;;
    --bundle-base) BUNDLE_BASE="$2"; shift 2 ;;
    --expected-model-hash) EXPECTED_MODEL_HASH="$2"; shift 2 ;;
    --expected-host-profile) EXPECTED_HOST_PROFILE="$2"; shift 2 ;;
    --repetitions) REPETITIONS="$2"; shift 2 ;;
    --no-build) NO_BUILD=1; shift ;;
    --no-upload-binary) NO_UPLOAD_BINARY=1; shift ;;
    --leave-running) LEAVE_RUNNING=1; shift ;;
    --stop-after-run) STOP_AFTER_RUN=1; shift ;;
    --allow-unsigned-eif-for-poc) ALLOW_UNSIGNED_EIF_FOR_POC=1; shift ;;
    --binary-upload-sse-s3) BINARY_UPLOAD_SSE_MODE="sse-s3"; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "${STACK_NAME}" ]] || { usage; exit 1; }
[[ "${REPETITIONS}" =~ ^[0-9]+$ ]] || die "--repetitions must be an integer"
[[ "${REPETITIONS}" -ge 1 ]] || die "--repetitions must be >= 1"
if [[ "${ALLOW_UNSIGNED_EIF_FOR_POC}" -eq 1
  && "${STACK_NAME}" != *-poc-*
  && "${CYNTRISEC_I_UNDERSTAND_UNSIGNED_EIF_OVERRIDE:-}" != "I_UNDERSTAND" ]]; then
  die "--allow-unsigned-eif-for-poc is refused unless STACK_NAME contains '-poc-' or CYNTRISEC_I_UNDERSTAND_UNSIGNED_EIF_OVERRIDE=I_UNDERSTAND is set"
fi

need_cmd aws
need_cmd python3

info "Resolving stack outputs"
if [[ -z "${INSTANCE_ID}" ]]; then
  INSTANCE_ID="$(stack_output "HostInstanceId")"
fi
if [[ -z "${EVIDENCE_BUCKET}" ]]; then
  EVIDENCE_BUCKET="$(stack_output "EvidenceBucketName")"
fi
if [[ -z "${EVIDENCE_KMS_KEY}" ]]; then
  EVIDENCE_KMS_KEY="$(stack_output "EvidenceKmsKeyArn")"
fi
if [[ -z "${MODEL_BUCKET}" ]]; then
  MODEL_BUCKET="${EVIDENCE_BUCKET}"
fi

[[ -n "${INSTANCE_ID}" && "${INSTANCE_ID}" != "None" ]] || die "could not resolve HostInstanceId"
[[ -n "${EVIDENCE_BUCKET}" && "${EVIDENCE_BUCKET}" != "None" ]] || die "could not resolve EvidenceBucketName"

cat <<EOF
AWS-native PoC run plan
  stack:           ${STACK_NAME}
  region:          ${REGION}
  instance:        ${INSTANCE_ID}
  evidence_bucket: ${EVIDENCE_BUCKET}
  model_bucket:    ${MODEL_BUCKET}
  local_binary:    ${SMOKE_TEST_BIN}
  remote_binary:   ${REMOTE_BIN}
  eif_path:        ${EIF_PATH}
  expected_profile:${EXPECTED_HOST_PROFILE:-<doctor-default>}
  unsigned_eif_poc:${ALLOW_UNSIGNED_EIF_FOR_POC}
  binary_upload_sse:${BINARY_UPLOAD_SSE_MODE}
  repetitions:     ${REPETITIONS}
EOF

if [[ "${DRY_RUN}" -eq 1 ]]; then
  info "dry-run requested; exiting before AWS mutations"
  exit 0
fi

if [[ "${NO_BUILD}" -eq 0 && "${NO_UPLOAD_BINARY}" -eq 0 ]]; then
  info "Building smoke-test binary"
  (cd "${PROJECT_DIR}" && cargo build --release -p ephemeral-ml-smoke-test)
fi

if [[ "${NO_UPLOAD_BINARY}" -eq 0 ]]; then
  [[ -x "${SMOKE_TEST_BIN}" ]] || die "smoke-test binary not found or not executable: ${SMOKE_TEST_BIN}"
fi

STARTED_BY_SCRIPT=0
TEMP_S3_KEY=""

cleanup() {
  local status=$?
  if [[ -n "${TEMP_S3_KEY}" ]]; then
    aws s3 rm "s3://${EVIDENCE_BUCKET}/${TEMP_S3_KEY}" --region "${REGION}" >/dev/null 2>&1 || true
  fi
  if [[ "${LEAVE_RUNNING}" -eq 0 && ( "${STARTED_BY_SCRIPT}" -eq 1 || "${STOP_AFTER_RUN}" -eq 1 ) ]]; then
    info "Stopping host ${INSTANCE_ID}"
    aws ec2 stop-instances --region "${REGION}" --instance-ids "${INSTANCE_ID}" >/dev/null || true
  fi
  exit "${status}"
}
trap cleanup EXIT

INSTANCE_STATE="$(aws ec2 describe-instances \
  --region "${REGION}" \
  --instance-ids "${INSTANCE_ID}" \
  --query "Reservations[0].Instances[0].State.Name" \
  --output text)"

case "${INSTANCE_STATE}" in
  stopped)
    info "Starting stopped host ${INSTANCE_ID}"
    aws ec2 start-instances --region "${REGION}" --instance-ids "${INSTANCE_ID}" >/dev/null
    STARTED_BY_SCRIPT=1
    aws ec2 wait instance-running --region "${REGION}" --instance-ids "${INSTANCE_ID}"
    ;;
  running)
    info "Host is already running"
    ;;
  pending)
    info "Host is pending; waiting for running state"
    aws ec2 wait instance-running --region "${REGION}" --instance-ids "${INSTANCE_ID}"
    ;;
  *)
    die "host must be running or stopped; current state=${INSTANCE_STATE}"
    ;;
esac

info "Waiting for SSM online"
for _ in $(seq 1 60); do
  SSM_ONLINE="$(aws ssm describe-instance-information \
    --region "${REGION}" \
    --filters "Key=InstanceIds,Values=${INSTANCE_ID}" \
    --query "InstanceInformationList[0].PingStatus" \
    --output text 2>/dev/null || true)"
  if [[ "${SSM_ONLINE}" == "Online" ]]; then
    break
  fi
  sleep 5
done
[[ "${SSM_ONLINE}" == "Online" ]] || die "SSM did not become Online for ${INSTANCE_ID}"

if [[ "${NO_UPLOAD_BINARY}" -eq 0 ]]; then
  TEMP_S3_KEY="_codex/ephemeralml-smoke-test-$(date -u +%Y%m%dT%H%M%SZ)-${RANDOM}"
  info "Uploading smoke-test binary to s3://${EVIDENCE_BUCKET}/${TEMP_S3_KEY}"
  S3_CP_ARGS=(s3 cp "${SMOKE_TEST_BIN}" "s3://${EVIDENCE_BUCKET}/${TEMP_S3_KEY}" --region "${REGION}")
  if [[ "${BINARY_UPLOAD_SSE_MODE}" == "sse-s3" ]]; then
    warn "binary upload uses SSE-S3 (no KMS access control); ensure no read-only IAM principal can list or read _codex/ objects"
    S3_CP_ARGS+=(--sse AES256)
  elif [[ -n "${EVIDENCE_KMS_KEY}" && "${EVIDENCE_KMS_KEY}" != "None" ]]; then
    S3_CP_ARGS+=(--sse aws:kms --sse-kms-key-id "${EVIDENCE_KMS_KEY}")
  fi
  aws "${S3_CP_ARGS[@]}" >/dev/null

  install_script="$(mktemp)"
  {
    echo "set -euo pipefail"
    echo "tmp=\$(mktemp)"
    echo "aws s3 cp $(shell_quote "s3://${EVIDENCE_BUCKET}/${TEMP_S3_KEY}") \"\${tmp}\" --region $(shell_quote "${REGION}")"
    echo "sudo install -m 0755 \"\${tmp}\" $(shell_quote "${REMOTE_BIN}")"
    echo "rm -f \"\${tmp}\""
    echo "$(shell_quote "${REMOTE_BIN}") --help >/dev/null"
  } > "${install_script}"
  send_ssm_script "install-smoke-test" "${install_script}"
  rm -f "${install_script}"
fi

for run_index in $(seq 1 "${REPETITIONS}"); do
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-run${run_index}"
  bundle_dir="${BUNDLE_BASE}/${run_id}"
  run_script="$(mktemp)"
  {
    echo "set -euo pipefail"
    echo "sudo mkdir -p $(shell_quote "${bundle_dir}")"
    echo "sudo -E env \\"
    echo "  AWS_REGION=$(shell_quote "${REGION}") \\"
    echo "  AWS_DEFAULT_REGION=$(shell_quote "${REGION}") \\"
    if [[ -n "${EXPECTED_HOST_PROFILE}" ]]; then
      echo "  CYNTRISEC_EXPECTED_HOST_PROFILE=$(shell_quote "${EXPECTED_HOST_PROFILE}") \\"
    fi
    if [[ "${ALLOW_UNSIGNED_EIF_FOR_POC}" -eq 1 ]]; then
      echo "  CYNTRISEC_DOCTOR_ALLOW_UNSIGNED_EIF_FOR_POC=1 \\"
    fi
    echo "  $(shell_quote "${REMOTE_BIN}") \\"
    echo "  --json \\"
    echo "  --terminate-existing \\"
    echo "  --stack-name $(shell_quote "${STACK_NAME}") \\"
    echo "  --bundle-dir $(shell_quote "${bundle_dir}") \\"
    echo "  --eif-path $(shell_quote "${EIF_PATH}") \\"
    echo "  --kms-proxy-bin $(shell_quote "${REMOTE_KMS_PROXY_BIN}") \\"
    echo "  --host-bin $(shell_quote "${REMOTE_HOST_BIN}") \\"
    echo "  --doctor-bin $(shell_quote "${REMOTE_DOCTOR_BIN}") \\"
    echo "  --verifier-bin $(shell_quote "${REMOTE_VERIFIER_BIN}") \\"
    echo "  --evidence-bucket $(shell_quote "${EVIDENCE_BUCKET}") \\"
    echo "  --model-bucket $(shell_quote "${MODEL_BUCKET}") \\"
    if [[ -n "${EXPECTED_MODEL_HASH}" ]]; then
      echo "  --expected-model-hash $(shell_quote "${EXPECTED_MODEL_HASH}") \\"
    fi
    echo "  --verbose"
  } > "${run_script}"
  send_ssm_script "smoke-test-${run_id}" "${run_script}"
  rm -f "${run_script}"
done

info "AWS-native PoC run complete"
