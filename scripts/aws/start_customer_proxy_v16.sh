#!/usr/bin/env bash
# Deploy the Cluster A v1.6 AWS worker stack and start the local customer proxy.
#
# This automates steps 1-5 of the customer E2E runbook:
#   1. Set release values
#   2. Deploy the CloudFormation worker stack
#   3. Read stack outputs
#   4. Download policy + model manifest through SSM
#   5. Run the local proxy container and wait for /health
#
# It intentionally does not run the batch verifier or cleanup. After this script
# succeeds, run scripts/aws/customer_openai_e2e.sh with the printed command.
set -euo pipefail

AWS_REGION_NAME="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
RELEASE_TAG="v1.6"
MODEL_ID="stage-0"
MODEL_URI="s3://cyntrisec-placeholder-models/stage-0-minilm"
INSTANCE_TYPE="m5.xlarge"
RETENTION_DAYS="7"
ENABLE_OBJECT_LOCK="false"
STACK_NAME=""
BUCKET_NAME=""
ACCESS_CIDR=""
OUT_DIR=""
PROXY_CONTAINER="cyntrisec-e2e-proxy"
PROXY_PORT="4000"

TEMPLATE_URL="https://s3.us-east-1.amazonaws.com/cyntrisec-public-templates-us-east-1/aws/v1.6/worker.yaml?versionId=geKxLqg1klvD7tgZeCuuyDSqm_wW_sLX"
ENCLAVE_IMAGE_SHA384="cb522223eebc335a2ebca329c076f4cd7eeb10db824bd853bee6db9706301645ad3dd71228038bbe805b7a8212cdb024"
ENCLAVE_PCR1_SHA384="4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493"
ENCLAVE_PCR2_SHA384="0216e427b4381a540d4895542e3acd4ed248679d008c61754e4a79bc27a8344792d9b925bfa4adf47215b3e5fc00b59a"

usage() {
    cat <<'USAGE'
Usage:
  bash scripts/aws/start_customer_proxy_v16.sh [options]

Options:
  --stack-name NAME       CloudFormation stack name. Default: cyntrisec-e2e-v16-<timestamp>
  --bucket-name NAME      Evidence bucket name. Default: cyntrisec-e2e-v16-<account>-<timestamp>
  --access-cidr CIDR      CIDR allowed to reach the worker NLB. Default: current public IP /32
  --region REGION         AWS region. Default: AWS_REGION/AWS_DEFAULT_REGION/us-east-1
  --out-dir DIR           Local output dir. Default: /tmp/<stack-name>
  --proxy-container NAME  Docker container name. Default: cyntrisec-e2e-proxy
  --proxy-port PORT       Local proxy port. Default: 4000
  --help                  Show this help

After success, run the printed customer_openai_e2e.sh command to execute the
OpenAI-format request batch and offline bundle verification.
USAGE
}

log() {
    printf '[cyntrisec-start] %s\n' "$*"
}

fail() {
    printf '[cyntrisec-start] ERROR: %s\n' "$*" >&2
    exit 1
}

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "missing required command: $1"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --stack-name) STACK_NAME="$2"; shift 2 ;;
        --bucket-name) BUCKET_NAME="$2"; shift 2 ;;
        --access-cidr) ACCESS_CIDR="$2"; shift 2 ;;
        --region) AWS_REGION_NAME="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --proxy-container) PROXY_CONTAINER="$2"; shift 2 ;;
        --proxy-port) PROXY_PORT="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

need aws
need curl
need docker
need jq

timestamp="$(date -u +%Y%m%d%H%M%S)"
account_id="$(aws sts get-caller-identity --query Account --output text)"

if [[ -z "$STACK_NAME" ]]; then
    STACK_NAME="cyntrisec-e2e-v16-${timestamp}"
fi
if [[ -z "$BUCKET_NAME" ]]; then
    BUCKET_NAME="cyntrisec-e2e-v16-${account_id}-${timestamp}"
fi
if [[ -z "$ACCESS_CIDR" ]]; then
    current_ip="$(curl -fsS https://checkip.amazonaws.com | tr -d '\n')"
    [[ -n "$current_ip" ]] || fail "could not determine current public IP"
    ACCESS_CIDR="${current_ip}/32"
fi
if [[ -z "$OUT_DIR" ]]; then
    OUT_DIR="/tmp/${STACK_NAME}"
fi

mkdir -p "$OUT_DIR"

if aws cloudformation describe-stacks \
    --region "$AWS_REGION_NAME" \
    --stack-name "$STACK_NAME" >/dev/null 2>&1; then
    fail "stack already exists: $STACK_NAME"
fi

log "region: $AWS_REGION_NAME"
log "stack: $STACK_NAME"
log "evidence bucket: $BUCKET_NAME"
log "access CIDR: $ACCESS_CIDR"
log "local output: $OUT_DIR"

log "creating CloudFormation stack"
aws cloudformation create-stack \
    --region "$AWS_REGION_NAME" \
    --stack-name "$STACK_NAME" \
    --template-url "$TEMPLATE_URL" \
    --capabilities CAPABILITY_NAMED_IAM \
    --on-failure DO_NOTHING \
    --parameters \
        ParameterKey=AccessCIDR,ParameterValue="$ACCESS_CIDR" \
        ParameterKey=ModelURI,ParameterValue="$MODEL_URI" \
        ParameterKey=EvidenceBucketName,ParameterValue="$BUCKET_NAME" \
        ParameterKey=RetentionDays,ParameterValue="$RETENTION_DAYS" \
        ParameterKey=InstanceType,ParameterValue="$INSTANCE_TYPE" \
        ParameterKey=EnableObjectLock,ParameterValue="$ENABLE_OBJECT_LOCK" \
        ParameterKey=ReleaseTag,ParameterValue="$RELEASE_TAG" \
        ParameterKey=EnclaveImageSha384,ParameterValue="$ENCLAVE_IMAGE_SHA384" \
        ParameterKey=EnclavePcr1Sha384,ParameterValue="$ENCLAVE_PCR1_SHA384" \
        ParameterKey=EnclavePcr2Sha384,ParameterValue="$ENCLAVE_PCR2_SHA384" >/dev/null

if ! aws cloudformation wait stack-create-complete \
    --region "$AWS_REGION_NAME" \
    --stack-name "$STACK_NAME"; then
    log "latest CloudFormation events:"
    aws cloudformation describe-stack-events \
        --region "$AWS_REGION_NAME" \
        --stack-name "$STACK_NAME" \
        --query 'StackEvents[0:20].[Timestamp,LogicalResourceId,ResourceStatus,ResourceStatusReason]' \
        --output table >&2 || true
    fail "stack did not reach CREATE_COMPLETE"
fi

log "stack CREATE_COMPLETE"
aws cloudformation describe-stacks \
    --region "$AWS_REGION_NAME" \
    --stack-name "$STACK_NAME" \
    --query 'Stacks[0].Outputs' \
    --output json > "${OUT_DIR}/outputs.json"

ENDPOINT_URL="$(jq -r '.[] | select(.OutputKey=="EndpointUrl").OutputValue' "${OUT_DIR}/outputs.json")"
WORKER_INSTANCE_ID="$(jq -r '.[] | select(.OutputKey=="WorkerInstanceId").OutputValue' "${OUT_DIR}/outputs.json")"

[[ "$ENDPOINT_URL" != "null" && -n "$ENDPOINT_URL" ]] || fail "missing EndpointUrl output"
[[ "$WORKER_INSTANCE_ID" != "null" && -n "$WORKER_INSTANCE_ID" ]] || fail "missing WorkerInstanceId output"

log "endpoint: $ENDPOINT_URL"
log "worker instance: $WORKER_INSTANCE_ID"

run_ssm_capture() {
    local comment="$1"
    local remote_command="$2"
    local output_path="$3"
    local command_id status

    for _ in $(seq 1 45); do
        if command_id="$(aws ssm send-command \
            --region "$AWS_REGION_NAME" \
            --instance-ids "$WORKER_INSTANCE_ID" \
            --document-name AWS-RunShellScript \
            --comment "$comment" \
            --parameters "commands=${remote_command}" \
            --query Command.CommandId \
            --output text 2>/dev/null)"; then
            break
        fi
        sleep 5
    done

    [[ -n "${command_id:-}" ]] || fail "could not send SSM command: $comment"

    for _ in $(seq 1 90); do
        status="$(aws ssm get-command-invocation \
            --region "$AWS_REGION_NAME" \
            --command-id "$command_id" \
            --instance-id "$WORKER_INSTANCE_ID" \
            --query Status \
            --output text 2>/dev/null || true)"

        case "$status" in
            Success)
                aws ssm get-command-invocation \
                    --region "$AWS_REGION_NAME" \
                    --command-id "$command_id" \
                    --instance-id "$WORKER_INSTANCE_ID" \
                    --query StandardOutputContent \
                    --output text > "$output_path"
                return 0
                ;;
            Failed|Cancelled|TimedOut|Cancelling)
                aws ssm get-command-invocation \
                    --region "$AWS_REGION_NAME" \
                    --command-id "$command_id" \
                    --instance-id "$WORKER_INSTANCE_ID" >&2 || true
                fail "SSM command failed: $comment"
                ;;
        esac
        sleep 2
    done

    fail "timed out waiting for SSM command: $comment"
}

log "downloading policy through SSM"
run_ssm_capture \
    "cyntrisec-policy-download" \
    "aws s3 cp s3://${BUCKET_NAME}/policy/cyntrisec-policy.json -" \
    "${OUT_DIR}/cyntrisec-policy.json"

log "downloading model manifest through SSM"
run_ssm_capture \
    "cyntrisec-manifest-download" \
    "aws s3 cp s3://${BUCKET_NAME}/policy/model-manifest.json -" \
    "${OUT_DIR}/model-manifest.json"

log "starting local proxy container: $PROXY_CONTAINER"
docker rm -f "$PROXY_CONTAINER" >/dev/null 2>&1 || true
docker run -d \
    --name "$PROXY_CONTAINER" \
    -p "${PROXY_PORT}:4000" \
    -e CYNTRISEC_PROXY_HOST=0.0.0.0 \
    -e CYNTRISEC_MODEL_CAPABILITIES=embeddings \
    -e CYNTRISEC_WORKER="$ENDPOINT_URL" \
    -e CYNTRISEC_WORKER_CHANNEL=secure \
    -e CYNTRISEC_POLICY_PATH=/etc/cyntrisec/policy.json \
    -e CYNTRISEC_MANIFEST_PATH=/etc/cyntrisec/model-manifest.json \
    -v "${OUT_DIR}/cyntrisec-policy.json:/etc/cyntrisec/policy.json:ro" \
    -v "${OUT_DIR}/model-manifest.json:/etc/cyntrisec/model-manifest.json:ro" \
    "public.ecr.aws/f4z4g3i5/proxy:${RELEASE_TAG}" >/dev/null

health_url="http://127.0.0.1:${PROXY_PORT}/health"
for _ in $(seq 1 90); do
    if health="$(curl -fsS "$health_url" 2>/dev/null)"; then
        if printf '%s\n' "$health" | jq -e '.status == "ok" and .backend_connected == true' >/dev/null; then
            printf '%s\n' "$health" > "${OUT_DIR}/proxy-health.json"
            log "proxy health OK"
            break
        fi
    fi
    sleep 2
done

if [[ ! -f "${OUT_DIR}/proxy-health.json" ]]; then
    docker logs --tail 120 "$PROXY_CONTAINER" >&2 || true
    fail "proxy did not become healthy at $health_url"
fi

cat > "${OUT_DIR}/env.sh" <<EOF
export AWS_REGION='${AWS_REGION_NAME}'
export AWS_DEFAULT_REGION='${AWS_REGION_NAME}'
export CYNTRISEC_E2E_STACK_NAME='${STACK_NAME}'
export CYNTRISEC_E2E_BUCKET_NAME='${BUCKET_NAME}'
export CYNTRISEC_E2E_OUT_DIR='${OUT_DIR}'
export CYNTRISEC_GATEWAY_URL='http://127.0.0.1:${PROXY_PORT}'
export CYNTRISEC_E2E_MODEL='${MODEL_ID}'
export CYNTRISEC_EXPECTED_RECEIPT_MODEL='${MODEL_ID}'
export CYNTRISEC_E2E_S3_PRESIGN_SSM_INSTANCE_ID='${WORKER_INSTANCE_ID}'
export CYNTRISEC_E2E_PROXY_CONTAINER='${PROXY_CONTAINER}'
EOF

cat <<EOF

READY

Stack:      ${STACK_NAME}
Bucket:     ${BUCKET_NAME}
Endpoint:   ${ENDPOINT_URL}
Worker EC2: ${WORKER_INSTANCE_ID}
Proxy:      ${health_url}
State file: ${OUT_DIR}/env.sh

Run step 6:

  source '${OUT_DIR}/env.sh'
  CARGO_TARGET_DIR=/tmp/ephemeralml-target \\
    bash scripts/aws/customer_openai_e2e.sh \\
      --url "\$CYNTRISEC_GATEWAY_URL" \\
      --model "\$CYNTRISEC_E2E_MODEL" \\
      --expected-model "\$CYNTRISEC_EXPECTED_RECEIPT_MODEL" \\
      --out-dir "\$CYNTRISEC_E2E_OUT_DIR/customer-openai-e2e" \\
      --s3-presign-ssm-instance-id "\$CYNTRISEC_E2E_S3_PRESIGN_SSM_INSTANCE_ID"

Cleanup reminder:

  docker rm -f '${PROXY_CONTAINER}'
  aws cloudformation delete-stack --region '${AWS_REGION_NAME}' --stack-name '${STACK_NAME}'
  aws cloudformation wait stack-delete-complete --region '${AWS_REGION_NAME}' --stack-name '${STACK_NAME}'

Then delete retained bucket/log groups/KMS keys exactly as documented in docs/pilot-deployment-runbook.md.
EOF
