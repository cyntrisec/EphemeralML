#!/usr/bin/env bash
set -euo pipefail

# EphemeralML Milestone A2 runner: Nitro Enclave VSOCK ping/pong
# Runs from Boris laptop. Creates AWS resources via Terraform, executes host steps via SSM SendCommand,
# captures logs for analysis, then destroys infra.
#
# Requirements (local): awscli configured, terraform, jq.
# Permissions: ability to create EC2/VPC/IAM via terraform; SSM SendCommand permissions.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$ROOT_DIR/../.." && pwd)" # projects/EphemeralML
STACK_DIR="$ROOT_DIR" # infra/hello-enclave

REGION="${AWS_REGION:-us-east-1}"
AZ="${A2_AZ:-us-east-1a}"
ITYPE="${A2_INSTANCE_TYPE:-m6i.xlarge}"
TIMEBOX_MIN="${A2_TIMEBOX_MIN:-30}"

RUN_ID="a2-$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="$STACK_DIR/logs/$RUN_ID"
mkdir -p "$LOG_DIR"

log() { echo "[$(date -u +%H:%M:%S)] $*"; }

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing dependency: $1" >&2
    exit 2
  }
}

need aws
need terraform
need jq

# Tee everything to a log
exec > >(tee "$LOG_DIR/local.log") 2>&1

log "RunID: $RUN_ID"
log "Region=$REGION AZ=$AZ InstanceType=$ITYPE Timebox=${TIMEBOX_MIN}min"

log "Preflight: caller identity"
aws sts get-caller-identity --output json | tee "$LOG_DIR/caller_identity.json"

log "Preflight: existing hello-host instances (should be empty)"
aws ec2 describe-instances \
  --region "$REGION" \
  --filters \
    'Name=tag:Name,Values=ephemeral-ml-hello-host' \
    'Name=instance-state-name,Values=pending,running,stopping,stopped' \
  --output json | tee "$LOG_DIR/pre_instances.json" >/dev/null
jq -r '.Reservations[].Instances[] | [.InstanceId,.State.Name,.InstanceType,.Placement.AvailabilityZone] | @tsv' "$LOG_DIR/pre_instances.json" || true

log "Preflight: terraform state list"
(
  cd "$STACK_DIR"
  terraform state list || true
) | tee "$LOG_DIR/pre_state.txt"

cat <<EOF

About to run Terraform APPLY (this creates AWS resources and may incur cost).
Expected runtime cost for $ITYPE is roughly: $0.192/hr (order of magnitude), so ${TIMEBOX_MIN}min ~ $0.$((TIMEBOX_MIN*192/60))

Type YES to proceed, anything else to abort:
EOF
read -r CONFIRM
if [[ "$CONFIRM" != "YES" ]]; then
  log "Aborted by user."
  exit 1
fi

log "Terraform init/plan/apply"
(
  cd "$STACK_DIR"
  terraform init -input=false
  terraform plan -input=false -var "availability_zone=$AZ" -var "instance_type=$ITYPE" | tee "$LOG_DIR/plan.txt"
  terraform apply -auto-approve -input=false -var "availability_zone=$AZ" -var "instance_type=$ITYPE" | tee "$LOG_DIR/apply.txt"

  terraform output -json | tee "$LOG_DIR/tf_output.json" >/dev/null
)

INSTANCE_ID=$(jq -r '.instance_id.value' "$LOG_DIR/tf_output.json")
log "Instance: $INSTANCE_ID"

log "Wait for SSM to see the instance"
SSM_OK=0
for i in {1..40}; do
  if aws ssm describe-instance-information --region "$REGION" --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
      --output json | jq -e '.InstanceInformationList | length > 0' >/dev/null; then
    SSM_OK=1
    break
  fi
  sleep 5
done
if [[ "$SSM_OK" != "1" ]]; then
  log "ERROR: Instance not visible in SSM after waiting."
  log "Proceeding to destroy for safety."
  goto_destroy=1
else
  log "SSM online. Sending remote command set (host-side steps)."
fi

# Create the remote script inline (run on the EC2 parent)
REMOTE_SH="$LOG_DIR/remote_on_host.sh"
cat >"$REMOTE_SH" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

log(){ echo "[host $(date -u +%H:%M:%S)] $*"; }

log "OS:"; cat /etc/os-release || true

# Ensure basic tools
sudo yum update -y
sudo yum install -y git jq python3 docker || true
sudo systemctl enable --now docker || true

# Nitro Enclaves tooling (AL2)
if ! command -v nitro-cli >/dev/null 2>&1; then
  log "Installing aws-nitro-enclaves-cli via amazon-linux-extras"
  sudo amazon-linux-extras install -y aws-nitro-enclaves-cli
fi

# Ensure blobs for build-enclave
if [[ ! -d /usr/share/nitro_enclaves/blobs ]]; then
  log "Installing cli-devel to get blobs"
  sudo yum install -y aws-nitro-enclaves-cli-devel
  sudo yum reinstall -y aws-nitro-enclaves-cli
fi

log "nitro-cli: $(nitro-cli --version || true)"

# Allocator config
sudo mkdir -p /etc/nitro_enclaves
cat <<'EOF' | sudo tee /etc/nitro_enclaves/allocator.yaml
---
cpu_count: 2
memory_mib: 1024
EOF
sudo systemctl enable --now nitro-enclaves-allocator.service
sudo systemctl start nitro-enclaves-allocator.service

# Source code delivery
# Prefer a tarball shipped by the launcher (works with private repos / avoids path mismatches).
WORK=/home/ec2-user/a2
mkdir -p "$WORK"

if [[ -n "${A2_TAR_B64:-}" ]]; then
  log "Extracting vsock-pingpong sources from A2_TAR_B64"
  echo "$A2_TAR_B64" | base64 -d | tar -xz -C "$WORK"
  cd "$WORK/vsock-pingpong"
else
  # Fallback: fetch repo if a public git URL was provided.
  if [[ -z "${REPO_URL:-}" ]]; then
    log "ERROR: neither A2_TAR_B64 nor REPO_URL is set"
    exit 3
  fi

  REPO_DIR=/home/ec2-user/clawd
  if [[ ! -d "$REPO_DIR" ]]; then
    log "Cloning repo to $REPO_DIR"
    git clone "$REPO_URL" "$REPO_DIR"
  else
    log "Repo exists; updating"
    (cd "$REPO_DIR" && git pull --ff-only) || true
  fi

  cd "$REPO_DIR/projects/EphemeralML/enclaves/vsock-pingpong"
fi

log "Docker build"
sudo docker build -t ephemeralml/vsock-pingpong:latest .

log "Build EIF"
sudo nitro-cli build-enclave --docker-uri ephemeralml/vsock-pingpong:latest --output-file vsock-pingpong.eif
ls -lh vsock-pingpong.eif

log "Run enclave"
RUN_JSON=$(sudo nitro-cli run-enclave --eif-path vsock-pingpong.eif --cpu-count 2 --memory 1024 --enclave-cid 16 --debug-mode)
echo "$RUN_JSON"
ENCLAVE_ID=$(echo "$RUN_JSON" | jq -r '.EnclaveID')
log "EnclaveID: $ENCLAVE_ID"

sleep 2
DESC=$(sudo nitro-cli describe-enclaves)
echo "$DESC"

log "Ping"
set +e
PING_OUT=$(python3 ./vsock_client.py 16 5000 2>&1)
PING_RC=$?
set -e

echo "$PING_OUT"

if [[ $PING_RC -ne 0 ]]; then
  log "Ping failed (rc=$PING_RC). Collecting diagnostics..."

  log "Console (first 200 lines, debug-mode required):"
  # console is interactive; use timeout to capture boot/app logs without hanging.
  timeout 8 sudo nitro-cli console --enclave-id "$ENCLAVE_ID" 2>&1 | sed -n '1,200p' || true

  log "nitro_enclaves error logs (latest first):"
  sudo ls -1t /var/log/nitro_enclaves/err*.log 2>/dev/null | head -n 5 || true
  LATEST_ERR=$(sudo ls -1t /var/log/nitro_enclaves/err*.log 2>/dev/null | head -n 1 || true)
  if [[ -n "$LATEST_ERR" ]]; then
    log "Latest error log: $LATEST_ERR (first 200 lines)"
    sudo sed -n '1,200p' "$LATEST_ERR" || true
  fi

  log "describe-enclaves after failure:"
  sudo nitro-cli describe-enclaves || true
  exit 4
fi

# Capture enclave id and terminate
log "Terminating enclave: $ENCLAVE_ID"
sudo nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID" || true
sudo nitro-cli describe-enclaves

log "DONE"
EOS

chmod +x "$REMOTE_SH"

REPO_URL_DEFAULT="${A2_REPO_URL:-}"
# Note: A2_REPO_URL is optional now. We ship the needed sources as a tarball by default.

goto_destroy=${goto_destroy:-0}

CMD_ID=""
if [[ "$goto_destroy" != "1" ]]; then
  # SendCommand with script content
  log "Sending SSM command (this is the main on-host execution)"
  # SSM expects a JSON array of commands. We ship the remote script as base64 and execute it.
  REMOTE_B64=$(base64 -w0 "$REMOTE_SH")
  # Also ship the enclave artifact directory (so we don't depend on git URL structure/private repos)
  TAR_B64=$(tar -C "$REPO_ROOT/enclaves" -cz vsock-pingpong | base64 -w0)

  REMOTE_CMD=$(jq -n --arg repo "$REPO_URL_DEFAULT" --arg b64 "$REMOTE_B64" --arg tar "$TAR_B64" '
    [
      "set -euo pipefail",
      "export REPO_URL=\($repo)",
      "export A2_TAR_B64=\($tar)",
      "echo \($b64) | base64 -d > /tmp/ephemeralml_a2_host.sh",
      "chmod +x /tmp/ephemeralml_a2_host.sh",
      "/tmp/ephemeralml_a2_host.sh"
    ]
  ')

  CMD_JSON=$(aws ssm send-command \
    --region "$REGION" \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --comment "EphemeralML A2 vsock pingpong" \
    --parameters commands="$REMOTE_CMD" \
    --timeout-seconds $((TIMEBOX_MIN*60)) \
    --cloud-watch-output-config CloudWatchOutputEnabled=false \
    --output json)

  echo "$CMD_JSON" | tee "$LOG_DIR/ssm_send_command.json" >/dev/null
  CMD_ID=$(echo "$CMD_JSON" | jq -r '.Command.CommandId')
  log "SSM CommandId: $CMD_ID"

  # Poll for completion
  STATUS="Pending"
  for i in {1..120}; do
    INV=$(aws ssm get-command-invocation --region "$REGION" --command-id "$CMD_ID" --instance-id "$INSTANCE_ID" --output json || true)
    echo "$INV" > "$LOG_DIR/ssm_invocation_last.json"
    STATUS=$(echo "$INV" | jq -r '.Status // "Unknown"')
    log "SSM status: $STATUS"
    if [[ "$STATUS" == "Success" || "$STATUS" == "Failed" || "$STATUS" == "Cancelled" || "$STATUS" == "TimedOut" ]]; then
      break
    fi
    sleep 5
  done

  echo "$INV" | jq -r '.StandardOutputContent' | tee "$LOG_DIR/host_stdout.log" >/dev/null
  echo "$INV" | jq -r '.StandardErrorContent'  | tee "$LOG_DIR/host_stderr.log" >/dev/null

  log "SSM finished with status: $STATUS"
fi

log "Terraform destroy (always)"
(
  cd "$STACK_DIR"
  terraform destroy -auto-approve -input=false | tee "$LOG_DIR/destroy.txt"
)

log "Postflight: verify no instances with tag remain"
aws ec2 describe-instances \
  --region "$REGION" \
  --filters \
    'Name=tag:Name,Values=ephemeral-ml-hello-host' \
    'Name=instance-state-name,Values=pending,running,stopping,stopped' \
  --output json | tee "$LOG_DIR/post_instances.json" >/dev/null

log "Postflight: terraform state list"
(
  cd "$STACK_DIR"
  terraform state list || true
) | tee "$LOG_DIR/post_state.txt"

cat <<EOF

A2 run finished.
Logs saved under: $LOG_DIR

Please send these files to the assistant for analysis:
- $LOG_DIR/plan.txt
- $LOG_DIR/apply.txt
- $LOG_DIR/tf_output.json
- $LOG_DIR/host_stdout.log
- $LOG_DIR/host_stderr.log
- $LOG_DIR/destroy.txt
- $LOG_DIR/pre_instances.json and post_instances.json
EOF
