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

# Fetch repo (assumes public git URL must be provided via SSM env var REPO_URL)
if [[ -z "${REPO_URL:-}" ]]; then
  log "ERROR: REPO_URL not set"
  exit 3
fi

WORK=/home/ec2-user/clawd
if [[ ! -d "$WORK" ]]; then
  log "Cloning repo to $WORK"
  git clone "$REPO_URL" "$WORK"
else
  log "Repo exists; updating"
  (cd "$WORK" && git pull --ff-only) || true
fi

cd "$WORK/projects/EphemeralML/enclaves/vsock-pingpong"

log "Docker build"
sudo docker build -t ephemeralml/vsock-pingpong:latest .

log "Build EIF"
sudo nitro-cli build-enclave --docker-uri ephemeralml/vsock-pingpong:latest --output-file vsock-pingpong.eif
ls -lh vsock-pingpong.eif

log "Run enclave"
sudo nitro-cli run-enclave --eif-path vsock-pingpong.eif --cpu-count 2 --memory 1024 --enclave-cid 16 --debug-mode
sleep 2
sudo nitro-cli describe-enclaves

log "Ping"
python3 ./vsock_client.py 16 5000

# Capture enclave id and terminate
ENCLAVE_ID=$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
log "Terminating enclave: $ENCLAVE_ID"
sudo nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID"
sudo nitro-cli describe-enclaves

log "DONE"
EOS

chmod +x "$REMOTE_SH"

REPO_URL_DEFAULT="${A2_REPO_URL:-}"
if [[ -z "$REPO_URL_DEFAULT" ]]; then
  cat <<EOF

You must provide a git clone URL reachable from the instance (HTTPS).
Example:
  export A2_REPO_URL=https://github.com/tsyrulb/EphemeralML.git
Then re-run this script.
EOF
  log "Missing A2_REPO_URL";
  goto_destroy=1
fi

goto_destroy=${goto_destroy:-0}

CMD_ID=""
if [[ "$goto_destroy" != "1" ]]; then
  # SendCommand with script content
  log "Sending SSM command (this is the main on-host execution)"
  CMD_JSON=$(aws ssm send-command \
    --region "$REGION" \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --comment "EphemeralML A2 vsock pingpong" \
    --parameters commands="$(sed 's/"/\\"/g' "$REMOTE_SH" | awk '{print}' ORS='\n')" \
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
