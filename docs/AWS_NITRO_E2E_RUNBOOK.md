# AWS Nitro Enclaves E2E Runbook

End-to-end inference on AWS Nitro Enclaves with PCR-pinned attestation.

## Prerequisites

- AWS CLI configured with permissions for EC2, including enclave-capable instances
- Key pair for SSH access (or create one: `aws ec2 create-key-pair --key-name <name>`)
- An m6i.xlarge (or larger) instance type (Nitro Enclaves capable)

## Architecture

```
EC2 Host (m6i.xlarge)                    Nitro Enclave (CID 16)
+--------------------------+             +---------------------------+
|  ephemeral-ml-host       | VSock 5000  |  ephemeral-ml-enclave     |
|  (production)            |------------>|  (production, NSM)        |
|                          | VSock 5001  |                           |
|  PCR pinning:            |------------>|  MiniLM-L6-v2 model       |
|  EPHEMERALML_EXPECTED_   | VSock 5002  |  bundled in EIF           |
|  PCR0/PCR1/PCR2          |<------------|                           |
+--------------------------+             +---------------------------+
```

One-way attestation: enclave attests to host via NSM COSE_Sign1. Host verifies
with NitroVerifier + PCR pinning. Host uses MockProvider (not in TEE).

## Step 1: Launch EC2 Instance

```bash
# Create key pair (skip if you have one)
aws ec2 create-key-pair --key-name ephemeralml-nitro-e2e \
  --query 'KeyMaterial' --output text > /tmp/ephemeralml-nitro-e2e.pem
chmod 600 /tmp/ephemeralml-nitro-e2e.pem

# Create security group with SSH
SG_ID=$(aws ec2 create-security-group \
  --group-name ephemeralml-nitro-e2e-sg \
  --description "EphemeralML Nitro E2E" \
  --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID --protocol tcp --port 22 --cidr 0.0.0.0/0

# Find latest AL2023 AMI
AMI_ID=$(aws ec2 describe-images --owners amazon \
  --filters "Name=name,Values=al2023-ami-2023*-x86_64" "Name=state,Values=available" \
  --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' --output text)

# Launch with Nitro Enclaves enabled, 30GB disk
INSTANCE_ID=$(aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type m6i.xlarge \
  --key-name ephemeralml-nitro-e2e \
  --security-group-ids $SG_ID \
  --enclave-options Enabled=true \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":30,"VolumeType":"gp3"}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=ephemeralml-nitro-e2e}]' \
  --query 'Instances[0].InstanceId' --output text)

echo "Instance: $INSTANCE_ID"
aws ec2 wait instance-running --instance-ids $INSTANCE_ID
IP=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
echo "IP: $IP"
```

## Step 2: Install Dependencies (on EC2)

```bash
SSH="ssh -o StrictHostKeyChecking=no -i /tmp/ephemeralml-nitro-e2e.pem ec2-user@$IP"

# Install system packages
$SSH "sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel \
  docker git gcc gcc-c++ cmake openssl-devel perl-FindBin perl-IPC-Cmd pkg-config"

# Start services and add user to groups
$SSH "sudo systemctl enable --now docker && \
  sudo systemctl enable --now nitro-enclaves-allocator && \
  sudo usermod -aG docker ec2-user && \
  sudo usermod -aG ne ec2-user"

# Configure allocator (4096 MiB, 2 CPUs for enclave)
$SSH "sudo bash -c 'cat > /etc/nitro_enclaves/allocator.yaml << EOF
---
memory_mib: 4096
cpu_count: 2
EOF
systemctl restart nitro-enclaves-allocator'"

# Install Rust
$SSH "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
```

## Step 3: Transfer Repository

```bash
rsync -az \
  --exclude 'target/' --exclude '.git/' --exclude 'test_assets/llama3/' \
  --exclude 'infra/' --exclude 'benchmark_results*/' --exclude 'evidence/' \
  -e "ssh -o StrictHostKeyChecking=no -i /tmp/ephemeralml-nitro-e2e.pem" \
  /path/to/EphemeralML-cyntrisec/ \
  ec2-user@$IP:~/EphemeralML-cyntrisec/
```

## Step 4: Build Production Binaries

```bash
$SSH "source ~/.cargo/env && cd ~/EphemeralML-cyntrisec && \
  cargo build --release --no-default-features --features production -p ephemeral-ml-enclave && \
  cargo build --release --no-default-features --features production -p ephemeral-ml-host"
```

Build time: ~5 min for first build, ~30s for incremental rebuilds.

## Step 5: Build Docker Image and EIF

```bash
# Stage binary for Docker (target/ is in .dockerignore)
$SSH "cd ~/EphemeralML-cyntrisec && mkdir -p docker-stage && \
  cp target/release/ephemeral-ml-enclave docker-stage/"

# Create production Dockerfile
$SSH "cat > ~/EphemeralML-cyntrisec/Dockerfile.nitro-e2e << 'DEOF'
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY docker-stage/ephemeral-ml-enclave /app/enclave_app
COPY test_assets/minilm/tokenizer.json /app/model/tokenizer.json
COPY test_assets/minilm/config.json /app/model/config.json
COPY test_assets/minilm/model.safetensors /app/model/model.safetensors
ENTRYPOINT [\"/app/enclave_app\", \"--model-dir\", \"/app/model\", \"--control-addr\", \"5000\", \"--data-in-addr\", \"5001\", \"--data-out-target\", \"5002\"]
DEOF"

# Build Docker image
$SSH "cd ~/EphemeralML-cyntrisec && docker build -f Dockerfile.nitro-e2e -t ephemeral-ml-enclave:latest ."

# Build EIF and extract PCR measurements
$SSH "nitro-cli build-enclave --docker-uri ephemeral-ml-enclave:latest \
  --output-file /tmp/ephemeral-ml-enclave.eif"
```

The build output will show PCR0/1/2 measurements. Save these for pinning.

## Step 6: Launch Enclave

```bash
# Terminate any existing enclaves
$SSH "nitro-cli terminate-enclave --all 2>/dev/null || true"

# Launch
$SSH "nitro-cli run-enclave \
  --eif-path /tmp/ephemeral-ml-enclave.eif \
  --memory 4096 \
  --cpu-count 2 \
  --enclave-cid 16"

# Wait for initialization (model loading + VSock bind)
sleep 15

# Verify running
$SSH "nitro-cli describe-enclaves"
```

## Step 7: Run Inference with PCR Pinning

**Critical:** Set `EPHEMERALML_EXPECTED_PCR0/1/2` from the EIF build output.
Running without these is a security violation.

```bash
$SSH "
export EPHEMERALML_EXPECTED_PCR0='<PCR0 from step 5>'
export EPHEMERALML_EXPECTED_PCR1='<PCR1 from step 5>'
export EPHEMERALML_EXPECTED_PCR2='<PCR2 from step 5>'

source ~/.cargo/env
cd ~/EphemeralML-cyntrisec

RUST_LOG=info ./target/release/ephemeral-ml-host \
  --enclave-cid 16 \
  --control-port 5000 \
  --data-in-port 5001 \
  --data-out-port 5002 \
  --text 'Confidential AI inference with cryptographic proof'
"
```

## Step 8: Cleanup

```bash
# Terminate enclave
$SSH "nitro-cli terminate-enclave --all"

# Terminate EC2 instance
aws ec2 terminate-instances --instance-ids $INSTANCE_ID

# Delete security group (after instance terminates)
aws ec2 wait instance-terminated --instance-ids $INSTANCE_ID
aws ec2 delete-security-group --group-id $SG_ID

# Delete key pair
aws ec2 delete-key-pair --key-name ephemeralml-nitro-e2e
rm /tmp/ephemeralml-nitro-e2e.pem
```

## Expected Output

Successful run shows:
1. Pipeline initialized with VSock connections on ports 5000/5001/5002
2. Attestation verification succeeded (with document hash)
3. Health check passed
4. Inference complete (~78ms enclave execution for MiniLM-L6-v2; ~118ms host E2E in current evidence)
5. Embedding output (384 dimensions, L2 norm ~7.3)
6. Signed attestation receipt with PCR measurements
7. `receipt.cbor` and `attestation.cbor` persisted for offline verification
8. Offline legacy + AIR v1 verification passes, and the trust-center upload path accepts the AWS AIR receipt

## Evidence Artifacts

| Artifact | Description |
|----------|-------------|
| EIF build JSON | PCR0/1/2 measurements from `nitro-cli build-enclave` |
| `describe-enclaves` | Runtime enclave state, CID, memory, CPU allocation |
| Host output log | Full pipeline trace: handshake, health check, inference, receipt |
| `receipt.json` | Parsed attestation receipt saved by host (`--receipt-output`) |
| `receipt.raw` | Raw `__receipt__` tensor bytes (wire format) saved by host (`--receipt-output-raw`) |
| `receipt.cbor` | AIR v1 COSE_Sign1 receipt saved by host (`--receipt-output-air-v1`) |
| `attestation.cbor` | Boot attestation sidecar saved by host (`--attestation-output`) |
| Receipt (in log) | Human-readable receipt summary printed by host binary (receipt ID, hashes, PCRs, signature) |

## Security Notes

- **PCR pinning is mandatory.** The host MUST set `EPHEMERALML_EXPECTED_PCR0/1/2`.
  Running without pinning means any enclave image would be accepted.
- **Debug mode zeros PCRs.** Never use `--debug-mode` in production.
- **One-way attestation.** The enclave attests to the host; the host is trusted
  (same EC2 instance, not in a TEE). For multi-enclave pipelines, use
  NitroVerifier between enclaves.
- **Model is bundled in EIF.** The model weights are measured in PCR2 (application).
  Changing the model changes the PCR and breaks pinning (by design).

## Cost

- m6i.xlarge: ~$0.192/hr (us-east-1, on-demand)
- 30GB gp3 EBS: ~$2.40/month
- Total for a 1-hour test session: ~$0.20

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `c++: not found` during build | `sudo dnf install -y gcc-c++` |
| `COPY failed` in Docker build | Binary is in `target/` which is in `.dockerignore`. Copy to `docker-stage/` first. |
| `PublicKeyMismatch` in handshake | Attestation bridge must pass HPKE key to NSM `public_key` field. See commit fixing `AttestationBridge.attest()`. |
| Enclave exits immediately | Check memory (need 4096 MiB for 87MB model). Use `--debug-mode` + `nitro-cli console` to see logs. |
| `VcpuLimitExceeded` | Terminate (not stop) other instances. Stopped instances still hold vCPU quota. |
| Zombie enclave (E39) | `aws ec2 stop-instances --force` then `start-instances`. IP changes. |
