# Milestone A2: Minimal VSOCK ping/pong (Nitro Enclaves)

Goal: run **our own** enclave program that listens on **AF_VSOCK port 5000** and replies `pong` to `ping`, then verify from the parent instance.

Repo code for this milestone lives at:
- `projects/EphemeralML/enclaves/vsock-pingpong/`

## 0) Cost-safety guardrails (pre-flight)

Run these **before** any `terraform apply` to ensure you’re not about to leak cost from a previous run.

From your laptop:

```bash
cd projects/EphemeralML/infra/hello-enclave

# If state exists locally, see what Terraform thinks exists
terraform state list || true

# Check if the host instance (by Name tag) is running/stopped (both cost money, running costs more)
aws ec2 describe-instances \
  --region us-east-1 \
  --filters \
    'Name=tag:Name,Values=ephemeral-ml-hello-host' \
    'Name=instance-state-name,Values=pending,running,stopping,stopped' \
  --query 'Reservations[].Instances[].{InstanceId:InstanceId,State:State.Name,Type:InstanceType,AZ:Placement.AvailabilityZone,PublicIp:PublicIpAddress}' \
  --output table
```

If anything shows up above and you didn’t mean to keep it, **destroy first** (see cleanup section).

## 1) Deploy the parent with Terraform

(Manual step; run `apply` only when you are ready to incur small, timeboxed AWS cost.)

Plan (safe):
```bash
cd projects/EphemeralML/infra/hello-enclave
terraform init
terraform plan -var 'availability_zone=us-east-1a' -var 'instance_type=m6i.xlarge'
```

Apply (only after confirmation):
```bash
terraform apply -var 'availability_zone=us-east-1a' -var 'instance_type=m6i.xlarge'
```

Grab the output `ssm_start_session` and connect:
```bash
aws ssm start-session --target i-xxxxxxxxxxxxxxxxx
```

## 2) On the parent: sanity checks

```bash
sudo nitro-cli --version || true
sudo systemctl status nitro-enclaves-allocator.service --no-pager || true
sudo nitro-cli describe-enclaves
```

If `nitro-cli` is missing on AL2, install via extras (known gotcha):
```bash
sudo amazon-linux-extras enable aws-nitro-enclaves-cli
sudo yum clean metadata
sudo yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
```

## 3) On the parent: build the enclave EIF from our Rust code

### Option A (recommended): build docker image on the parent, then build EIF

```bash
# On the parent instance
sudo yum install -y git

# Pull repo content (or copy this directory via scp/rsync if you prefer)
cd /home/ec2-user
git clone <YOUR_REPO_URL> clawd
cd clawd/projects/EphemeralML/enclaves/vsock-pingpong

# Build the docker image used by nitro-cli
sudo docker build -t ephemeralml/vsock-pingpong:latest .

# Build EIF
sudo nitro-cli build-enclave \
  --docker-uri ephemeralml/vsock-pingpong:latest \
  --output-file vsock-pingpong.eif
```

## 4) Run the enclave

Start enclave with a fixed CID (`16`) to make the client trivial:

```bash
sudo nitro-cli run-enclave \
  --eif-path vsock-pingpong.eif \
  --cpu-count 2 \
  --memory 1024 \
  --enclave-cid 16 \
  --debug-mode

sudo nitro-cli describe-enclaves
```

(Optional) view enclave stderr:
```bash
sudo nitro-cli console --enclave-id <enclave-id>
```

## 5) Ping from the parent (VSOCK client)

Use the minimal python client from the repo:

```bash
# On the parent instance
cd /home/ec2-user/clawd/projects/EphemeralML/enclaves/vsock-pingpong
python3 ./vsock_client.py 16 5000
# Expected output: pong
```

If python3 is missing:
```bash
sudo yum install -y python3
```

## 6) Cleanup (post-run guardrails)

### On the parent: terminate enclave
```bash
sudo nitro-cli terminate-enclave --enclave-id <enclave-id>
```

### From your laptop: destroy infra (requires conscious confirmation)

```bash
cd projects/EphemeralML/infra/hello-enclave
terraform destroy
```

### Verify nothing is left running

```bash
aws ec2 describe-instances \
  --region us-east-1 \
  --filters \
    'Name=tag:Name,Values=ephemeral-ml-hello-host' \
    'Name=instance-state-name,Values=pending,running,stopping,stopped' \
  --query 'Reservations[].Instances[].{InstanceId:InstanceId,State:State.Name}' \
  --output table
```

## Notes
- Enclaves have **no network**; all communication here is **vsock**.
- If `nitro-cli console` fails with `E44`, you must run the enclave with `--debug-mode`.
- If `build-enclave` fails with `E19` on AL2, ensure `aws-nitro-enclaves-cli-devel` is installed (blobs path).
