# Nitro Enclave Hello World (AWS)

Goal: prove the *deployment loop* works: EC2 parent boots → allocator runs → EIF builds → enclave launches → vsock ping/pong.

For Milestone A2 (our own minimal vsock ping/pong), use: `VSOCK_PINGPONG_RUNBOOK.md`.

## Recommended defaults
- Region: `us-east-1`
- OS/AMI: Amazon Linux 2
- Instance: `m6i.xlarge` (recommended) or `c6i.xlarge` (compute). Many `.large` sizes don't allow Enclaves; `c6a.*` is cheaper but **does not support** Nitro Enclaves.
- Connectivity: **SSM-only** (no SSH inbound)

## 1) Deploy with Terraform
If you hit an AZ availability error (common), pin a known-good AZ like `us-east-1a` or `us-east-1b`.

```bash
cd projects/EphemeralML/infra/hello-enclave
terraform init
terraform apply -var 'availability_zone=us-east-1a' -var 'instance_type=m6i.xlarge'
```

Outputs include an `aws ssm start-session --target i-...` command.

## 2) Connect via SSM
```bash
aws ssm start-session --target <instance-id>
```

## 3) Sanity check on the parent
```bash
sudo nitro-cli --version
sudo systemctl status nitro-enclaves-allocator.service --no-pager
sudo nitro-cli describe-enclaves
```

## 4) Build an EIF
Fastest path is to use AWS samples (vsock ping/pong) and build a docker image, then:
```bash
sudo nitro-cli build-enclave --docker-uri <image:tag> --output-file hello.eif
```

## 5) Run the enclave
```bash
sudo nitro-cli run-enclave --eif-path hello.eif --cpu-count 2 --memory 1024 --enclave-cid 16
sudo nitro-cli describe-enclaves
sudo nitro-cli console --enclave-id <id>
```

## 6) Test vsock
On the parent, connect to CID `16` / port `5000` (whatever your enclave server uses):
```bash
sudo yum install -y socat
socat - VSOCK-CONNECT:16:5000
```

## Troubleshooting

### "Unsupported" instance type / AZ capacity errors (common)
**Symptom:** Terraform or EC2 returns an error implying the chosen instance type is not supported/available in the selected subnet/AZ.

**Common cause:** the subnet lands in an AZ where the chosen instance type is not available (e.g. `us-east-1e`).

**Fix:**
- **Pin a known-good AZ** explicitly (example: `us-east-1a` or `us-east-1b`).
- Use an instance type that **supports Nitro Enclaves**.
  - Confirmed **NOT working**: `c6a.large`, `m6i.large`.
  - Confirmed **working**: `m6i.xlarge`.

Example:
```bash
terraform apply -var 'availability_zone=us-east-1a' -var 'instance_type=m6i.xlarge'
```

### `nitro-cli build-enclave` fails with `E19`
**Symptom:** `nitro-cli build-enclave ...` fails with error `E19`.

**Root cause seen in validation:** missing blob directory (`/usr/share/nitro_enclaves/blobs`).

**Fix (Amazon Linux 2):**
```bash
# AL2: nitro-cli is installed via amazon-linux-extras (not yum direct)
sudo amazon-linux-extras enable aws-nitro-enclaves-cli
sudo yum clean metadata
sudo yum install -y aws-nitro-enclaves-cli

# Ensure blobs exist
sudo yum install -y aws-nitro-enclaves-cli-devel

# If you still see E19, reinstall
sudo yum reinstall -y aws-nitro-enclaves-cli

# Sanity check
ls -la /usr/share/nitro_enclaves/blobs
```

### `nitro-cli console` fails with `E44`
**Symptom:** `sudo nitro-cli console --enclave-id <id>` fails with `E44`.

**Root cause:** console access requires the enclave to be started in debug mode.

**Fix:** re-run the enclave with `--debug-mode`:
```bash
sudo nitro-cli run-enclave --eif-path hello.eif --cpu-count 2 --memory 1024 --enclave-cid 16 --debug-mode
sudo nitro-cli console --enclave-id <id>
```

### SSM connect issues from laptop
**Symptom:** `aws ssm start-session ...` fails locally due to missing `session-manager-plugin`.

**Fix:** install the Session Manager Plugin on your laptop.

If your package manager is failing due to third-party repositories, disable the failing repo entry and retry the plugin install.

## Troubleshooting (Known gotchas)

### Instance type errors
- `InvalidParameterValue: You cannot enable Nitro Enclaves for "c6a.large"` → **c6a.* does not support Enclaves**.
- `... for "m6i.large"` → many `.large` sizes do not allow Enclaves; use **xlarge+**.

### Availability Zone errors
- `Unsupported: ... not supported in your requested Availability Zone (us-east-1e)` → pin AZ:
  - `terraform apply -var 'availability_zone=us-east-1a' ...`

### SSM issues
- `SessionManagerPlugin is not found` (on laptop) → install **session-manager-plugin**.

### nitro-cli install on AL2
- `No package aws-nitro-enclaves-cli available` → install via **amazon-linux-extras**:
  - `sudo amazon-linux-extras install -y aws-nitro-enclaves-cli`

### build-enclave errors
- **E19** `Could not open kernel command line file` / missing `/usr/share/nitro_enclaves/blobs`:
  - `sudo yum install -y aws-nitro-enclaves-cli-devel`
  - `sudo yum reinstall -y aws-nitro-enclaves-cli`

### Console errors
- **E44** on `nitro-cli console` → enclave must be started with `--debug-mode`.

## Cleanup
```bash
terraform destroy
```

Notes:
- Enclaves have **no network**. Everything is via vsock.
- The allocator must reserve enough CPU/RAM for your `run-enclave` request.
