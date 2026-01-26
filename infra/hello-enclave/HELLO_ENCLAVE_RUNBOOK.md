# Nitro Enclave Hello World (AWS)

Goal: prove the *deployment loop* works: EC2 parent boots → allocator runs → EIF builds → enclave launches → vsock ping/pong.

## Recommended defaults
- Region: `us-east-1`
- OS/AMI: Amazon Linux 2
- Instance: `m6i.xlarge` (recommended) or `c6i.xlarge` (compute). Many `.large` sizes don't allow Enclaves; `c6a.*` is cheaper but **does not support** Nitro Enclaves.
- Connectivity: **SSM-only** (no SSH inbound)

## 1) Deploy with Terraform
```bash
cd projects/EphemeralML/infra/hello-enclave
terraform init
terraform apply
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

## Cleanup
```bash
terraform destroy
```

Notes:
- Enclaves have **no network**. Everything is via vsock.
- The allocator must reserve enough CPU/RAM for your `run-enclave` request.
