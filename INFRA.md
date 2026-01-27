# Infrastructure Notes (EphemeralML)

## Nitro Enclaves debug notes
- KMS + Nitro Enclaves postmortem / fixes: `infra/hello-enclave/KMS_DEBUG_NOTES_2026-01-27.md`

## Nitro Enclaves: Hello-World Deployment Loop

A minimal AWS Nitro Enclave deployment loop:
- Terraform deploy (VPC/subnet/IGW/SG + EC2 with `enclave_options.enabled = true`)
- Connect via SSM Session Manager
- Install Nitro Enclaves tooling on AL2
- Build EIF from a local Docker image (`nitro-cli build-enclave`)
- Run enclave (`nitro-cli run-enclave`)
- Observe output via console in debug mode (`nitro-cli console --debug-mode`)
- Cleanup with `terraform destroy`

### Working configuration
- Region: `us-east-1`
- AZ: **pin** (e.g. `us-east-1a`) to avoid type not supported in `us-east-1e`
- Instance type: `m6i.xlarge` (many `.large` sizes fail Enclaves enablement)
- OS/AMI: Amazon Linux 2
- Access model: SSM-only (no inbound SG)

### Common pitfalls
- `c6a.large` does **not** support Nitro Enclaves.
- `m6i.large` does **not** support Nitro Enclaves (xlarge works).
- `nitro-cli` on AL2 is installed via `amazon-linux-extras install aws-nitro-enclaves-cli`.
- `nitro-cli build-enclave` requires `/usr/share/nitro_enclaves/blobs` (fixed via `aws-nitro-enclaves-cli-devel` + reinstall).
- `nitro-cli console` requires enclave started with `--debug-mode`.
- Local workstation needs `session-manager-plugin` to use `aws ssm start-session`.

## Terraform stack
See: `projects/EphemeralML/infra/hello-enclave`.
