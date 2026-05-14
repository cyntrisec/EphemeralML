# Documentation Map

This repository serves multiple audiences: developers integrating the product, reviewers validating the security model, and standards readers evaluating AIR v1.

## Start Here

- [`../README.md`](../README.md) — top-level product and diligence summary
- [`pilot-deployment-runbook.md`](pilot-deployment-runbook.md) — canonical AWS BYOC pilot deployment and smoke-test path
- [`../examples/sample-receipt/README.md`](../examples/sample-receipt/README.md) — verify a sample AIR receipt without deploying AWS
- [`../QUICKSTART.md`](../QUICKSTART.md) — local developer proof paths and build commands
- [`design.md`](design.md) — architecture and threat model
- [`benchmarks.md`](benchmarks.md) — benchmark methodology and measured results
- [`BENCHMARK_SCHEMA.md`](BENCHMARK_SCHEMA.md) — shared JSON shape for reproducible benchmark outputs
- [`ENTERPRISE_BENCHMARK_REPORT.md`](ENTERPRISE_BENCHMARK_REPORT.md) — current buyer-facing AIR receipt cost report from the GCP Confidential Space warm-path benchmark

## Product and Deployment

- [`build-matrix.md`](build-matrix.md) — feature flags, deployment modes, and build commands
- [`pilot-deployment-runbook.md`](pilot-deployment-runbook.md) — current Cluster A AWS BYOC pilot runbook
- [`AWS_NATIVE_POC_RUNBOOK.md`](AWS_NATIVE_POC_RUNBOOK.md) — historical AWS-native Nitro PoC, benchmark, and redacted evidence workflow
- [`AWS_NITRO_E2E_RUNBOOK.md`](AWS_NITRO_E2E_RUNBOOK.md) — historical hand-built Nitro E2E runbook
- [`AWS_NITRO_E2E_REPORT.md`](AWS_NITRO_E2E_REPORT.md) — historical Nitro E2E report
- [`verifier-api.md`](verifier-api.md) — verifier service surface
- [`cli-ux.md`](cli-ux.md) — operator and developer CLI ergonomics
- [`REPO_MAINTENANCE_SCOPE.md`](REPO_MAINTENANCE_SCOPE.md) — active vs frozen areas and local disk hygiene
- [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — operational debugging notes

## Security and Trust

- [`AIR_PROOF_BOUNDARY.md`](AIR_PROOF_BOUNDARY.md) — customer-facing explanation of what AIR proves and what remains outside the receipt boundary
- [`SECURITY_MODEL.md`](SECURITY_MODEL.md) — security assumptions and trust boundaries
- [`security-demo.md`](security-demo.md) — host-blindness walkthrough
- [`OPEN_SOURCE_BOUNDARY.md`](OPEN_SOURCE_BOUNDARY.md) — what stays public vs private
- [`security/`](security/) — security-specific supporting docs

## Research and Publication

- [`BENCHMARK_SPEC.md`](BENCHMARK_SPEC.md) — benchmark spec and literature-backed methodology
- [`publication/`](publication/) — publication-facing supporting materials
- [`releases/`](releases/) — release-specific notes

## Standards

- [`../spec/v1/README.md`](../spec/v1/README.md) — AIR v1 entrypoint
