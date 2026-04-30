# AWS-Native Nitro PoC Runbook

This runbook covers the repeatable AWS-native PoC path:

1. AWS KMS releases model material only to a Nitro Enclave measurement accepted by policy.
2. The enclave fetches encrypted model weights from S3 through the host-side VSock proxy.
3. The enclave emits an AIR receipt for a synthetic inference.
4. The verifier checks the AIR receipt offline against the Nitro attestation sidecar.
5. A redacted benchmark packet is generated for customer or reviewer sharing.

This is the AWS CPU Nitro path. It does not prove GPU or accelerator attestation.

## Scope

The runner in `scripts/aws/run_native_poc.sh` operates an existing
`infra/aws-native-poc/cyntrisec-aws-poc.yaml` stack. It intentionally does not
create infrastructure or build a fresh EIF. The stack must already contain:

- A Nitro-enabled EC2 host managed by SSM.
- The host binaries under `/opt/cyntrisec/bin/`.
- The approved EIF under `/opt/cyntrisec/eif/`.
- KMS policy pinned to the approved `EnclaveImageSha384`.
- The packaged encrypted model object in the stack-owned S3 bucket.

## Bootstrap Loop

The high-confidence setup has a real bootstrap loop:

1. Create or update the stack to get model/evidence KMS keys and buckets.
2. Package the model with `scripts/aws/package_model.sh`.
3. Build the AWS PoC EIF that contains the model manifest and wrapped DEK.
4. Extract the final EIF SHA384/PCR0 from `nitro-cli build-enclave`.
5. Update the stack parameter `EnclaveImageSha384` so KMS release is pinned to the final EIF.
6. Run the repeatable PoC runner.

Do not skip step 5. Running with an unpinned or stale EIF hash weakens the proof
from "KMS released to this measured enclave" to "the code happened to run."

## Repeatable Run

From the repo root:

```bash
scripts/aws/run_native_poc.sh \
  --stack-name <stack-name> \
  --region us-east-1 \
  --repetitions 3 \
  --expected-model-hash <sha256-model-artifact-set>
```

Default behavior:

- Builds `target/release/ephemeralml-smoke-test`.
- Starts the EC2 host if it is stopped.
- Waits for SSM to become online.
- Uploads the smoke-test binary to a temporary private S3 object.
- Installs it on the host under `/opt/cyntrisec/bin/`.
- Runs the five-stage smoke test one or more times.
- Deletes the temporary binary object.
- Stops the host only if this script started it.

Use `--dry-run` to resolve the stack and print the execution plan without AWS
mutations. Use `--no-upload-binary` when the host already has the exact
smoke-test binary you want to test. Use `--stop-after-run` when you want the
host stopped even if it was already running before the script started.

## Benchmark Summary

For one packet:

```bash
scripts/aws/summarize_benchmarks.py artifacts/benchmarks/aws-native-poc-20260430
```

For multiple downloaded bundles:

```bash
scripts/aws/summarize_benchmarks.py /tmp/cyntrisec-bundles/
```

The summary reports cold-start and warm-path numbers separately:

- `Enclave launch` is mostly cold-start platform cost.
- `Warm path without enclave launch` is `total_smoke_test_ms - enclave_launch_ms`.
- `KMS decrypt + receipt verify` is the cryptographic proof path overhead.

The first clean redacted run on 2026-04-30 measured:

- KMS model decrypt: `35 ms`
- Synthetic inference: `67 ms`
- AIR receipt verify: `38 ms`
- S3 upload: `517 ms`
- Enclave launch: `19228 ms`
- Total smoke path: `21900 ms`

These are PoC measurements, not a production SLO. For customer claims, report
cold-start and warm-enclave paths separately.

## Redacted Evidence Packet

Generate a customer-shareable packet from a private evidence bundle:

```bash
scripts/aws/redact_evidence_bundle.py \
  /tmp/private-smoke-test-bundle \
  artifacts/benchmarks/aws-native-poc-YYYYMMDD \
  --force
```

The redacted packet includes:

- `README.md`
- `benchmark.redacted.json`
- `negative-tests.redacted.json`
- `SHA256SUMS` when present

The redacted packet excludes:

- Raw `attestation.cbor`
- Raw `receipt.cbor`
- `kms-release.json`
- Host logs
- AWS request IDs
- Raw KMS response material
- Exact AWS account, host, bucket, AMI, and instance identifiers

## Customer-Safe Claim

Use this wording:

> This AWS-native PoC demonstrates per-inference AIR receipt generation inside
> an AWS Nitro Enclave, with model key release gated by AWS KMS attestation
> policy and offline receipt verification. It proves the CPU Nitro path for a
> synthetic inference. GPU attestation is separate and not included in this
> packet.

Avoid absolute claims such as "no trust in AWS required" or "cryptographic
deletion proof." The accurate claim is reduced cloud-operator trust through
hardware attestation, policy-gated key release, and signed execution receipts.
