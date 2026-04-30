# AWS-Native Nitro PoC Benchmark Packet

Date: 2026-04-30

This packet is a redacted summary of the first clean benchmark rerun for the
Cyntrisec AWS-native PoC. Raw attestation documents, raw receipts, KMS release
JSON, host logs, cloud account identifiers, and exact resource identifiers are
intentionally not included here. The full evidence bundle remains in the
private PoC S3 bucket.

## Evidence Location

- Stack: AWS-native PoC stack in a private AWS account
- Region: `us-east-1`
- Evidence prefix: private S3 evidence bucket, `smoke-tests/20260430T175711Z/`
- Local bundle path on host: redacted
- Receipt SHA-256: `473355582743d03d61846fc13aa7670a91653b2d1d59d688317e9e5b1d52cfca`

## Platform

- Instance type: `m7i.xlarge`
- Availability zone: `us-east-1a`
- Kernel: `6.1.166-197.305.amzn2023.x86_64`
- Nitro CLI: `Nitro CLI 1.4.4`
- Enclave memory: `4096 MiB`
- Enclave vCPUs: `2`
- Enclave CID: `16`

The previous stopped `m6i.xlarge` host could not be restarted due EC2
`InsufficientInstanceCapacity`, so the CloudFormation stack parameter was
updated to `m7i.xlarge`. Nitro Enclaves support remained enabled.

## Cryptographic Inputs

- EIF PCR0: `184b2a72e7bbe6d84dfddc586d3ce7ecc49085c044f31594e67042b6a5ff4e010f7a2052e430190b6bb54762059c4b21`
- Model artifact hash: `53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db`
- Measurement type: `nitro-pcr`
- Security mode: `production`

## Result

Status: PASS

The run proved the AWS-native CPU Nitro trust path:

- AWS KMS released model material only to a RecipientInfo request bound to the accepted Nitro EIF measurement.
- Encrypted model weights were fetched from S3 through the host-side VSock proxy.
- The enclave loaded the model and performed the synthetic inference.
- The enclave emitted an AIR receipt.
- Offline AIR verification passed against the supplied Nitro attestation sidecar.
- Negative checks rejected tampered receipt, wrong attestation sidecar, and wrong model hash.
- The evidence bundle was uploaded to the stack-owned S3 bucket with SSE-KMS.

## Timings

- Doctor total: `1383 ms`
- EIF check: `898 ms`
- KMS model decrypt: `35 ms`
- Enclave launch: `19228 ms`
- Synthetic inference: `67 ms`
- Receipt verification: `38 ms`
- S3 upload: `517 ms`
- Total smoke path: `21900 ms`

## Included Files

- `benchmark.redacted.json`: benchmark environment, timings, evidence sizes, and negative-test summary.
- `negative-tests.redacted.json`: verifier outputs for expected-reject checks.
- `SHA256SUMS`: hashes from the full uploaded evidence bundle.

## Exclusions

This packet does not include:

- Raw `attestation.cbor`
- Raw `receipt.cbor`
- `kms-release.json`
- Host logs
- AWS request IDs or raw KMS response material

Those remain in the private evidence bundle and should be shared only under an
explicit review context.

## Cleanup State

After the run:

- Nitro enclave cleanup command returned no running enclaves.
- `kms_proxy_host` was killed if present.
- Temporary SSH ingress from the Codex IP was revoked.
- The EC2 host was stopped and had no public IP.
- Temporary S3 object `_codex/ephemeralml-smoke-test-20260430` was deleted.
