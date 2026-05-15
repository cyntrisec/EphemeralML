# Cyntrisec Pilot Deployment Runbook

This is the canonical customer-facing AWS BYOC runbook for the Cluster A
`v1.1.2` template distribution.

This runbook validates the AWS worker stack after the Cluster A release
artifacts have been published and the signed worker template has been uploaded
to the release S3 bucket. CloudFormation launches from the S3 regional URL, not
from the branded `templates.cyntrisec.com` mirror.

## Prerequisites

- AWS CLI authenticated into the pilot account.
- A released tag such as `v1.1`.
- `enclave-measurements.json` from the Cluster A image release workflow.
- `worker-template.json` from the same release workflow, containing the S3
  template URL and optional S3 `versionId`.
- `cosign` installed locally for template verification.
- Docker installed locally for the customer-side proxy.
- `cyntrisec-verify` available locally.

## Verify Template Before Deploy

Download the versioned worker template and verify it before opening the
CloudFormation launch URL. This validates the template itself, not only the OCI
artifacts that the template later pulls during instance boot.

```bash
TEMPLATE_BASE=https://s3.us-east-1.amazonaws.com/cyntrisec-public-templates-us-east-1/aws/v1.1.2
curl -fsSLO "$TEMPLATE_BASE/worker.yaml"
curl -fsSLO "$TEMPLATE_BASE/worker.yaml.sha256"
curl -fsSLO "$TEMPLATE_BASE/worker.yaml.cosign.bundle"

sha256sum -c worker.yaml.sha256
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/cyntrisec/EphemeralML/.github/workflows/cluster-a-image-release.yml@refs/tags/cluster-a-v[0-9]+(\.[0-9]+)*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle worker.yaml.cosign.bundle \
  worker.yaml
aws cloudformation validate-template --template-body file://worker.yaml
```

## Deploy

1. Open the CloudFormation launch URL produced by the website's Deploy to AWS
   button.
2. Confirm the URL includes:
   - `templateURL=https://s3.us-east-1.amazonaws.com/cyntrisec-public-templates-us-east-1/aws/v1.1.2/worker.yaml`
   - `param_ReleaseTag=v1.1` or the template default `ReleaseTag=v1.1`
   - `param_EnclaveImageSha384=<from enclave-measurements.json>`
   - `param_EnclavePcr1Sha384=<from enclave-measurements.json>`
   - `param_EnclavePcr2Sha384=<from enclave-measurements.json>`

If `worker-template.json` includes a non-null `s3_url_with_version`, prefer that
exact URL for `templateURL`. It pins the S3 object version in addition to the
immutable release path. When putting that URL into a CloudFormation Quick Create
link, URL-encode the nested `?versionId=...` query string inside `templateURL`.
3. Fill the visible parameters:
   - `AccessCIDR`
   - `ModelURI`
   - `EvidenceBucketName`
   - `RetentionDays`
   - `InstanceType`

`AccessCIDR` defaults to `192.0.2.0/32`, a non-routable TEST-NET-1 address,
so the worker NLB is closed until the operator explicitly opens it. Set it to
the customer proxy's egress IP, VPN CIDR, or office CIDR. Do not use
`0.0.0.0/0` for a pilot unless the account owner has explicitly accepted the
resource-abuse risk.

4. Create the stack and wait for `CREATE_COMPLETE`.

Security-sensitive operators can launch without the website redirect by using
the verified local template:

```bash
aws cloudformation create-stack \
  --stack-name cyntrisec-worker-v11 \
  --template-body file://worker.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
    ParameterKey=AccessCIDR,ParameterValue=<customer-egress-cidr> \
    ParameterKey=ModelURI,ParameterValue=s3://<model-bucket>/<model-prefix> \
    ParameterKey=EvidenceBucketName,ParameterValue=<unique-evidence-bucket> \
    ParameterKey=RetentionDays,ParameterValue=90 \
    ParameterKey=EnclaveImageSha384,ParameterValue=<from enclave-measurements.json> \
    ParameterKey=EnclavePcr1Sha384,ParameterValue=<from enclave-measurements.json> \
    ParameterKey=EnclavePcr2Sha384,ParameterValue=<from enclave-measurements.json>
```

The stack smoke test only checks service liveness: both relay services active,
the enclave watchdog active, one running enclave, and TCP 443 listening.
`CREATE_COMPLETE` does not mean the worker can serve inference. Full inference
validation happens below.

For v1 operator debugging, use SSM and journald on the instance instead of SSH:

```bash
aws ssm start-session --target <worker-instance-id>
sudo journalctl -u cyntrisec-worker-config -u cyntrisec-relay-egress -u cyntrisec-enclave -u cyntrisec-enclave-watchdog -u cyntrisec-relay --since -1h
```

## Run Proxy

From the stack outputs, run `PolicyDownloadCommand`, `ModelManifestDownloadCommand`, then `ProxyCommand`.

`PolicyDownloadCommand` and `ModelManifestDownloadCommand` use direct
`aws s3 cp`. If the local operator identity can create the stack but does not
have `kms:Decrypt` on the stack EvidenceKey, direct download fails with
`AccessDenied`. In that case use the SSM fallback outputs instead:

```bash
# From CloudFormation Outputs:
#   PolicySsmDownloadCommand
#   ModelManifestSsmDownloadCommand
POLICY_SSM_DOWNLOAD_COMMAND="$(aws cloudformation describe-stacks \
  --stack-name <stack-name> \
  --query 'Stacks[0].Outputs[?OutputKey==`PolicySsmDownloadCommand`].OutputValue' \
  --output text)"
MODEL_MANIFEST_SSM_DOWNLOAD_COMMAND="$(aws cloudformation describe-stacks \
  --stack-name <stack-name> \
  --query 'Stacks[0].Outputs[?OutputKey==`ModelManifestSsmDownloadCommand`].OutputValue' \
  --output text)"

printf '%s\n' "$POLICY_SSM_DOWNLOAD_COMMAND"
bash -lc "$POLICY_SSM_DOWNLOAD_COMMAND"
printf '%s\n' "$MODEL_MANIFEST_SSM_DOWNLOAD_COMMAND"
bash -lc "$MODEL_MANIFEST_SSM_DOWNLOAD_COMMAND"
```

The SSM fallback asks the worker instance role to stream the policy/manifest
back through AWS Systems Manager. It avoids granting broad local KMS decrypt
permission to every operator workstation while preserving SSE-KMS on the
evidence bucket.

Expected local listener:

```bash
curl -fsS http://127.0.0.1:4000/health
```

## Inference Smoke

The `cluster-a-v1.1` release image bundles MiniLM for stable first-release measurements, so the smoke uses the OpenAI-compatible embeddings endpoint:

```bash
curl -fsS http://127.0.0.1:4000/v1/embeddings \
  -H 'content-type: application/json' \
  -d '{"model":"stage-0","input":"local pilot smoke"}' \
  -D /tmp/cyntrisec-headers.txt \
  -o /tmp/cyntrisec-response.json
```

Assert:

- HTTP status is `200`.
- `x-cyntrisec-bundle-url` is present.
- `x-cyntrisec-bundle-sha256` is a 64-character lowercase hex string.

## Customer-Style Batch E2E

After the single smoke passes, run the batch harness from a customer laptop or
operator workstation while the local proxy is still listening on `127.0.0.1:4000`:

```bash
bash scripts/aws/customer_openai_e2e.sh \
  --url http://127.0.0.1:4000 \
  --model stage-0 \
  --expected-model stage-0
```

The script sends a batch of OpenAI-format embedding requests, saves every
request/response/header set under `/tmp/cyntrisec-customer-openai-e2e-*` by
default, downloads each emitted S3 bundle, checks the bundle SHA-256 from the
response header, extracts the tarball, verifies `SHA256SUMS`, and runs
`cyntrisec-verify` offline against `air.cbor` + `attestation.cbor`. Pass
`--out-dir evidence/customer-openai-e2e-<date>` only when you intentionally
want a redacted pilot record in the repository.

If direct `aws s3 cp` bundle download fails because the local operator lacks
EvidenceKey decrypt permission, pass the stack `WorkerInstanceId` output:

```bash
WORKER_INSTANCE_ID="$(aws cloudformation describe-stacks \
  --stack-name <stack-name> \
  --query 'Stacks[0].Outputs[?OutputKey==`WorkerInstanceId`].OutputValue' \
  --output text)"

bash scripts/aws/customer_openai_e2e.sh \
  --url http://127.0.0.1:4000 \
  --model stage-0 \
  --expected-model stage-0 \
  --s3-presign-ssm-instance-id "$WORKER_INSTANCE_ID"
```

This generates short-lived HTTPS bundle URLs through SSM and still performs the
offline verification locally.

`--include-chat` is optional. The current `cluster-a-v1.1` image is
embeddings-first, so an unsupported `/v1/chat/completions` response is accepted
unless `--require-chat` is passed.

## Verify Bundle

Fetch the bundle:

```bash
BUNDLE_URL="$(awk 'tolower($1)=="x-cyntrisec-bundle-url:" {print $2}' /tmp/cyntrisec-headers.txt | tr -d '\r')"
BUNDLE_SHA256="$(awk 'tolower($1)=="x-cyntrisec-bundle-sha256:" {print $2}' /tmp/cyntrisec-headers.txt | tr -d '\r')"
aws s3 cp "$BUNDLE_URL" /tmp/cyntrisec.bundle.tar.gz
echo "$BUNDLE_SHA256  /tmp/cyntrisec.bundle.tar.gz" | sha256sum -c -
mkdir -p /tmp/cyntrisec-bundle
tar -xzf /tmp/cyntrisec.bundle.tar.gz -C /tmp/cyntrisec-bundle
(cd /tmp/cyntrisec-bundle && sha256sum -c SHA256SUMS)
cyntrisec-verify /tmp/cyntrisec-bundle/air.cbor \
  --attestation /tmp/cyntrisec-bundle/attestation.cbor \
  --expected-model stage-0 \
  --expected-security-mode production \
  --max-age 0
```

If direct `aws s3 cp "$BUNDLE_URL"` fails on KMS permissions, use the
`BundlePresignCommandTemplate` output or the batch harness option
`--s3-presign-ssm-instance-id`.

Expected verifier matrix:

- `receipt_signature`: `Verified`
- `policy_match`: `Verified`
- `platform_attestation`: `Verified`
- `model_identity`: `Verified`
- `gpu_attestation`: `NotApplicable` for the Nitro CPU pilot
- `overall_confidential_ai`: `Verified`

## Evidence To Save

- CloudFormation stack events showing `CREATE_COMPLETE`.
- The stack outputs.
- `/tmp/cyntrisec-headers.txt`.
- `/tmp/cyntrisec-response.json`.
- Bundle SHA-256 check output.
- `cyntrisec-verify` output.
- Screenshots of the verifier matrix if this is a customer-facing pilot record.
