# Cyntrisec Pilot Deployment Runbook

This runbook validates the AWS worker stack after the Cluster A release
artifacts have been published and `deploy/aws/v1/worker.yaml` has been uploaded
to `https://templates.cyntrisec.com/aws/v1/worker.yaml`.

## Prerequisites

- AWS CLI authenticated into the pilot account.
- A released tag such as `v1`.
- `enclave-measurements.json` from the Cluster A image release workflow.
- Docker installed locally for the customer-side proxy.
- `cyntrisec-verify` available locally.

## Deploy

1. Open the CloudFormation launch URL produced by the website's Deploy to AWS
   button.
2. Confirm the URL includes:
   - `templateURL=https://templates.cyntrisec.com/aws/v1/worker.yaml`
   - `param_EnclaveImageSha384=<from enclave-measurements.json>`
   - `param_EnclavePcr1Sha384=<from enclave-measurements.json>`
   - `param_EnclavePcr2Sha384=<from enclave-measurements.json>`
3. Fill the visible parameters:
   - `AccessCIDR`
   - `ModelURI`
   - `EvidenceBucketName`
   - `RetentionDays`
   - `InstanceType`
4. Create the stack and wait for `CREATE_COMPLETE`.

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

From the stack outputs, run `PolicyDownloadCommand`, then run `ProxyCommand`.

Expected local listener:

```bash
curl -fsS http://127.0.0.1:4000/health
```

## Inference Smoke

Send one OpenAI-compatible request:

```bash
curl -fsS http://127.0.0.1:4000/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"stage-0","messages":[{"role":"user","content":"local pilot smoke"}]}' \
  -D /tmp/cyntrisec-headers.txt \
  -o /tmp/cyntrisec-response.json
```

Assert:

- HTTP status is `200`.
- `x-cyntrisec-bundle-url` is present.
- `x-cyntrisec-bundle-sha256` is a 64-character lowercase hex string.

## Verify Bundle

Fetch the bundle:

```bash
BUNDLE_URL="$(awk 'tolower($1)=="x-cyntrisec-bundle-url:" {print $2}' /tmp/cyntrisec-headers.txt | tr -d '\r')"
BUNDLE_SHA256="$(awk 'tolower($1)=="x-cyntrisec-bundle-sha256:" {print $2}' /tmp/cyntrisec-headers.txt | tr -d '\r')"
aws s3 cp "$BUNDLE_URL" /tmp/cyntrisec.bundle.tar.gz
echo "$BUNDLE_SHA256  /tmp/cyntrisec.bundle.tar.gz" | sha256sum -c -
cyntrisec-verify /tmp/cyntrisec.bundle.tar.gz
```

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
