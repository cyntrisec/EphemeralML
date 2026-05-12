# cyntrisec-relay-egress

`cyntrisec-relay-egress` is the Nitro parent-side helper for enclave-initiated
egress. It speaks the versioned CBOR egress protocol from
`ephemeral-ml-common` over one vsock connection per request, performs a local
allowlist check, then calls AWS KMS or S3 with the instance profile.

This binary is deliberately separate from `cyntrisec-relay`. The byte relay on
port 5000 forwards encrypted worker-channel bytes and has no AWS SDK
dependencies. This egress helper listens on a different vsock port, default
5001, and owns the AWS SDK surface for KMS Decrypt and S3 PutObject.

## Configuration

Environment variables mirror the command-line flags:

- `CYNTRISEC_EGRESS_VSOCK_PORT`: parent-side vsock listen port, default `5001`
- `CYNTRISEC_EGRESS_AWS_REGION`: AWS region, default `us-east-1`
- `CYNTRISEC_EGRESS_ALLOWED_BUCKETS`: comma-separated S3 bucket allowlist
- `CYNTRISEC_EGRESS_ALLOWED_KMS_KEYS`: comma-separated KMS key ARN allowlist
- `CYNTRISEC_EGRESS_MAX_REQUEST_BYTES`: request cap, default `104857600`
- `CYNTRISEC_EGRESS_MAX_CONN`: concurrent connection cap, default `64`
- `CYNTRISEC_EGRESS_IDLE_SECS`: per-request idle timeout, default `300`
- `CYNTRISEC_EGRESS_LOG_FORMAT`: `json` or `pretty`, default `json`

The allowlists are defense in depth. IAM still scopes the instance profile, but
the relay refuses out-of-scope bucket or key requests before reaching AWS.

## Deployment Notes

The future worker CloudFormation template should run both parent-side services:

- `cyntrisec-relay` on vsock port 5000 for SecureChannel worker traffic
- `cyntrisec-relay-egress` on vsock port 5001 for KMS/S3 egress

The template should pass the evidence bucket and KMS key ARNs to
`CYNTRISEC_EGRESS_ALLOWED_BUCKETS` and
`CYNTRISEC_EGRESS_ALLOWED_KMS_KEYS`. The instance profile should independently
grant only the matching `kms:Decrypt` and `s3:PutObject` permissions.

The service does not parse OpenAI JSON, receipts, AIR, policies, manifests, or
bundle tarballs. It decodes only `EgressRequest` CBOR and emits only
`EgressResponse` CBOR.
