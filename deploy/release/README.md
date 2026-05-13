# Cyntrisec release artifacts

## Cluster A image release

`.github/workflows/cluster-a-image-release.yml` builds the artifacts consumed by
the AWS worker CloudFormation template:

- `public.ecr.aws/f4z4g3i5/relay:<tag>`: host byte-relay executable OCI artifact
- `public.ecr.aws/f4z4g3i5/relay-egress:<tag>`: host KMS/S3 egress helper
  executable OCI artifact. This artifact also contains
  `cyntrisec-worker-config`, the tiny parent-side vsock service that serves
  customer-specific worker boot config to the prebuilt EIF.
- `public.ecr.aws/f4z4g3i5/proxy:<tag>`: local customer proxy image
- `public.ecr.aws/f4z4g3i5/enclave:<tag>`: Nitro EIF OCI artifact

The workflow also pushes `public.ecr.aws/f4z4g3i5/enclave-rootfs:<tag>` as the
Docker rootfs image used to build the EIF. The customer-facing artifact remains
the signed EIF OCI artifact plus `enclave-measurements.json`.

`f4z4g3i5` is the AWS-assigned ECR Public registry alias for the current
release account. If AWS later grants the branded `cyntrisec` alias, update the
workflow namespace and the CloudFormation installer references together.

The host executable artifacts are release packaging artifacts for native
systemd services; the EC2 host does not need Docker for the relay processes.

The EIF job requires a self-hosted runner with labels
`self-hosted`, `linux`, `x64`, and `nitro-enclaves`, plus working `nitro-cli`
and Docker. It emits `enclave-measurements.json`, which contains the hidden
CloudFormation URL parameters:

- `param_EnclaveImageSha384`
- `param_EnclavePcr1Sha384`
- `param_EnclavePcr2Sha384`

For a CI dry run, start the workflow manually with `push=false`. That builds the
relay executables and proxy image without publishing or signing them. Set
`build_enclave_eif=true` only on the Nitro runner. A tag push to
`cluster-a-v*` enables publish mode and signs pushed artifacts with keyless
cosign via GitHub OIDC after pushing with the release AWS role. The workflow
strips the `cluster-a-` prefix for OCI tags, so
`cluster-a-v1.1` publishes `public.ecr.aws/f4z4g3i5/...:v1.1`.

The first public v1 EIF uses the bundled MiniLM smoke model so the release has
stable measurements. Customer model selection and the final worker boot
configuration are owned by the AWS `worker.yaml` deployment slice.
The release workflow restores the public MiniLM `model.safetensors` file during
the EIF job and verifies its pinned SHA-256 before building the rootfs; the
weight file remains gitignored and is not committed to the repository.

## Release gates

Jobs that assume `AWS_RELEASE_ROLE_ARN` run under the GitHub environment
`production-release`. Configure that environment with required reviewers before
publishing customer artifacts, and keep the self-hosted Nitro runner ephemeral:
one release job per fresh runner, then tear it down.

The AWS release role trust policy must be scoped to this repository, release
environment, and release tag namespace. The intended GitHub OIDC conditions are:

```json
{
  "StringEquals": {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
    "token.actions.githubusercontent.com:repository": "cyntrisec/EphemeralML",
    "token.actions.githubusercontent.com:sub": "repo:cyntrisec/EphemeralML:environment:production-release"
  },
  "StringLike": {
    "token.actions.githubusercontent.com:ref": "refs/tags/cluster-a-v*"
  }
}
```

Do not broaden the `sub` condition to all tags or branches. If the legacy
`worker-v*` tag family is used for an internal dry run, do it in a separate
workflow; this customer-facing release workflow and deploy-time cosign policy
intentionally accept only `cluster-a-v*`.

The role's ECR Public permissions must allow publishing and first-time
repository bootstrap for the five release repositories (`relay`,
`relay-egress`, `proxy`, `enclave-rootfs`, `enclave`). In addition to the
upload and image-read actions, include `ecr-public:CreateRepository` so a
fresh release account can publish without a manual repository pre-create step,
and `ecr-public:DescribeRegistries` so CI can fail early if the account's
public alias is not `cyntrisec`.

## Release public keys

This directory ships the cosign public keys the `ephemeralml-doctor` binary
embeds at build time to verify the EIF image's signature (Check 2).

## Files

### `cyntrisec-release-dev-v1.pub` — **DEV KEY — NOT PRODUCTION**

A local ECDSA P-256 cosign keypair generated 2026-04-23. The private key is
**not** in the repo — it lives on the founder's dev machine at
`~/cyntrisec-dev-keys/cosign.key` (ignored).

**Trust story:** this key is used for:
- Local integration tests that exercise the doctor's Check 2 end-to-end
  against a real cosign signature (not a mock)
- Pre-release dry runs before the production KMS-backed cosign infrastructure
  is deployed

It is **NOT** used to sign any artifact that customers receive. Binaries
signed with this key would fail verification against the production public
key that ships in pilot customer binaries once Day 8 release-signing
infrastructure is deployed.

**Rotation / retirement plan:** when `deploy/aws/release-signing-bootstrap.yaml`
is deployed in the Cyntrisec release account:

1. Extract the KMS-backed public key: `aws kms get-public-key --key-id alias/cyntrisec-release-signing ...`
2. Commit the extracted key as `cyntrisec-release-v1.pub` (same filename
   convention, no `dev`)
3. Update the doctor's `include_bytes!` reference to point at the production
   key
4. Delete `cyntrisec-release-dev-v1.pub` and retire the local private key

From that point on, the local dev key is only used for offline test fixtures
and never signs anything the doctor ships against.

## Why the pubkey is embedded in the doctor binary

Per `byoc-phase-1-supply-chain-posture-spec-2026-04-23.md` §4.2:

> Embedded in the doctor binary at build time: the production public key
> (`cyntrisec-release-v1.pub` contents, ~90 bytes for EC P-256), plus the
> Fulcio and Rekor root certificates for the provenance path.

An attacker with root on the customer's pilot host can swap a file at
`/opt/cyntrisec/etc/cyntrisec-release.pub` — but cannot swap the bytes baked
into a signed doctor binary without breaking the doctor's own cosign
signature (verified out-of-band by the customer before installation per
Section 4.1 of the supply-chain spec).

## Key fingerprint

`cyntrisec-release-dev-v1.pub` — SHA-256 of the file contents:

```
5d5532f66085ac9e6b8e697292f189ea98e262639d6517daae10e4b9c739c55a
```
