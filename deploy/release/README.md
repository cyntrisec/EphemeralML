# Cyntrisec release public keys

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
