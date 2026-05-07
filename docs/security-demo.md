# Security Demonstration: Host Blindness

This document describes how to demonstrate the host-blindness property without
overclaiming what the demo proves.

## Current Status

The old `SpyProxy` / `host/tests/spy_test.rs` walkthrough was removed with the
legacy in-repo transport implementation. The current transport layer lives in
the sibling `confidential-ml-transport` crate and is exercised by the
EphemeralML demo, gateway, and platform E2E runbooks.

`host/src/bin/spy_host.rs` remains as a simple diagnostic/demo utility, but it
is not the canonical security test and should not be cited as cryptographic
proof.

## What To Run Today

Use the local demo for a developer-level proof path:

```bash
bash scripts/demo.sh
```

The demo starts a mock-mode backend, sends an encrypted request, returns a
signed receipt, and verifies tamper detection. It proves the local protocol and
receipt tooling work; it does not prove hardware isolation.

Use the platform runbooks for hardware-backed evidence:

```bash
# AWS Nitro
bash scripts/nitro_e2e.sh

# GCP Confidential Space
bash scripts/gcp/mvp_gpu_e2e.sh --cpu-only
```

For AWS BYOC evidence, use `docs/AWS_NATIVE_POC_RUNBOOK.md` and the
`ephemeralml-doctor` / `ephemeralml-smoke-test` tooling.

## What The Demo Proves

- The host/gateway path can carry encrypted transport frames without needing
  plaintext prompts or responses.
- The inference result is bound to a signed receipt.
- Tampering with the receipt or expected hashes is detected by the verifier.

## What It Does Not Prove

- Local mock mode does not prove TEE hardware isolation.
- A packet/log inspection demo is observational, not a mathematical proof that
  no plaintext can ever appear in host memory.
- Hardware-backed claims require platform attestation evidence, measurement
  policy, and receipt signing-key binding.

Use `docs/AIR_PROOF_BOUNDARY.md` for customer-facing language about the exact
assurance layer a receipt/verifier result supports.
