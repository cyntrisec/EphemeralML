# AWS Nitro Enclaves E2E — Final Report

**Date:** 2026-02-23
**Status:** SUCCESS — Full pipeline inference with PCR-pinned attestation on real Nitro hardware.

## What Worked

End-to-end confidential inference completed successfully:

1. **Enclave launched** on real Nitro hardware (m6i.xlarge, us-east-1)
2. **Host connected** over VSock (ports 5000/5001/5002) using pipeline mode
3. **Attestation handshake** completed with HPKE key binding in NSM attestation document
4. **PCR pinning** verified all 3 measurements (enforced by `nitro_e2e.sh` — the script refuses to proceed without valid PCRs; the host binary itself only warns and continues if PCRs are missing)
5. **MiniLM-L6-v2 inference** returned 384-dim embeddings in 78ms (75ms execution, ~3ms overhead)
6. **Signed attestation receipt** produced with Ed25519 signature

### Results Summary

| Metric | Value |
|--------|-------|
| Model | MiniLM-L6-v2 (22.7M params, 87MB safetensors) |
| Embedding dimensions | 384 |
| L2 norm | 7.3331 |
| Inference time | ~78ms total, ~75ms execution |
| Receipt ID | `5c5fe418-483f-4621-8829-6e5a931e39c9` |
| First 5 dims | [-0.1558, 0.8509, -0.0341, 0.2921, 0.2311] |

## Infrastructure Configuration

| Setting | Value |
|---------|-------|
| Instance type | m6i.xlarge (4 vCPUs, 16 GiB) |
| Region / AZ | us-east-1 |
| AMI | AL2023 (ami-0f3caa1cf4417e51b) |
| Disk | 30 GiB gp3 |
| Enclave memory | 4096 MiB |
| Enclave CPUs | 2 |
| Enclave CID | 16 |
| IAM role | None (local model, no KMS) |
| Model path | Bundled in EIF at `/app/test_assets/minilm/` |
| Feature flags | `--no-default-features --features production` |

### PCR Measurements (from this run)

| PCR | Prefix | Measures |
|-----|--------|----------|
| PCR0 | `f279be5d...` | Enclave image hash |
| PCR1 | `4b4d5b36...` | Linux kernel + boot config |
| PCR2 | `f4f8b2fa...` | Application (binary + model weights) |

## Bugs Found and Fixed

### 1. Attestation Public Key Mismatch (CRITICAL)

**Root cause:** `AttestationBridge.attest()` ignored the `public_key` parameter from cml-transport's handshake. The NSM attestation document's `public_key` field contained the RSA KMS key (~300 bytes DER) instead of the HPKE X25519 ephemeral key (32 bytes). The handshake verifier then saw a mismatch and rejected the connection.

**Fix (3 files):**

- `enclave/src/attestation.rs`: Added `generate_attestation_for_transport()` method to the `AttestationProvider` trait with a `handshake_public_key` parameter. Added `generate_nsm_attestation_with_key()` that accepts a `public_key_override` to pass the HPKE key to NSM instead of the RSA key. Implemented on both `NSMAttestationProvider` and `DefaultAttestationProvider`.

- `enclave/src/attestation_bridge.rs`: Changed `attest()` to use the `public_key` parameter (was `_public_key`) and call `generate_attestation_for_transport()` instead of `generate_attestation()`.

**Impact:** Without this fix, the handshake always fails with `PublicKeyMismatch`. This was the only code bug blocking E2E.

### 2. Missing Model Weights in Dockerfile (BUILD)

**Root cause:** `enclave/Dockerfile.enclave` copied `tokenizer.json` and `config.json` but not `model.safetensors`. The enclave would start but fail to load the model.

**Fix:** Added `COPY test_assets/minilm/model.safetensors /app/test_assets/minilm/model.safetensors`.

### 3. Docker Build Failure — target/ in .dockerignore (BUILD)

**Root cause:** `.dockerignore` excludes `target/`, so `COPY target/release/ephemeral-ml-enclave` fails during `docker build`.

**Fix:** Stage the binary to `docker-stage/` before building. Updated `Dockerfile.enclave` to `COPY docker-stage/ephemeral-ml-enclave` and `scripts/nitro_e2e.sh` to create the staging directory.

## Security Caveats

### Current Limitations

1. **One-way attestation only.** The enclave attests to the host; the host is trusted (same EC2 instance, not in a TEE). The host uses `MockProvider`. For multi-party scenarios, the client should verify the receipt independently.

2. **No IAM role / KMS integration.** The model is bundled in the EIF (measured in PCR2). For production with KMS-gated model release, the enclave needs an IAM role and KMS proxy.

3. **Receipt verification is local.** The Ed25519 receipt signing key is generated inside the enclave at startup. There is no external root of trust binding the signing key to an attestation. The receipt's `attestation_hash` links back to the NSM document, but a standalone verifier would need the full attestation chain.

4. **Debug mode zeros PCRs.** Never use `--debug-mode` in production. The host binary now fails closed on missing or malformed PCR env vars (returns an error instead of warning and continuing). Pass `--allow-unpinned` to bypass for development/debugging only.

5. **No network isolation.** The security group allows SSH from 0.0.0.0/0. Production should restrict to bastion/VPN.

6. **Mock tests don't exercise the NSM path.** The `AttestationProvider` trait has mock and production implementations. Unit tests use mocks; only real Nitro hardware tests the NSM codepath. The `generate_attestation_for_transport` fix was only testable on real hardware (or by adding an integration-level mock of the NSM IOCTL).

### What's Correctly Secured

- PCR pinning is fail-closed at both layers: `nitro_e2e.sh` aborts without valid PCRs, and the host binary returns an error if `EPHEMERALML_EXPECTED_PCR0/1/2` are missing or malformed (unless `--allow-unpinned` is explicitly passed)
- Model weights are measured in PCR2 — changing the model changes the hash
- HPKE key is bound in the attestation document — prevents key substitution
- Ed25519 receipt signature is verified with `verify_strict`
- RSA decryption uses blinded mode (Marvin attack mitigation)

## Artifacts Produced

| Artifact | Location |
|----------|----------|
| E2E runbook | `docs/AWS_NITRO_E2E_RUNBOOK.md` |
| Automation script | `scripts/nitro_e2e.sh` |
| This report | `docs/AWS_NITRO_E2E_REPORT.md` |
| Dockerfile (fixed) | `enclave/Dockerfile.enclave` |
| Attestation fix | `enclave/src/attestation.rs`, `enclave/src/attestation_bridge.rs` |

**Evidence gap:** The success-run evidence was not copied off the EC2 instance before termination and is therefore not independently verifiable from checked-in artifacts. The `evidence/aws-nitro-e2e-20260221_193937/` directory contains an older blocked run, not this one. The next E2E run should use `scp` or the updated `nitro_e2e.sh` to persist evidence locally before cleanup.

Evidence that was on the terminated EC2 instance:
- EIF build JSON with PCR0/1/2
- `describe-enclaves` output (CID 16, RUNNING, 4096 MiB)
- Host output log (full pipeline trace with human-readable receipt summary)

**Note:** The host binary prints the receipt as a human-readable summary, not raw CBOR bytes. A raw CBOR receipt artifact was not saved to disk. The `host_output.log` captures the printed summary (receipt ID, hashes, PCRs, signature, timing). To persist a machine-verifiable receipt, the host binary would need a `--receipt-output <path>` flag that writes the raw `__receipt__` tensor bytes.

## Next Steps to Harden / Productionize

### Short-term (before next E2E run)

1. ~~**Harden host binary to fail-closed on missing PCRs**~~ — Done. `host/src/main.rs` now returns an error when `expected_pcrs` is empty (unless `--allow-unpinned`), and returns an error on malformed hex or wrong-length values.
2. **Add integration test for `generate_attestation_for_transport`** — mock the NSM IOCTL response to verify the HPKE key lands in the attestation document's `public_key` field.
3. **Update `nitro_e2e.sh` to save evidence locally** — `scp` the evidence directory from EC2 before terminating, and persist a raw receipt artifact.
4. **Pin the Dockerfile base image** — use `ubuntu:22.04@sha256:...` for reproducible builds.

### Medium-term (production readiness)

5. **KMS-gated model release** — add IAM role to the instance, run `kms_proxy_host`, enclave decrypts model weights at runtime instead of bundling in EIF.
6. **Receipt chain verification** — bind the Ed25519 signing key to the attestation document so external verifiers can validate receipts without trusting the host.
7. **Multi-enclave pipeline** — test 2-3 stage pipeline on m6i.2xlarge (8 vCPUs, 32 GiB) with 3 enclaves for model sharding.
8. **Restrict security group** — SSH from VPN/bastion only, or use SSM Session Manager (no SSH at all).

### Long-term (cross-cloud)

9. **GCP Confidential Space deployment** — containerize for CS, obtain TDX attestation token from Launcher socket, use WIP + Cloud KMS for model release.
10. **GPU inference** — test on AWS P6e-GB200 (Nitro + Blackwell, GA July 2025) or Azure H100 CC (SEV-SNP, GA now).
11. **Receipt standard** — formalize the proof bundle format, publish verification spec, build hosted verification API.

## Cost

Total for this session: ~$0.40 (m6i.xlarge for ~2 hours including build time, 30 GiB gp3).
