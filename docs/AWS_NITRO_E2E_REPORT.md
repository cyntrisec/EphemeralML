# AWS Nitro Enclaves E2E — Final Report

**Date:** 2026-04-10/11
**Status:** SUCCESS — Full pipeline inference with PCR-pinned attestation on real Nitro hardware, plus offline AIR v1 verification and trust-center upload verification.

## What Worked

End-to-end confidential inference and receipt verification completed successfully:

1. **Enclave launched** on real Nitro hardware (m6i.xlarge, us-east-1)
2. **Host connected** over VSock (ports 5000/5001/5002) using pipeline mode
3. **Attestation handshake** completed with HPKE key binding in NSM attestation document
4. **PCR pinning** verified all 3 measurements (enforced by `nitro_e2e.sh`; host validation is fail-closed on missing/malformed PCRs unless `--allow-unpinned` is explicitly used)
5. **MiniLM-L6-v2 inference** returned 384-dim embeddings in ~81ms host-observed latency (78ms enclave execution from `timing.json`)
6. **Signed attestation receipt** produced with Ed25519 signature and persisted to local evidence (`receipt.json` + `receipt.raw`)
7. **AIR v1 receipt** persisted as `receipt.cbor` and verified offline with `ephemeralml-verify`
8. **Boot attestation sidecar** persisted as `attestation.cbor` and used to derive the receipt signing key during verification
9. **Trust-center upload path** accepted the AWS AIR receipt and returned `{"verified":true,"format":"air_v1","verdict":"verified"}`

### Results Summary

| Metric | Value |
|--------|-------|
| Model | MiniLM-L6-v2 (22.7M params, 87MB safetensors) |
| Embedding dimensions | 384 |
| L2 norm | 7.3331 |
| Inference time | ~81ms host-observed, 78ms enclave execution (`timing.json`) |
| Receipt ID | `d703095a-7852-44a1-aa7f-ac6999d7d41d` |
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
| PCR0 | `99d6cd9e...` | Enclave image hash |
| PCR1 | `4b4d5b36...` | Linux kernel + boot config |
| PCR2 | `8a489d26...` | Application (binary + model weights) |

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

### 4. Stage Measurement Propagation Broke One-Way Nitro Data Channels

**Root cause:** The host copied the enclave PCR allowlist into `StageSpec.expected_measurements`. The pipeline stage runtime reuses that field for its own data-channel verification, so the enclave tried to verify the non-TEE host as if it were another enclave and aborted with `missing required field: measurement[0]`.

**Fix:** Keep PCR pinning on the host `SessionConfig`, but leave `StageSpec.expected_measurements` empty in the single-stage Nitro host flow. Also disable only the pipeline-level `require_measurements` sanity check in this path, while keeping transport-level measurement verification enabled.

**Impact:** This preserves real Nitro PCR verification on control and data channels from the host side and restores the valid one-way attestation model for host-to-enclave deployments.

### 5. AWS Receipt Verification Needed Attestation-Carried Key Provenance

**Root cause:** The previous Nitro path could generate receipts, but the evidence bundle did not include a verification artifact that let the offline verifier or trust-center derive the receipt signing key without a separate manual pubkey export.

**Fix:** Emit a boot attestation sidecar (`attestation.cbor`), add shared receipt-key extraction from attestation in the client crate, and let the verifier API upload flow accept `attestation_file` as an alternative to `public_key`.

**Impact:** Nitro receipts are now verifiable offline and through the trust-center API using the attestation document captured during the real run.

## Security Caveats

### Current Limitations

1. **One-way attestation only.** The enclave attests to the host; the host is trusted (same EC2 instance, not in a TEE). The host uses `MockProvider`. For multi-party scenarios, the client should verify the receipt independently.

2. **No IAM role / KMS integration.** The model is bundled in the EIF (measured in PCR2). For production with KMS-gated model release, the enclave needs an IAM role and KMS proxy.

3. **Trust-center verification is key-provenance aware but policy-light.** The trust center can now derive the receipt signing key from `attestation.cbor`, but it still does not enforce deployment-specific PCR allowlists by itself. Caller-supplied policy remains required for strong deployment matching.

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
| Latest success-run evidence bundle | `evidence/nitro-20260410_225206/` |
| Earlier success-run evidence bundle | `evidence/aws-nitro-e2e-20260225_095649/` |
| Attestation bridge fixes | `enclave/src/attestation.rs`, `enclave/src/attestation_bridge.rs` |
| Nitro attestation-sidecar flow | `enclave/src/main.rs`, `enclave/src/stage_executor.rs`, `host/src/main.rs`, `client/src/receipt_key.rs`, `verifier-api/src/routes.rs` |

Fresh success-run evidence is now checked in under `evidence/nitro-20260410_225206/`, including:
- `eif_build_output.json` and `pcr_measurements.json`
- `enclave_launch.json` and `enclave_describe*.json`
- `host_output.log`
- `receipt.json`, `receipt.raw`, and `receipt.cbor`
- `attestation.cbor`
- `legacy_verify.log`, `air_verify.log`, `verification.json`
- `trust_center_verify.json` and `trust_center_server.log`
- `timing.json`

The older `evidence/aws-nitro-e2e-20260221_193937/` directory is retained as a blocked-run artifact for debugging history.

## Next Steps to Harden / Productionize

### Short-term (before next E2E run)

1. ~~**Harden host binary to fail-closed on missing PCRs**~~ — Done. `host/src/main.rs` now returns an error when `expected_pcrs` is empty (unless `--allow-unpinned`), and returns an error on malformed hex or wrong-length values.
2. ~~**Close the Nitro AIR/trust-center gap**~~ — Done. `nitro_e2e.sh` now emits `attestation.cbor`, verifies legacy + AIR v1 receipts offline, and posts the AIR receipt to the verifier API using attestation-derived key provenance.
3. **Add integration test for the single-stage Nitro measurement split** — assert that the host can enforce PCR pinning while the stage still accepts the non-TEE host in one-way attestation mode.
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
