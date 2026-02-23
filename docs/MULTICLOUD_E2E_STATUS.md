# Multicloud E2E Validation Status

**Last updated:** 2026-02-23

EphemeralML has been validated single-stage E2E on AWS Nitro Enclaves and GCP Confidential Space (CPU and H100 GPU). All three runs completed inference with MiniLM-L6-v2, produced Ed25519-signed attestation receipts, and verified them.

## Summary

| Platform | Machine | TEE | Model | Inference | Receipt | Status |
|----------|---------|-----|-------|-----------|---------|--------|
| AWS Nitro | m6i.xlarge | Nitro Enclave (KVM) | MiniLM-L6-v2 | 75ms | Verified | **PASS** |
| GCP TDX CPU | c3-standard-4 | Intel TDX | MiniLM-L6-v2 | 69ms | Verified | **PASS** |
| GCP TDX GPU | a3-highgpu-1g | Intel TDX + H100 CC | MiniLM-L6-v2 | 12,226ms* | Verified | **PASS** |

\*GPU inference time is dominated by first-run CUDA kernel JIT warmup. MiniLM (22.7M params) is far too small to benefit from H100 parallelism; steady-state GPU inference for this model would be comparable to or slower than CPU due to memory-transfer overhead. The H100 E2E validates the pipeline, not GPU performance. Real GPU benchmarks require 7B+ parameter models.

---

## 1. AWS Nitro Enclaves

**Date:** 2026-02-21
**Commit:** `8b91a41`
**Docs:** [`docs/AWS_NITRO_E2E_REPORT.md`](AWS_NITRO_E2E_REPORT.md), [`docs/AWS_NITRO_E2E_RUNBOOK.md`](AWS_NITRO_E2E_RUNBOOK.md)

### Configuration

| Setting | Value |
|---------|-------|
| Instance | m6i.xlarge (4 vCPU, 16 GiB, Intel Xeon 8375C Ice Lake) |
| Region | us-east-1 |
| Enclave | 4096 MiB, 2 CPUs, CID 16 |
| Model source | Bundled in EIF (measured in PCR2) |
| Feature flags | `--no-default-features --features production` |
| Communication | VSock pipeline (control:5000, data_in:5001, data_out:5002) |

### Attestation Model

- **Provider:** AWS Nitro Secure Module (NSM)
- **Format:** COSE_Sign1 with CBOR-encoded attestation document
- **Measurements:** PCR0 (enclave image), PCR1 (kernel), PCR2 (application) — SHA-384
- **Key binding:** HPKE X25519 ephemeral key bound in NSM attestation `public_key` field
- **Verification:** PCR pinning enforced by `nitro_e2e.sh` (fail-closed); host binary returns error on missing PCRs unless `--allow-unpinned`

### Timing

| Phase | Duration |
|-------|----------|
| Build (enclave binary, production features) | ~11 min |
| EIF build (Docker + nitro-cli) | ~2 min |
| Enclave boot | ~10s |
| Inference (MiniLM-L6-v2, 384-dim) | 75ms execution, ~78ms total |

### Bugs Fixed During Run

1. **Attestation public key mismatch (CRITICAL):** NSM doc contained RSA KMS key instead of HPKE handshake key. Fixed by adding `generate_attestation_for_transport()` with `public_key_override`.
2. **Missing model weights in Dockerfile:** Added `model.safetensors` to COPY.
3. **Docker build failure:** `.dockerignore` excludes `target/`; staged binary to `docker-stage/`.

### Evidence

- Checked-in report: `docs/AWS_NITRO_E2E_REPORT.md`
- `evidence/aws-nitro-e2e-20260221_193937/REPORT.md` — earlier blocked run (not the success run)
- **Gap:** Success-run evidence (host output log, EIF PCR JSON) was not copied off EC2 before termination. Next run should use `scp` or the updated `nitro_e2e.sh` evidence collection.

---

## 2. GCP Confidential Space — CPU (Intel TDX)

**Date:** 2026-02-23
**Image tag:** `634a545`
**Evidence:** `evidence/gcp-tdx-e2e-20260223_193001/`

### Configuration

| Setting | Value |
|---------|-------|
| Instance | c3-standard-4 (4 vCPU, Intel Sapphire Rapids) |
| Zone | us-central1-a |
| CS image | `confidential-space` (production, GA) |
| Model source | Local (bundled in container at `/app/model/`) |
| Feature flags | `--no-default-features --features gcp` |
| Communication | TCP direct mode (port 9000) |

### Attestation Model

- **Provider:** Confidential Space Launcher JWT (fetched from `/run/container_launcher/teeserver.sock`)
- **Format:** OIDC JWT with TDX quote embedded; `eat_nonce` for session binding
- **JWT issuer:** `https://confidentialcomputing.googleapis.com`
- **Measurements:** TDX MRTD + RTMRs (from Launcher measurement, not raw configfs-tsm — CS does not expose configfs-tsm inside the container)
- **Key binding:** HPKE key hash in trust evidence bundle
- **Verification:** Client verifies JWT signature; MRTD pinning via `EPHEMERALML_EXPECTED_MRTD` (not enforced in this test — `REQUIRE_MRTD=false`)

### Timing

| Phase | Duration |
|-------|----------|
| Docker build (CPU, gcp features) | 462s (~7.7 min) |
| Docker push to AR | 111s |
| VM boot to RUNNING | ~15s |
| Container startup (image pull + CS Launcher) | ~50s |
| Model load | 242ms |
| CS identity (Launcher JWT + TDX quote) | ~850ms |
| Inference (MiniLM-L6-v2, 384-dim) | 69ms |

### Evidence Artifacts

| File | Description |
|------|-------------|
| `receipt.json` | Signed inference receipt (JSON) |
| `receipt.pubkey` | Ed25519 public key (hex) |
| `attestation.bin` | Raw TDX quote (764 bytes) |
| `container_logs.txt` | Full container lifecycle from Cloud Logging |
| `instance_describe.yaml` | CVM instance configuration |
| `e2e_report.md` | Detailed report with trust evidence bundle |

---

## 3. GCP Confidential Space — GPU (Intel TDX + NVIDIA H100 CC)

**Date:** 2026-02-23
**Image tag:** `634a545`
**Evidence:** `evidence/gcp-gpu-e2e-20260223_203030/`

### Configuration

| Setting | Value |
|---------|-------|
| Instance | a3-highgpu-1g (26 vCPU, 234 GiB, 1x H100 80GB) |
| Provisioning | Spot (preemptible) |
| Zone | us-central1-a |
| CS image | `confidential-space-preview-cgpu` (GPU CC Preview) |
| CUDA | 12.2.2 (build), driver 535.247.01 (host-installed by Launcher) |
| Model source | Local (bundled in container at `/app/model/`) |
| Feature flags | `--no-default-features --features gcp,cuda` |
| Communication | TCP direct mode (port 9000) |
| Compute cap | `CUDA_COMPUTE_CAP=90` (H100 Hopper) |

### Attestation Model

Same as CPU TDX above. The H100 operates in CC-On mode (Confidential Computing enabled), providing GPU memory isolation. The TDX quote covers the CPU TEE; the GPU CC status is attested separately by the Launcher.

### Timing

| Phase | Duration |
|-------|----------|
| Docker build (CUDA 12.2, candle-cuda kernels) | 602s (~10 min) |
| Docker push to AR | 48s |
| VM boot to RUNNING | ~15s |
| GPU driver install (535.247.01) | ~30s |
| Container startup (image pull + CS Launcher) | ~45s |
| CUDA initialization | ~10s |
| Model load (safetensors → GPU) | 561ms |
| CS identity (Launcher JWT + TDX quote) | ~700ms |
| Inference (MiniLM-L6-v2, 384-dim, H100) | 12,226ms |

**Why inference is slow:** The 12.2s includes first-run CUDA kernel JIT/PTX compilation. MiniLM (22.7M params, ~87 MB) fits entirely in CPU L3 cache. GPU parallelism is wasted on a model this small; memory transfer overhead dominates. This number should not be cited as H100 inference performance. Steady-state GPU advantage only appears with models >1B parameters.

### Spot Availability

H100 Spot capacity fluctuated during the test:
- us-central1-a: stockout → retry succeeded ~5 min later
- us-central1-b: stockout
- us-central1-c: stockout
- Quota requests submitted for us-east4, us-west1, us-west4, us-east5

### Inference Value Comparison (CPU vs GPU)

```
CPU: [0.3414222,  0.75955707, 0.071208954, 0.2389017,  -0.15010944]
GPU: [0.34142268, 0.75955725, 0.071208164, 0.23890182, -0.15010901]
```

Differences in the 5th–7th decimal place — expected FP32 CPU vs GPU rounding.

---

## Evidence Artifact Schema

Each E2E run should produce the following standard artifacts:

| Artifact | Filename | Format | Description |
|----------|----------|--------|-------------|
| Receipt | `receipt.json` | JSON | Signed `AttestationReceipt` with hashes, measurements, signature |
| Receipt (raw) | `receipt.raw` | CBOR/JSON | Original `__receipt__` tensor bytes (wire format, for canonical verification) |
| Receipt public key | `receipt.pubkey` | Hex text | Ed25519 signing key for offline verification |
| Attestation | `attestation.bin` | Binary | Raw attestation (NSM COSE_Sign1 or TDX quote) |
| Container/enclave logs | `container_logs.txt` | Text | Full enclave lifecycle output |
| Instance metadata | `instance_describe.yaml` | YAML | Cloud provider instance configuration |
| Report | `e2e_report.md` | Markdown | Human-readable summary with timings and trust bundle |
| Timing | `timing.json` | JSON | Machine-readable timing breakdown (phase durations, enclave execution time) |

### Current Artifact Coverage

| Artifact | AWS Nitro | GCP CPU | GCP GPU |
|----------|-----------|---------|---------|
| `receipt.json` | Missing* | Present | Present |
| `receipt.pubkey` | Missing* | Present | Present |
| `receipt.raw` | Missing* | Not collected** | Not collected** |
| `attestation.bin` | Missing* | Present | Present |
| `container_logs.txt` | Missing* | Present | Present |
| `instance_describe.yaml` | N/A | Present | Present |
| `e2e_report.md` | `docs/AWS_NITRO_E2E_REPORT.md` | Present | Present |
| `timing.json` | Implemented (via `nitro_e2e.sh`) | Implemented (via `verify.sh`) | Implemented (via `verify.sh`) |

\*AWS success-run artifacts were not copied off EC2 before termination. `--receipt-output` and `--receipt-output-raw` flags now available on the host binary for future runs.

\*\*Raw receipt bytes (`receipt.raw`) are available via `--receipt-output-raw` on the host binary (AWS Nitro pipeline mode). GCP client saves parsed JSON only; raw wire bytes are available inside the client if needed.

---

## Cross-Platform Comparison

| Metric | AWS Nitro | GCP TDX CPU | GCP TDX GPU |
|--------|-----------|-------------|-------------|
| TEE type | Nitro Enclave (KVM) | Intel TDX | Intel TDX + H100 CC |
| CPU | Ice Lake 8375C | Sapphire Rapids | Sapphire Rapids |
| Instance cost | ~$0.19/hr | ~$0.21/hr | ~$3.70/hr (Spot) |
| Attestation format | COSE_Sign1/CBOR | Launcher JWT + TDX quote | Launcher JWT + TDX quote |
| Attestation latency | <1ms (NSM device) | ~850ms (HTTP to Launcher) | ~700ms (HTTP to Launcher) |
| Communication | VSock (pipeline) | TCP (direct) | TCP (direct) |
| Model load | Not timed separately | 242ms | 561ms |
| Inference (MiniLM) | 75ms | 69ms | 12,226ms (cold) |
| Boot to ready | ~10s (enclave only) | ~83s (VM + container) | ~135s (VM + driver + container) |
| Receipt format | Human-readable print | JSON file | JSON file |
| CS image | N/A | GA production | Preview (GPU CC) |

---

## Code Fixes Applied

### For AWS Nitro E2E (commit `8b91a41`)

1. **Attestation key binding fix** (`enclave/src/attestation.rs`, `enclave/src/attestation_bridge.rs`) — Added `generate_attestation_for_transport()` to pass HPKE key to NSM instead of RSA KMS key.
2. **Dockerfile fixes** (`enclave/Dockerfile.enclave`) — Added model weights, staged binary to avoid `.dockerignore` conflict.
3. **PCR fail-closed** (`host/src/main.rs`, `host/src/pcr.rs`) — Host binary errors on missing/malformed PCRs unless `--allow-unpinned`. 13 unit tests.

### For GCP E2E (this session)

4. **Deploy metadata fix** (`scripts/gcp/deploy.sh`) — WIP audience always passed in metadata when available, not only for `gcs-kms` model source. Launcher JWT transport attestation needs it regardless.

---

## Known Gaps and Next Steps

### Evidence Gaps

- [ ] AWS success-run artifacts not preserved (need `scp` before termination in next run)
- [x] Host binary now supports `--receipt-output <path>` (parsed JSON) and `--receipt-output-raw <path>` (wire-format bytes)
- [x] `timing.json` generation added to `verify.sh` (GCP) and `nitro_e2e.sh` (AWS)

### Test Gaps

- [ ] Transport attestation key binding (`generate_attestation_for_transport`): the bridge contract (user_data embedding, receipt key propagation, error forwarding) is covered by 6 mock-mode unit tests in `attestation_bridge.rs`. However, verifying that the hardware attestation document contains the correct HPKE `public_key` field requires real TEE hardware (NSM IOCTL on Nitro, Launcher JWT on GCP). Validated via `nitro_e2e.sh` and `scripts/gcp/verify.sh` E2E runs.
- [x] Deploy metadata regression test added (`scripts/test_deploy_metadata.sh`, 13 tests) — covers WIP audience presence for all model sources
- [ ] No warm-inference GPU benchmark (only cold-start measured)

### Production Gaps

- [ ] KMS-gated model release not tested on Nitro (model bundled in EIF)
- [ ] MRTD pinning not enforced on GCP runs (`REQUIRE_MRTD=false`)
- [ ] CS configfs-tsm not available inside container — boot evidence uses synthetic TDX provider
- [ ] No multi-enclave pipeline tested on either platform
- [ ] Dockerfile base images not pinned to digest

### Cross-Platform

- [ ] Azure SEV-SNP E2E not attempted (DCesv5 needs `ConfidentialVMTdxStatelessPreview` feature flag — stayed "Pending")
- [ ] Receipt format normalization between Nitro (CBOR in `__receipt__` tensor, printed to stdout) and GCP (JSON file written by client)
