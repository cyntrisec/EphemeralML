# Multicloud E2E Validation Status

**Last updated:** 2026-02-28
**Canonical claims:** See `docs/publication/claim_definitions.md` for formal definitions and `docs/publication/claim_evidence_matrix.md` for traceability.

EphemeralML has been validated single-stage E2E on AWS Nitro Enclaves and GCP Confidential Space (CPU and H100 GPU). All three platforms completed inference with MiniLM-L6-v2, produced Ed25519-signed attestation receipts, and verified them. Cross-cloud results validate functional and security correctness — they are NOT cross-provider overhead comparisons (different CPUs, different TEE architectures).

## Summary

| Platform | Machine | TEE | Model | Execution | AIR v1 | Negative | Compliance | Evidence | Status |
|----------|---------|-----|-------|-----------|--------|----------|------------|----------|--------|
| AWS Nitro | m6i.xlarge | Nitro Enclave | MiniLM-L6-v2 | 76ms | Legacy JSON | PCR-pinned | N/A | `nitro-e2e-20260227T095832Z/` | **PASS** |
| GCP TDX CPU | c3-standard-4 | Intel TDX | MiniLM-L6-v2 | 75ms | 11/11 PASS | 2/2 PASS | 16/16 | `mvp-20260227_092628/` | **PASS** |
| GCP TDX GPU | a3-highgpu-1g | TDX + H100 CC | MiniLM-L6-v2 | pipeline* | 11/11 PASS | 2/2 PASS | 16/16 | `mvp-20260227_095900/` | **PASS** |

\*GPU inference time for MiniLM is dominated by CUDA JIT warmup and is NOT representative of GPU performance. MiniLM (22.7M params) is far too small to benefit from H100 parallelism. The H100 E2E validates the pipeline, not GPU performance. Real GPU benchmarks require 7B+ parameter models. Do not cite GPU inference time as a performance metric.

---

## 1. AWS Nitro Enclaves

**Date:** 2026-02-27 (latest), 2026-02-25 (benchmark)
**Commit:** `f1ba30d` (build), `a33dc8b` (HEAD at evidence collection)
**Evidence:** `evidence/nitro-e2e-20260227T095832Z/` (latest), `artifacts/benchmarks/aws-nitro-modern-20260225-clean/` (benchmark)
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
| Inference (MiniLM-L6-v2, 384-dim) | 78ms execution (`timing.json`), 118ms client E2E |

### Bugs Fixed During Run

1. **Attestation public key mismatch (CRITICAL):** NSM doc contained RSA KMS key instead of HPKE handshake key. Fixed by adding `generate_attestation_for_transport()` with `public_key_override`.
2. **Missing model weights in Dockerfile:** Added `model.safetensors` to COPY.
3. **Docker build failure:** `.dockerignore` excludes `target/`; staged binary to `docker-stage/`.

### Evidence

- Checked-in report: `docs/AWS_NITRO_E2E_REPORT.md`
- `evidence/aws-nitro-e2e-20260225_095649/` — success run (receipt, raw receipt, PCRs, Nitro JSON, logs, timing)
- `evidence/aws-nitro-e2e-20260221_193937/REPORT.md` — earlier blocked run (kept for debugging history)

---

## 2. GCP Confidential Space — CPU (Intel TDX)

**Date:** 2026-02-25
**Image tag:** `f1ba30d`
**Evidence:** `evidence/gcp-tdx-e2e-20260225_091357/`

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
| Client build (cold compile on verifier host) | 6,994ms |
| Port wait (`verify.sh`) | 30,000ms |
| E2E client call | 2,850ms |
| Inference (MiniLM-L6-v2, 384-dim) | 76ms |
| Receipt verification | 149,575ms* |

\*`receipt_verify_ms` includes a first-time verifier build/compile in this run (cold cache), so it is not pure cryptographic verification latency.

### Evidence Artifacts

| File | Description |
|------|-------------|
| `receipt.json` | Signed inference receipt (JSON) |
| `receipt.pubkey` | Ed25519 public key (hex) |
| `attestation.bin` | Raw TDX quote (764 bytes) |
| `container_logs.txt` | Full container lifecycle from Cloud Logging |
| `instance_describe.yaml` | CVM instance configuration |
| `manifest.json` | Receipt/attestation manifest emitted by verifier |
| `artifact_manifest.json` | Local evidence file inventory |
| `timing.json` | Machine-readable timing breakdown for this run |

---

## 3. GCP Confidential Space — GPU (Intel TDX + NVIDIA H100 CC)

**Date:** 2026-02-25
**Image tag:** `f1ba30d-gpu-20260225`
**Evidence:** `evidence/gcp-gpu-e2e-20260225_092824/`

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
| Client build (verifier host) | 990ms |
| Port wait (`verify.sh --gpu`) | 90,000ms |
| E2E client call | 14,888ms |
| Inference (MiniLM-L6-v2, 384-dim, H100) | 12,319ms |
| Receipt verification | 578ms |

**Why inference is slow:** The 12.2s includes first-run CUDA kernel JIT/PTX compilation. MiniLM (22.7M params, ~87 MB) fits entirely in CPU L3 cache. GPU parallelism is wasted on a model this small; memory transfer overhead dominates. This number should not be cited as H100 inference performance. Steady-state GPU advantage only appears with models >1B parameters.

### Spot Availability

2026-02-25 rerun successfully allocated H100 Spot (`a3-highgpu-1g`) in `us-central1-a`. Capacity remains quota/stockout-sensitive and may require retries on other runs.

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
| `receipt.json` | Present | Present | Present |
| `receipt.pubkey` | N/A* | Present | Present |
| `receipt.raw` | Present | Not collected** | Not collected** |
| `attestation.bin` | Not collected*** | Present | Present |
| `container_logs.txt` | Present (`host_output.log`) | Present | Present |
| `instance_describe.yaml` | N/A | Present | Present |
| `e2e_report.md` | `docs/AWS_NITRO_E2E_REPORT.md` | Not collected (2026-02-25 rerun) | Not collected (2026-02-25 rerun) |
| `timing.json` | Implemented (via `nitro_e2e.sh`) | Implemented (via `verify.sh`) | Implemented (via `verify.sh`) |

\*AWS Nitro host saves `receipt.json` and `receipt.raw` in the evidence bundle; no separate `receipt.pubkey` file is emitted in this flow.

\*\*Raw receipt bytes (`receipt.raw`) are available via `--receipt-output-raw` on the host binary (AWS Nitro pipeline mode). GCP client saves parsed JSON only; raw wire bytes are available inside the client if needed.

\*\*\*Nitro evidence bundle includes `pcr_measurements.json`, `eif_build_output.json`, `enclave_describe*.json`, and receipt artifacts. Unlike GCP, there is no standalone `attestation.bin` file in the current AWS script output.

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
| Inference (MiniLM) | 78ms | 76ms | 12,319ms (cold) |
| Boot to ready | ~10s (enclave only) | ~83s (VM + container) | ~135s (VM + driver + container) |
| Receipt format | JSON + raw receipt files (plus human-readable log) | JSON file | JSON file |
| CS image | N/A | GA production | Preview (GPU CC) |

---

## Code Fixes Applied

### For AWS Nitro E2E (commit `8b91a41`)

1. **Attestation key binding fix** (`enclave/src/attestation.rs`, `enclave/src/attestation_bridge.rs`) — Added `generate_attestation_for_transport()` to pass HPKE key to NSM instead of RSA KMS key.
2. **Dockerfile fixes** (`enclave/Dockerfile.enclave`) — Added model weights, staged binary to avoid `.dockerignore` conflict.
3. **PCR fail-closed** (`host/src/main.rs`, `host/src/pcr.rs`) — Host binary errors on missing/malformed PCRs unless `--allow-unpinned`. 13 unit tests.

### For GCP + AWS reruns (2026-02-25)

4. **GCP verify script compatibility fixes** (`scripts/gcp/verify.sh`) — switched smoke validation back to the legacy `ephemeral-ml-client`, added longer GPU wait, and separated request model ID vs receipt model ID to handle `stage-0` request routing with `minilm-l6-v2` receipt manifests.
5. **Client receipt/model alias support** (`client/src/main.rs`, `client/src/secure_client.rs`) — added env overrides so verification can accept the current GCP receipt model ID while preserving existing request routing.
6. **Nitro PCR parser fix** (`scripts/nitro_e2e.sh`) — resilient extraction of PCR JSON from `nitro-cli build-enclave` output that contains non-JSON log lines before the JSON block.
7. **Nitro runtime entrypoint fixes** (`enclave/Dockerfile.enclave`) — absolute model path plus explicit pipeline ports (`5000/5001/5002`) to match host orchestrator expectations.

---

## Known Gaps and Next Steps

### Evidence Gaps

- [x] AWS success-run artifacts preserved locally (`evidence/aws-nitro-e2e-20260225_095649/`)
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
- [ ] Receipt format normalization between Nitro (JSON + raw `__receipt__` bytes captured by host) and GCP (JSON file written by client; raw wire bytes not saved by default)
