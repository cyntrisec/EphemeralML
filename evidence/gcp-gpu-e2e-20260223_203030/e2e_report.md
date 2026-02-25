# GCP Confidential Space GPU E2E Report — H100, Local Model

**Date:** 2026-02-23
**Instance:** ephemeralml-gpu (a3-highgpu-1g, 1x NVIDIA H100 80GB, 26 vCPUs, 234 GiB RAM)
**Provisioning:** Spot (preemptible)
**Zone:** us-central1-a
**IP:** 34.68.215.180
**Image:** us-docker.pkg.dev/project-d3c20737-eec2-453d-8e5/ephemeralml/enclave:634a545
**CS Image Family:** confidential-space-preview-cgpu (GPU CC Preview)
**CUDA:** 12.2.2 (build), driver 535.247.01 (host-installed)
**Model:** MiniLM-L6-v2 (22.7M params, 384-dim, safetensors, bundled in container)
**Model Source:** local (no KMS/GCS)

## Result: PASS

Full E2E pipeline completed successfully on GPU Confidential Computing:
1. GPU Docker image built with CUDA 12.2 + candle-cuda (CUDA_COMPUTE_CAP=90 for H100)
2. Image pushed to Artifact Registry
3. a3-highgpu-1g Spot instance launched with TDX + H100 CC
4. NVIDIA driver 535.247.01 installed by Confidential Space Launcher
5. CUDA detected and GPU selected for inference
6. Client connected over TCP:9000 with TDX attestation handshake (Launcher JWT)
7. MiniLM-L6-v2 inference on H100 returned 384 floats
8. Ed25519-signed receipt produced and verified

## Timing

| Phase | Duration |
|-------|----------|
| Docker build (CUDA kernels) | 602s (~10 min) |
| Docker push to AR | 48s |
| VM boot to RUNNING | ~15s |
| GPU driver install (535.247.01) | ~30s |
| Container startup (image pull + launch) | ~45s |
| CUDA initialization | ~10s |
| Model load (in-enclave, GPU) | 561ms |
| CS identity (Launcher JWT + TDX quote) | ~700ms |
| Inference (384-dim embedding, H100) | 12,226ms* |
| Total (boot to ready) | ~135s from VM RUNNING |

*First inference includes CUDA kernel warmup / JIT compilation. MiniLM (22.7M params) is far too small to benefit from H100 — model fits entirely in CPU L3 cache. H100 GPU is designed for 7B+ models.

## Trust Evidence Bundle

```
Platform:           tdx
Model ID:           stage-0
Quote Hash:         6e4f15d2fc6be8573328af30c549ae469e253725091eef931aeafd51a1a7e9f7
HPKE Public Key:    f00ae4282f04e6a79d972fa562575658
Receipt Sign Key:   dbf5a573be905260589a4451a314343b
Model Hash:         53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db
```

## Receipt Summary

- **Receipt ID:** 975c799d-2677-4e58-96b8-035593924e33
- **Model:** stage-0 v1.0
- **Platform:** tdx-mrtd-rtmr
- **Execution Time:** 12,226ms (CUDA first-run warmup)
- **Signature:** Ed25519, VERIFIED
- **Destroy Evidence:** 5 actions

## GPU Boot Sequence (from logs)

1. `20:09:34` — CS Launcher starts, detects NVIDIA_H100_80GB
2. `20:09:41` — GPU driver installer starts (v535.247.01 for TDX)
3. `20:09:53` — Driver installation verified
4. `20:10:22` — GPU driver installation completed
5. `20:10:59` — Container starts, CUDA detected: "CUDA available — using GPU"
6. `20:11:09` — Model load starts (safetensors → GPU)
7. `20:11:10` — Model loaded (561ms), trust evidence printed
8. `20:11:10` — Listening on 0.0.0.0:9000

## Comparison: CPU vs GPU on Confidential Space

| Metric | CPU (c3-standard-4) | GPU (a3-highgpu-1g) |
|--------|---------------------|---------------------|
| **Result** | PASS | PASS |
| **TEE Type** | Intel TDX | Intel TDX + H100 CC |
| **CPU** | Sapphire Rapids (4 vCPU) | Sapphire Rapids (26 vCPU) |
| **GPU** | None | NVIDIA H100 80GB |
| **Instance Cost** | ~$0.21/hr | ~$3.70/hr (Spot) |
| **Model Load** | 242ms | 561ms |
| **Inference (MiniLM)** | 69ms | 12,226ms* |
| **Boot to Ready** | ~83s | ~135s |
| **CS Image** | confidential-space (GA) | confidential-space-preview-cgpu |
| **CUDA Version** | N/A | 12.2.2 |
| **Driver** | N/A | 535.247.01 (CC-capable) |

*GPU inference is slower for tiny models due to CUDA warmup, kernel JIT, and memory transfer overhead. The H100 is designed for models with billions of parameters.

## Inference Values Comparison (CPU vs GPU)

The embedding values are nearly identical, with minor floating-point differences:
```
CPU: [0.3414222,  0.75955707, 0.071208954, 0.2389017,  -0.15010944]
GPU: [0.34142268, 0.75955725, 0.071208164, 0.23890182, -0.15010901]
```
Differences are in the 5th-7th decimal place — expected for FP32 CPU vs GPU rounding.

## H100 Spot Availability Note

- First attempt (us-central1-a): STOCKOUT, suggested us-central1-c
- Second attempt (us-central1-c): STOCKOUT, no zones available
- Third attempt (us-central1-b): STOCKOUT
- Fourth attempt (us-central1-a, ~5 min later): **SUCCESS**

H100 Spot capacity fluctuates rapidly. Quota requests submitted for 4 additional US regions (us-east4, us-west1, us-west4, us-east5) for future resilience.

## Evidence Files

- `receipt.json` — Signed inference receipt
- `receipt.pubkey` — Ed25519 public key (hex)
- `attestation.bin` — Raw attestation
- `container_logs.txt` — Full container lifecycle (122 lines)
- `instance_describe.yaml` — CVM instance configuration

## Cost

- a3-highgpu-1g Spot: ~$3.70/hr
- Actual usage: ~25 min
- Estimated cost: ~$1.50
