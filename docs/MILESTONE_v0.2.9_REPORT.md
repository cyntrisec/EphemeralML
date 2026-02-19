# Milestone v0.2.9 Report

**Date:** 2026-02-19
**Branch:** `milestone/gpu-load-v0.2.9`
**Platforms:** GCP Confidential Space — c3-standard-4 (CPU TDX) and a3-highgpu-1g (GPU H100 CC)
**Image:** `us-docker.pkg.dev/<gcp-project-id>/ephemeralml/enclave:e7ce267`

## Summary

This milestone validates EphemeralML's production readiness on GCP Confidential Space through sustained load testing, compliance overhead measurement, and encrypted model reuse across fresh VM deployments.

## 1. Sustained CPU Load Tests

**Infrastructure:** GCP c3-standard-4 (Intel Sapphire Rapids), us-central1-a, Confidential Space production image (TDX).

### 100-Request Load Test

| Metric | Value |
|--------|-------|
| Total requests | 100/100 (0 failures) |
| Throughput | 4.04 RPS |
| p50 latency | 229ms |
| p95 latency | 344ms |
| p99 latency | 344ms (same as p95 at N=100) |
| Total time | ~24.7s |

### 200-Request Load Test

| Metric | Value |
|--------|-------|
| Total requests | 200/200 (0 failures) |
| Throughput | 3.88 RPS |
| p50 latency | 234ms |
| p95 latency | 366ms |
| Total time | ~51.5s |

**Observations:**
- Zero failures across 300 total requests over the same encrypted channel.
- Throughput is stable at ~4 RPS (bounded by single-threaded inference on MiniLM-L6-v2).
- p50 latency consistent at ~230ms; p95 at ~350ms.
- All requests returned valid Ed25519-signed receipts.

**Evidence:** `evidence/milestone-v029-20260219_221749/load{100,200}-last-receipt.json`

## 2. Receipt/Compliance Overhead

Measured with **release binaries** (not `cargo run`, which adds ~200ms process spawn overhead).

| Operation | Time |
|-----------|------|
| Receipt verify (`verify_receipt`) | 3-4ms |
| Compliance collect + verify | 4-5ms |
| Inference (single request) | ~230-515ms |

**Receipt overhead as % of inference:** ~1.3-1.7%

This is negligible. The prior session's measurements (~155% for verify, ~311% for compliance) were dominated by `cargo run` process spawn overhead, not actual verification work.

## 3. Encrypted Model Reuse (5 Cycles)

Validated that the same KMS-encrypted model in GCS can be reliably decrypted and loaded across 5 completely independent VM deployments.

### Protocol Per Cycle

1. Deploy fresh c3-standard-4 CVM with Confidential Space production image
2. Container boots, obtains CS attestation token, unwraps DEK via WIP+KMS
3. Decrypts model, verifies SHA-256 hash against manifest
4. Client connects via HPKE-X25519-ChaCha20Poly1305 channel
5. Runs inference, receives Ed25519-signed receipt
6. Verify GCS object generations unchanged (immutability check)
7. Delete instance

### Results

| Cycle | Inference | Receipt ID | GCS Immutable |
|-------|-----------|-----------|--------------|
| 1 | 515ms | 1f72c927... | PASS |
| 2 | 511ms | 47020dec... | PASS |
| 3 | 497ms | f27cd8bc... | PASS |
| 4 | 431ms | 513b6488... | PASS |
| 5 | 593ms | e5847274... | PASS |

### GCS Object Generations (unchanged across all 5 cycles)

| Object | Generation |
|--------|-----------|
| config.json | 1771517340844022 |
| manifest.json | 1771517356016461 |
| model.safetensors.enc | 1771517351265881 |
| tokenizer.json | 1771517343575526 |
| wrapped_dek.bin | 1771517353646236 |

**Observations:**
- Boot-to-ready: ~40s per cycle (VM RUNNING to server accepting connections)
- Different external IPs allocated across cycles (GCP ephemeral IP rotation)
- Each fresh boot independently obtains a TDX attestation token and KMS key
- Model hash verified against manifest on every boot
- All receipts have unique IDs and `attestation_doc_hash` values (different keys per boot)

**Evidence:** `evidence/milestone-v029-reuse/cycle-{1..5}-receipt.json`, `summary.txt`, `gcs-baseline.txt`

## 4. GPU E2E (a3-highgpu-1g, H100 CC, Spot)

**Infrastructure:** GCP a3-highgpu-1g (1x NVIDIA H100 80GB), Confidential Space Preview (cgpu), Spot provisioning, us-central1-a.

**Quota:** 3 preemptible H100 GPUs approved in us-central1. A100 requests denied (not needed).

### Single Inference

| Metric | Value |
|--------|-------|
| Latency | 455ms |
| Receipt | 7b4d7011... |
| Attestation | TDX verified (Confidential Space) |
| Signature | Ed25519 [PASS] |

### 100-Request Load Test

| Metric | Value |
|--------|-------|
| Total requests | 100/100 (0 failures) |
| Throughput | 3.43 RPS |
| p50 latency | 270ms |
| p95 latency | 359ms |
| p99 latency | 494ms |
| min/max | 262ms / 494ms |
| Total time | 29.2s |

### GPU vs CPU Comparison

| Metric | GPU (a3-highgpu-1g) | CPU (c3-standard-4) | Delta |
|--------|-------|-------|-------|
| p50 | 270ms | 229ms | +18% |
| p95 | 359ms | 344ms | +4% |
| RPS | 3.43 | 4.04 | -15% |

Note: Model runs on CPU in both cases (candle uses CPU device). GPU overhead comes from the a3-highgpu-1g platform differences (GPU driver stack, CC overhead, Spot scheduling). True GPU-accelerated inference requires CUDA support in candle engine (future work).

### Operational Notes

- AKCert provisioning is per-host; first attempt failed ("failed to find AKCert on this VM"). Retry on a different host succeeded. Known Confidential Space GPU Preview limitation.
- us-central1-b and us-central1-c were stocked out for a3-highgpu-1g.
- Boot-to-ready: ~5s (warm host) to ~90s (cold host with GPU driver install).
- Spot VM was not preempted during the ~10 min test window.

**Evidence:** `evidence/milestone-v029-gpu/gpu-single-receipt.json`, `gpu-load100-receipt.json`, `summary.txt`

## 5. Security Properties Validated

| Property | Evidence |
|----------|---------|
| TDX attestation | CS Launcher JWT with TDX quote in every cycle |
| KMS-gated key release | WIP token exchange + KMS DecryptSymmetric per boot |
| Model integrity | SHA-256 hash check against manifest per boot |
| Transport encryption | HPKE-X25519-ChaCha20Poly1305 (verified in handshake) |
| Receipt signing | Ed25519 signature [PASS] on all 406 receipts (305 CPU + 101 GPU) |
| Data zeroization | Destroy evidence in all receipts (5 actions) |
| GCS immutability | Object generations unchanged across 5 deploys |

## 6. What Changed in v0.2.9

### Code Changes (from v0.2.8)

- **`client/src/bin/ephemeralml.rs`**: Added `--count` flag for multi-request load testing over a single encrypted channel. Single-request mode retains verbose output; multi-request mode prints compact per-request lines with p50/p95/p99/RPS summary.
- **Mock-mode hardening** (carried from v0.2.8 merge): `verify_receipt` exit codes, error hint gating, CI mock-gate job.

### Infrastructure

- GPU quota requests submitted for a3-highgpu-1g
- Google for Startups Cloud Program enrolled ($2,000 credits)

## Release Checklist

- [x] CI green on main (10 jobs)
- [x] CPU real-hardware evidence (300 requests, 5 deploy cycles)
- [x] GPU real-hardware evidence (101 requests on a3-highgpu-1g H100 CC)
- [x] Receipt/compliance overhead measured (<2% of inference)
- [x] Encrypted model reuse validated (5 cycles, GCS immutable)
- [x] Version bump to 0.2.9 across all crates
- [x] CHANGELOG.md updated
- [ ] Push to main, verify CI green
- [ ] Tag `v0.2.9`
