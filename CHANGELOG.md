# Changelog

## [0.2.1] - 2026-02-18

### Fixed
- **GCP deploy scopes**: Changed from narrow scopes to `cloud-platform` (fixes 403 on Confidential Space)
- **Fail-closed attestation on CS**: Added `EPHEMERALML_ALLOW_SYNTHETIC_TRANSPORT=true` to deploy.sh metadata (configfs-tsm is not exposed inside CS containers)
- **Empty env var crash**: Dockerfile `ENV=""` + clap `Option<String>` yielded `Some("")` not `None`, crashing on model hash and signing key checks
- **Receipt request_hash mismatch**: Enclave now hashes full serialized request (matching client), not just `input_data` field
- **CLI verify missing flags**: Added `--format`, `--expected-model`, `--measurement-type` to `ephemeralml verify`

### Added
- **Multi-platform release binaries**: Linux (amd64/arm64, glibc/musl) + macOS (arm64/amd64) — 6 targets via CI matrix
- **Installer auto-detection**: `install.sh` detects OS, architecture, and libc variant (musl vs glibc)
- **Installer script** (`scripts/install.sh`): `curl -fsSL .../install.sh | bash` installs CLI binaries to `~/.ephemeralml/bin/`
- **JSON output for verify**: `ephemeralml verify --format json` returns machine-readable verification results

## [0.2.0] - 2026-02-18

### Added
- **Prebuilt CLI binaries via GitHub Releases**: `ephemeralml`, `ephemeralml-verify`, `ephemeralml-compliance`, `ephemeralml-orchestrator` shipped as `ephemeralml-{tag}-linux-amd64.tar.gz` with SHA256SUMS
- **GitHub Actions release workflow** (`.github/workflows/release.yml`): Triggered on `v*` tag push — builds Linux binaries, pushes Docker image to GHCR, creates GitHub Release
- **MVP GPU E2E script** (`scripts/gcp/mvp_gpu_e2e.sh`): One-command 10-step golden path with GPU support, compliance bundle verification, and negative tests
- **`--allow-synthetic-transport` flag**: Explicit opt-in required for synthetic TDX quotes in Confidential Space (fail-closed by default)

### Changed
- **Version bump**: All crates from 0.1.0 to 0.2.0
- **QUICKSTART.md**: Restructured to lead with 30-second verify, 5-minute local demo, and full GCP GPU deployment
- **Dockerfiles**: Added `EPHEMERALML_ALLOW_SYNTHETIC_TRANSPORT` env var and launch policy label

### Security
- **Fail-closed attestation**: CS deployments without configfs-tsm now fail with a clear error instead of silently falling back to synthetic transport quotes. This closes a trust gap where a misconfigured Confidential Space deployment could silently serve unattested transport channels.

## [3.1.0] - 2026-02-17

### Added
- **GPU Confidential Space deployment**: a3-highgpu-1g with NVIDIA H100 in CC-mode, TDX attestation confirms `nvidia_gpu.cc_mode: ON`
- **CUDA 12.2 support**: Matches GCP Confidential Space cos-gpu-installer v2.5.3 (driver 535.247.01). CUDA 12.6+ fails with `CUDA_ERROR_UNSUPPORTED_PTX_VERSION`
- **Llama 3 8B GGUF inference**: Q4_K_M quantized (4.6GB), 50 tokens in 12s (241ms/token) on H100 with TDX attestation and Ed25519-signed receipts
- **GCS loader improvements**: 16GB max model size (was 4GB), 600s timeout (was 120s), Content-Length pre-check for early rejection of oversized models
- **`Dockerfile.gpu`**: GPU container build based on `nvidia/cuda:12.2.2-devel-ubuntu22.04`
- **`.dockerignore`**: Reduces build context size
- **Launch policy labels**: Container metadata for Confidential Space policy enforcement
- **`--gpu` flag for deploy.sh**: Selects a3-highgpu-1g machine type and GPU container image

### Changed
- **GCS loader**: Increased default size limit from 4GB to 16GB and timeout from 120s to 600s
- **Documentation**: Updated README, QUICKSTART, build-matrix, and PRODUCTION_GCP to reflect GPU capability

## [3.0.0] - 2026-02-13

### Added
- **GCP Confidential Space integration**: Full `--features gcp` path for deploying on Intel TDX CVMs (c3-standard-4)
- **TDX attestation provider**: `TeeAttestationProvider` in `enclave/src/tee_provider.rs` — builds TDX quotes via configfs-tsm, wraps them in `TeeAttestationEnvelope` (CBOR) with receipt signing key in user_data
- **TDX attestation bridge**: `TeeAttestationBridge` adapts the TDX attestation envelope to `confidential-ml-transport` trait interface, propagating receipt key through the full CBOR envelope
- **Client TDX verifier**: `TdxEnvelopeVerifierBridge` in `client/src/attestation_bridge.rs` — decodes CBOR envelope, verifies inner TDX document via `TdxVerifier`, extracts user_data for receipt key delivery
- **MRTD measurement pinning**: `EPHEMERALML_EXPECTED_MRTD` environment variable for TDX measurement enforcement on the client side
- **GCP KMS client**: `GcpKmsClient` in `enclave/src/gcp_kms_client.rs` — Attestation API challenge/verify + STS token exchange + Cloud KMS Decrypt API (implemented and tested, not yet wired into runtime model-loading path)
- **GCS model loader**: `GcsModelLoader` in `enclave/src/gcs_loader.rs` — fetches encrypted models from Google Cloud Storage
- **Three-way feature exclusivity**: `mock`, `production`, `gcp` are mutually exclusive via `compile_error!` guards in all three crates (client, enclave, host)
- **Feature-driven dependency activation**: Transport/pipeline features (`mock`, `tcp`, `tdx`, `vsock`) are now driven by crate feature flags instead of hardcoded in base dependency declarations

### Changed
- **Client verifier dispatch**: 3-way dispatch — `MockVerifierBridge` (mock), `TdxEnvelopeVerifierBridge` (gcp), `CoseVerifierBridge` (production)
- **Test module gating**: All test modules that import mock types are now `#[cfg(all(test, feature = "mock"))]` instead of bare `#[cfg(test)]`, fixing compilation under `--features gcp`
- **Workspace description**: Updated to include GCP Confidential Space
- **Documentation**: Updated README, QUICKSTART, build-matrix, design doc, CONTRIBUTING, SECURITY, and requirements to reflect multi-cloud support

## [2.0.0] - 2026-02-12

### Added
- **Pipeline integration**: End-to-end inference via `confidential-ml-pipeline` orchestrator with per-stage attestation, health checks, and graceful shutdown
- **Working demo**: `bash scripts/demo.sh` runs MiniLM-L6-v2 inference end-to-end — loads model, sends text, returns 384-dim embeddings + signed Attested Execution Receipt
- **Stage executor**: `EphemeralStageExecutor` bridges Candle inference engine with pipeline framework, generates receipts alongside inference outputs
- **Attestation bridge**: Adapts EphemeralML attestation providers to `confidential-ml-transport` trait interface
- **CLI args for enclave**: `--model-dir` and `--model-id` flags via clap for model loading configuration
- **Receipt pretty-printer**: Host displays full receipt with hex-encoded hashes, PCR measurements, Ed25519 signature status
- **Embedding display**: Host shows dimensions, first 5 values, L2 norm of output embeddings
- **Pipeline integration tests**: 10 tests covering init, health check, forward, receipt generation, multi-batch, and shutdown
- **Scripts**: `scripts/demo.sh` (one-command demo), `scripts/download_model.sh` (model weight management)

### Changed
- **Architecture**: Migrated from custom HPKE/VSock protocol to `confidential-ml-transport` SecureChannel + `confidential-ml-pipeline` orchestrator
- **Removed legacy code**: Deleted custom HPKE sessions, VSock framing, session manager, assembly layer, spy mode, and standalone benchmark binaries (functionality now provided by transport/pipeline crates)
- **Test count**: 99 tests passing across 6 crates (down from 111 — removed tests for deleted legacy code, added pipeline integration tests)

### Fixed
- **Model loading**: Enclave now loads model weights before starting pipeline (was creating empty engine causing "Model not loaded" errors)

## [1.0.3] - 2026-02-01

### Added
- **Comprehensive Benchmark Suite**: 6 benchmark binaries covering all performance-critical paths
  - `benchmark_baseline`: Raw inference throughput (MiniLM, 22.7M params)
  - `benchmark_enclave`: Full enclave pipeline with VSock + crypto overhead
  - `benchmark_crypto`: HPKE session + AES-GCM encrypt/decrypt microbenchmarks
  - `benchmark_e2e`: End-to-end latency from client request to decrypted response
  - `benchmark_concurrent`: Multi-client throughput scaling (1–64 concurrent sessions)
  - `benchmark_cose`: COSE_Sign1 attestation verification with P-384 cert chain
- **Benchmark Results**: All results from m6i.xlarge (Nitro-enabled) in `benchmark_results/`
- **Benchmark Documentation**: Specification, methodology, and analysis in `docs/`

### Changed
- **Repository polish**: Added CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md
- **CI pipeline**: GitHub Actions workflow for fmt, clippy, and test checks
- **Issue/PR templates**: Standardized bug report, feature request, and PR templates
- Cleaned up old/superseded benchmark result files

## [1.0.2] - 2026-01-29

### Fixed
- **Critical VSock Protocol Regression**: Fixed mismatch between enclave and host message framing
  - Unified `VSockMessage.sequence` type to `u32` (was inconsistent `u64` vs `u32`)
  - Standardized `MessageType` enum values across all crates
  - Header size now consistently 9 bytes: `[len:4][type:1][seq:4]`
- **S3WeightStorage**: Added missing `Clone` derive for production builds

### Added
- **ModelLoader**: Comprehensive model loading with integrity verification
  - Ed25519 manifest signature verification
  - SHA-256 hash validation against manifest
  - Safetensors format validation with dtype enforcement (F32/F16/BF16)
- **Audit Logging**: `AuditLogger` with automatic sensitive data sanitization
- **STATUS_SUMMARY.md**: Added detailed progress tracking document

### Verified
- E2E path: `Enclave → VSock → Host Proxy → S3 → Host Proxy → VSock → Enclave`
- Encrypted artifact hash verification working
- Production mode boot health check passing

## [1.0.1] - 2026-01-28

### Added
- Benchmark binary with MiniLM inference
- Attested Execution Receipt (AER) generation
- Real NSM attestation integration

## [1.0.0] - 2026-01-27

### Added
- Initial release with core functionality
- HPKE encrypted sessions
- KMS RecipientInfo with RSA-2048
- Candle inference engine
