# Changelog

## [0.2.8] - 2026-02-19

### Added
- **Compliance evidence completeness**: Server now returns boot attestation bytes (base64) and model manifest JSON as sidecar fields in the inference response. Client saves them as `/tmp/ephemeralml-attestation.bin` and `/tmp/ephemeralml-manifest.json`.
- **`collect --manifest`**: New flag to include model manifest JSON in compliance bundles.
- **`collect --strict`**: Fail if attestation or manifest evidence is missing (required by ATT-001, ATT-002, MODEL-002, KEY-001).
- **`collect --auto-discover`**: Scan a directory for `*.bin` attestation and `manifest.json` files, auto-adding them to the bundle.
- **Enriched destroy evidence**: Receipts now include 5 destroy actions (3 `explicit_zeroize` + 2 `drop_on_scope_exit`) covering output bytes, output tensor, generated text, session DEK, and ephemeral keypair.
- **6 new conformance tests**: CT-020 (strict receipt-only fails), CT-021 (complete bundle types), CT-022 (auto-discover), CT-023 (all 16 baseline rules pass), CT-024 (ATT-002 hash mismatch), CT-025 (enriched destroy evidence).
- **E2E script**: Updated to copy sidecar evidence files and use `--strict`/`--manifest`/`--attestation` flags in compliance collect.

### Changed
- **Version bump**: All crates from 0.2.7 to 0.2.8
- **`base64` dependency**: Now non-optional in enclave crate (was gcp-only) to support sidecar encoding in all modes.
- **`DirectInferenceResponse`**: New optional fields `boot_attestation_b64` and `model_manifest_json`.
- **`InferenceResult`/`InferenceHandlerOutput`**: Extended with the same optional fields on the client side.

### Security
- Boot attestation bytes are captured at boot time and passed immutably via `Arc<Vec<u8>>` — no copies or mutations after initial capture.
- Sidecar fields are `Option<T>` — mock mode returns `None`, no synthetic evidence is generated.
- `--strict` mode enforces fail-closed collection: bundles missing any evidence type referenced by baseline rules exit non-zero.

## [0.2.7] - 2026-02-19

### Added
- **Destroy evidence in receipts**: `DestroyEvidence` and `DestroyAction` types in receipt schema. Receipts from v0.2.7+ enclaves include cryptographic proof of data cleanup (session key zeroization, DEK wipe, buffer clearing).
- **Verifier strict mode**: `--require-destroy-event` flag on `ephemeralml verify`. When set, verification fails if destroy evidence is absent or empty. Fail-closed by default.
- **DESTROY-001 compliance rule**: New rule in baseline and HIPAA profiles. Checks that receipts contain destroy evidence with at least one cleanup action.
- **EML-DESTROY-001 baseline control**: Destroy evidence mapped to baseline control registry.
- **HIPAA audit mapping**: DESTROY-001 added to HIPAA-AUDIT-001 control (164.312(b) audit controls).
- **Zeroization throughout**: Enclave request/response buffers, DEK/model decrypt buffers, transport payload buffers, and pipeline stage intermediates all wrapped in zeroizing types.
- **Security model documentation**: `docs/SECURITY_MODEL.md` and `docs/PRODUCTION_GCP.md` updated with data destruction guarantees, best-effort vs guaranteed behavior, and trust model boundaries.
- **6 new conformance tests**: CT-017 (missing destroy evidence fails), CT-018 (empty actions fails), CT-019 (verifier require-destroy-event flag positive/negative/strict).

### Changed
- **Version bump**: All crates from 0.2.5 to 0.2.7
- **Baseline profile**: 16 rules (was 15), 16 controls (was 15)
- **HIPAA audit control**: Now includes DESTROY-001 alongside SIG-001, SEQ-001, CHAIN-001

### Security
- Destroy evidence is backward-compatible: old receipts without `destroy_evidence` deserialize successfully (`Option<DestroyEvidence>`, `#[serde(default)]`).
- Fail-closed: `--require-destroy-event` defaults to off; when enabled, missing evidence is a hard verification failure.

## [0.2.5] - 2026-02-18

### Added
- **API key authentication**: Verify endpoints require `Authorization: Bearer <key>` or `X-API-Key: <key>`. Fail-closed: startup fails without `--api-key` or `--insecure-no-auth`.
- **Per-IP rate limiting**: 60 req/min/IP default via `--rate-limit`. Returns 429 when exceeded. Health endpoint exempt.
- **CORS tightening**: With auth enabled, startup fails if no `--cors-origin` unless `--allow-permissive-cors` is set.
- **New policy fields in verifier API**: `expected_attestation_source` and `expected_image_digest` on both JSON and multipart endpoints.
- **Verifier API documentation**: `docs/verifier-api.md` with auth, rate limits, policy fields, curl examples.
- **12 new tests**: Auth success/failure (Bearer + X-API-Key), rate limit enforcement, policy field acceptance/skip, backward compatibility, health/landing auth exemption.

### Changed
- **Version bump**: All crates from 0.2.4 to 0.2.5

### Security
- No silent insecure defaults. Auth, rate limiting, and CORS require explicit opt-out with loud warnings.
- New env vars: `EPHEMERALML_VERIFIER_API_KEY`, `EPHEMERALML_VERIFIER_NO_AUTH`, `EPHEMERALML_VERIFIER_RATE_LIMIT`.
- New CLI flags: `--api-key`, `--insecure-no-auth`, `--rate-limit`, `--allow-permissive-cors`.

## [0.2.4] - 2026-02-18

### Fixed
- **Clippy `--tests` warnings**: Fixed `clone_on_copy`, `useless_conversion`, `redundant_field_names`, `needless_borrows_for_generic_args` in enclave test code (`model_loader.rs`, `pipeline_integration_test.rs`)
- **Dead code lint in test helpers**: Added `#[allow(dead_code)]` to `MockHttpServer` (used across modules but clippy `--tests` flags it)
- **Stale doc references**: Removed remaining `--allow-synthetic-transport` / `ALLOW_SYNTHETIC_TRANSPORT` mentions from `docs/GCP_HARDWARE_TEST_REPORT.md`

### Changed
- **Version bump**: All crates from 0.2.2 to 0.2.4

## [0.2.2] - 2026-02-18

### Fixed
- **GCP deploy scopes**: Changed from narrow scopes to `cloud-platform` (fixes 403 on Confidential Space)
- **Fail-closed attestation on CS**: CS mode now uses Launcher JWT via `CsTransportAttestationBridge` (configfs-tsm is not exposed inside CS containers)
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
- **`--allow-synthetic-transport` flag**: Added in 0.2.0, removed in 0.2.3 (dead code — CS mode uses Launcher JWT via `CsTransportAttestationBridge`, `--synthetic` controls TeeAttestationProvider)

### Changed
- **Version bump**: All crates from 0.1.0 to 0.2.0
- **QUICKSTART.md**: Restructured to lead with 30-second verify, 5-minute local demo, and full GCP GPU deployment
- **Dockerfiles**: Added launch policy label

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
