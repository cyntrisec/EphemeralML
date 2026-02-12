# Changelog

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
