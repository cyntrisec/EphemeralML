# Changelog

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
