# AWS Nitro Enclave E2E Validation Report

**Date:** 2026-02-21T19:39–20:45 UTC
**Instance:** i-08e468b0b6f702de0 (m6i.xlarge, us-east-1a)
**Enclave Options:** Enabled

## Environment

| Component | Version |
|-----------|---------|
| Kernel | 4.14.355-280.714.amzn2.x86_64 |
| OS | Amazon Linux 2 (Karoo) |
| Rust | rustc 1.93.1 (01f6ddf75 2026-02-11) |
| Nitro CLI | 1.4.4 |
| Docker | 25.0.14 |
| OpenSSL (vendored) | 3.4.1 (system ships 1.0.2k) |
| EphemeralML | v0.2.9 |
| Model | MiniLM-L6-v2 (22.7M params, 87 MB) |

## Infrastructure

Provisioned via Terraform (`infra/hello-enclave/main.tf`):
- VPC `10.42.0.0/16` + public subnet + IGW
- m6i.xlarge with Nitro Enclaves enabled
- KMS key `639e04b3-33c3-481d-9564-0f7ea2cf65c7` with PCR-bound attestation policy
- IAM role with SSM, KMS, S3 access

## Test Results

### Phase 1: Build (PASS with fixes)

| Step | Status | Notes |
|------|--------|-------|
| Install build deps | PASS | gcc, gcc-c++, openssl-devel, pkg-config, git |
| Install Rust toolchain | PASS | rustup + stable |
| Default-feature build (4 binaries) | PASS | enclave, host, client, compliance — 10m 59s total |
| Production-feature build (enclave) | **FAIL → FIX → PASS** | OpenSSL 1.0.2k too old for `to_vec_padded()`; installed OpenSSL 3.4.1 from source |
| Production-feature build (enclave, 2nd) | **FAIL → FIX → PASS** | `EphemeralKeyPair` missing `Clone` derive; added `#[derive(Clone)]` |
| Production-feature build (kms_proxy_host) | PASS | Properly feature-gated for production |

### Phase 2: EIF Build & Enclave Boot (PASS)

| Step | Status | Notes |
|------|--------|-------|
| Download model from HuggingFace | PASS | 87 MB model.safetensors |
| Docker image build | PASS | ubuntu:22.04 base, ~186 MB EIF |
| nitro-cli build-enclave | PASS | PCR measurements generated (see below) |
| Enclave allocator (4096 MiB, 2 CPUs) | PASS | Needed restart after config change |
| nitro-cli run-enclave (debug mode) | PASS | CID 16, 3072 MiB, 2 CPUs |
| NSM module load | PASS | Hardware random bytes flowing |
| EphemeralML app start | PASS | Production Mode, Candle CPU engine |
| Pipeline worker bind | PASS | control=5000, data_in=5001, data_out=5002 |

### Phase 3: Unit Tests (PASS)

39 tests, 0 failures on EC2 instance:
- 5 KMS simulation tests (identity, decryption, model swap, tamper)
- 5 Candle engine tests (BERT, GGUF, model registration)
- 4 host resilience tests (circuit breaker, rate limit, retry, blindness)
- 3 degradation tests
- 22 verifier API tests (auth, rate limit, receipt verification, multipart upload)

### Phase 4: Full Inference E2E (BLOCKED)

| Step | Status | Blocker |
|------|--------|---------|
| Host orchestrator → Enclave pipeline | **BLOCKED** | `host/src/main.rs` has unconditional mock imports (lines 1, 8) preventing production build |
| Direct mode on Nitro | **N/A** | `--direct` flag only implemented for GCP/TDX and mock modes, not production Nitro |

## PCR Measurements

### Build 1 (original entrypoint)
```
PCR0: f29898383266078e2859af891437b76d210c9058bc7010155168cbfaf9c6f54c717c0db65a8d9027bd8c036dbfaf4901
PCR1: 0343b056cd8485ca7890ddd833476d78460aed2aa161548e4e26bedf321726696257d623e8805f3f605946b3d8b0c6aa
PCR2: 15d7c0a35f1e8ba7aef6071cb67d2f524822ff570a2c0e66694fc4ccaa4f8d1164ee992ed768c4c888373909dc8e3ad2
```

### Build 2 (with --model-dir --direct)
```
PCR0: 5f3dd77dc6b79b5e61beef2d9987acc4cf4cb01c64fe0bf4b0f06151128b37c68cdba4c9efe8a1b29c9fa7258081c94d
PCR1: 0343b056cd8485ca7890ddd833476d78460aed2aa161548e4e26bedf321726696257d623e8805f3f605946b3d8b0c6aa
PCR2: f7dd63399cdc6671c20719a71036682d4ba6bba423794b23a0f8d425cc4c38a9628f41c3f21943d6a3a7d8d004054bf5
```

### Build 3 (with --model-dir only, pipeline mode)
```
PCR0: 39e3c7d3f40d845f42aa52b403bdc691bebc25f489efc4d5e98fa359a478c24bcbd21066c4f851005df5d1b5ebf7aef6
PCR1: 0343b056cd8485ca7890ddd833476d78460aed2aa161548e4e26bedf321726696257d623e8805f3f605946b3d8b0c6aa
PCR2: 0670573caf46d9478f640ad26a6613204d5fe4f7e6b14e3696eb87254d26a819e5eb7cfac59b5f370fad0619deba24d2
```

**Observations:**
- PCR1 (kernel/OS) is stable across all builds (same ubuntu:22.04 base)
- PCR0 (enclave image hash) and PCR2 (application hash) change with entrypoint/binary changes
- PCR values are SHA-384 (48 bytes / 96 hex chars) — correct for Nitro

## Enclave Console Log (excerpt)

```
EphemeralML Enclave v2.0
EphemeralML Enclave (Production Mode)
Using CPU device step="device_init" device="cpu"
Starting connectivity health check step="health_check"
Fetching test-model-001 from S3 via Host Proxy step="model_load" source="s3"
S3 fetch failed (expected if model not uploaded) step="model_load"
  error=Enclave(NetworkError("Failed to connect to host proxy (VSock): Connection reset by peer (os error 104)"))
No EPHEMERALML_EXPECTED_PCR0/1/2 set. Peer Nitro attestation measurements are NOT pinned. step="pcr_pin"
Production stage worker starting step="pipeline" control="127.0.0.1:5000" data_in="127.0.0.1:5001" data_out="127.0.0.1:5002"
```

## Errors Encountered (chronological)

### E1: Missing C++ compiler (FIXED)
```
error occurred in cc-rs: failed to find tool "c++": No such file or directory
```
**Fix:** `sudo yum install -y gcc-c++`

### E2: OpenSSL 1.0.2k too old (FIXED)
```
error[E0599]: no method named `to_vec_padded` found for reference `&BigNumRef`
```
Amazon Linux 2 ships OpenSSL 1.0.2k (2017). The `to_vec_padded()` method requires OpenSSL 1.1.0+.
**Fix:** Built OpenSSL 3.4.1 from source at `/usr/local/openssl3`, set `OPENSSL_DIR`/`OPENSSL_STATIC`/`OPENSSL_LIB_DIR`/`OPENSSL_INCLUDE_DIR` env vars.

### E3: Missing Clone derive on EphemeralKeyPair (FIXED)
```
error[E0277]: the trait `Clone` is not implemented for `EphemeralKeyPair`
```
`NSMAttestationProvider` derives `Clone` but its field `EphemeralKeyPair` doesn't.
**Fix:** Added `Clone` to `#[derive(Debug, ZeroizeOnDrop)]` → `#[derive(Debug, Clone, ZeroizeOnDrop)]` in `enclave/src/attestation.rs:36`.

### E4: .dockerignore excludes target/ (FIXED)
```
failed to compute cache key: "/target/release/ephemeral-ml-enclave": not found
```
**Fix:** Built Docker image from a clean `/tmp/eif-build/` context with copied binary.

### E5: ec2-user not in `ne` group (FIXED)
```
File: '/dev/nitro_enclaves', failing operation: 'Open'
```
**Fix:** `sudo usermod -aG ne ec2-user` then `sg ne -c "nitro-cli ..."`.

### E6: Missing log directory (FIXED)
```
File: '/var/log/nitro_enclaves/nitro_enclaves.log', failing operation: 'Open'
```
**Fix:** `sudo mkdir -p /var/log/nitro_enclaves && sudo touch ... && sudo chmod 666 ...`

### E7: Host binary unconditional mock imports (NOT FIXED — code gap)
```
error[E0432]: unresolved import `ephemeral_ml_host::mock`
error[E0432]: unresolved imports `confidential_ml_transport::MockProvider`, `confidential_ml_transport::MockVerifier`
```
`host/src/main.rs` lines 1 and 8 import mock types without `#[cfg(feature = "mock")]` guards. The `#[cfg(feature = "production")]` block in main() simply prints an error message and exits — the host binary has no production orchestrator.

### E8: No --direct mode in Nitro production path (code gap)
The `--direct` flag is only supported in GCP/TDX and mock code paths. The production Nitro path (`#[cfg(feature = "production")]`) always enters pipeline mode, requiring a host orchestrator.

## Code Gaps Found

1. **`host/src/main.rs:1,8`** — Unconditional mock imports prevent production build. Need `#[cfg(feature = "mock")]` guards.
2. **`enclave/src/main.rs`** — Production Nitro path lacks `--direct` mode support. Only pipeline mode available.
3. **`enclave/src/attestation.rs:36`** — `EphemeralKeyPair` missing `Clone` derive (fixed during test).
4. **OpenSSL version requirement** — crates.io `confidential-ml-transport` v0.4.0 requires OpenSSL 1.1.0+ but Amazon Linux 2 ships 1.0.2k. Consider adding `openssl-sys/vendored` feature flag.

## Summary

| Category | Result |
|----------|--------|
| Infrastructure provisioning | PASS |
| Production binary build | PASS (after 3 fixes) |
| EIF build with PCR measurements | PASS |
| Enclave boot on Nitro hardware | PASS |
| NSM attestation module | PASS (loaded, random bytes flowing) |
| Inference engine initialization | PASS (Candle CPU) |
| Pipeline worker start | PASS |
| Unit tests | PASS (39/39) |
| Full inference through pipeline | BLOCKED (host code gap) |
| Receipt generation | BLOCKED (depends on inference) |
| Receipt verification | BLOCKED (depends on receipt) |
| Compliance check | BLOCKED (depends on receipt) |
| KMS attestation-bound decrypt | NOT TESTED (no model uploaded to S3) |

**Overall: 8/13 checks PASS, 4 BLOCKED by host code gap, 1 NOT TESTED.**

The enclave boots and runs in production mode on real Nitro hardware. The blocking issue is the host orchestrator binary, which needs production feature gates added to complete the full inference pipeline.
