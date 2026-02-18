# GCP Hardware Test Report — v0.2.0

**Date:** 2026-02-18
**Project:** `project-d3c20737-eec2-453d-8e5`
**Zone:** `us-central1-a`
**Machine:** `c3-standard-4` (Intel Sapphire Rapids, TDX)
**Image:** `us-docker.pkg.dev/project-d3c20737-eec2-453d-8e5/ephemeralml/enclave:v0.2.0`

## Test Result: PASS

Full golden path verified on real GCP Confidential Space hardware:
- Deploy to Confidential Space (c3-standard-4, TDX)
- MiniLM inference (384-dim embeddings, 79ms)
- Ed25519-signed receipt generation
- Receipt verification (signature PASS, measurements PASS)

## Errors Encountered and Fixes

### Error 1: Insufficient OAuth Scopes (403)

**Symptom:** Container launcher failed immediately with:
```
failed to create REST verifier client: listing regions in project "...":
googleapi: Error 403: Request had insufficient authentication scopes.
```

**Root Cause:** `deploy.sh` specified narrow scopes:
```bash
--scopes=devstorage.read_only,cloudkms,logging.write,monitoring.write
```
The Confidential Space Launcher needs the `confidentialcomputing` API scope to generate attestation tokens via the REST verifier client.

**Fix:** Changed `deploy.sh` to use `cloud-platform` scope:
```bash
--scopes=cloud-platform
```
The service account's IAM bindings still constrain actual access; the broad scope just means "whatever IAM allows."

**User Impact:** Any user deploying EphemeralML would have hit this on first deploy. Fixed in `deploy.sh`.

---

### Error 2: Fail-Closed Attestation Blocks All CS Deployments

**Symptom:** Container started but immediately exited because configfs-tsm was unavailable and no Launcher JWT fallback existed.

**Root Cause:** On Confidential Space, configfs-tsm (`/sys/kernel/config/tsm/report`) is **never** exposed inside the container. The CS Launcher handles attestation via its own socket (`/run/container_launcher/teeserver.sock`), not the kernel TSM ABI. Our fail-closed check was correct for non-CS platforms but too aggressive for CS.

**Fix:** Added `CsTransportAttestationBridge` which uses the Launcher JWT for transport attestation when configfs-tsm is unavailable. No additional flags required — the bridge auto-detects CS mode.

**User Impact:** Every CS deployment would have failed without the bridge. Fixed in the transport attestation path.

---

### Error 3: Empty Env Var Treated as Set (model hash crash)

**Symptom:** Container crashed with:
```
Fatal: --expected-model-hash must be 64 hex chars (32 bytes), got 0
```

**Root Cause:** `Dockerfile.gcp` sets `EPHEMERALML_EXPECTED_MODEL_HASH=""` (empty string). Clap reads this as `Some("")`, not `None`. `hex::decode("")` returns an empty vec (0 bytes), triggering the 32-byte length check.

This is a general pattern: Dockerfile `ENV FOO=""` + clap `env = "FOO"` with `Option<String>` yields `Some("")`, not `None`.

**Fix:** Added empty-string guard in `enclave/src/main.rs`:
```rust
// Before:
Some(hex_str) => { ... }
// After:
Some(hex_str) if !hex_str.is_empty() => { ... }
```

Also fixed similar pattern for `EPHEMERALML_MODEL_SIGNING_PUBKEY`:
```rust
// Before:
std::env::var("EPHEMERALML_MODEL_SIGNING_PUBKEY").is_ok()
// After:
std::env::var("EPHEMERALML_MODEL_SIGNING_PUBKEY")
    .map(|v| !v.is_empty()).unwrap_or(false)
```

**User Impact:** Any CS deployment with default ENV values would crash. Fixed in `enclave/src/main.rs`.

---

### Error 4: Request Hash Mismatch (client verification failure)

**Symptom:** Inference succeeded but client rejected the receipt:
```
Inference failed: Receipt request_hash does not match sent request
```

**Root Cause:** Hash computation mismatch:
- **Client:** `SHA256(serde_json::to_vec(&full_input_struct))` — hashes the entire JSON payload
- **Enclave:** `SHA256(request.input_data)` — hashed only the `input_data` field

The client sends `{"model_id":"stage-0","input_data":"text...","generate":false}` and hashes all of it. The enclave deserialized that JSON, extracted `request.input_data`, and hashed only the text.

**Fix:** Changed `enclave/src/server.rs` to hash the full request bytes:
```rust
// Before (line 299):
request_plaintext: &request.input_data,
// After:
request_plaintext: bytes,  // full serialized request
```

**User Impact:** Every inference request would fail the receipt verification added in the security fixes. Fixed in `enclave/src/server.rs`.

---

## GPU Test: PASS

**Machine:** `a3-highgpu-1g` (1x NVIDIA H100 80GB, Spot, TDX + CC)
**Image family:** `confidential-space-preview-cgpu`
**Image:** `us-docker.pkg.dev/project-d3c20737-eec2-453d-8e5/ephemeralml/enclave:v0.2.0-gpu`

- CUDA detected and used (gpu_id=0)
- Model loaded in 555ms on GPU
- Inference: 384-dim MiniLM embeddings returned
- Receipt: `de07f7e9-c497-488b-add1-c0f75b173bda`
- Verification: Signature PASS, Measurements PASS
- No additional bugs found on GPU path

**Quota note:** Project needed `PREEMPTIBLE_NVIDIA_H100_GPUS` quota (3 approved via prior request) and `PREEMPTIBLE_CPUS >= 26` in `us-central1`.

---

## Files Changed

| File | Change |
|------|--------|
| `scripts/gcp/deploy.sh` | `--scopes=cloud-platform` |
| `enclave/src/main.rs` | Empty-string guards for `expected_model_hash` and `model_signing_pubkey` |
| `enclave/src/server.rs` | Hash full request bytes for receipt `request_hash` |

## Checklist for Users

Before deploying EphemeralML v0.2.0 on GCP Confidential Space:

1. Enable APIs: `compute`, `cloudkms`, `artifactregistry`, `iam`, `storage`, `confidentialcomputing`
2. Create service account with `cloud-platform` scope
3. Create firewall rule for TCP 9000-9002
4. Build and push Docker image to Artifact Registry
5. Ensure Artifact Registry repo uses `us` (multi-region) or same region as zone
6. For GPU: request `NVIDIA_H100_80GB_GPUS` quota in your region

## Evidence

- Receipt: `98aee3e7-326a-4929-a695-42a96f407fa6`
- Model: MiniLM-L6-v2 (22.7M params, 384-dim)
- Inference time: 79ms
- Image digest: `sha256:068c3cdf32e2c09a263858094e079955c3abb384af3749700a7047c53e88d302`
