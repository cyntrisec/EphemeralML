# Real User Flow Validation Report

**Date:** 2026-02-19
**Version:** v0.2.8 (commit e7ce267)
**Validator:** Adversarial validation, full E2E on GCP Confidential Space
**Evidence:** `evidence/real-user-flow-20260219_180646/`

---

## Pass/Fail Matrix

| Phase | Test | Result | Notes |
|-------|------|--------|-------|
| A | Preflight — gcloud auth | PASS | contact@cyntrisec.com |
| A | Preflight — project/zone | PASS | project-d3c20737-eec2-453d-8e5, us-central1-a |
| A | Preflight — C3 CPU quota | PASS | C3_CPUS: 11 (need 4) |
| A | Preflight — GPU quota | **BLOCKED** | A100=0, H100=0, A100_80GB=0 |
| A | Preflight — tools | PASS | gcloud, docker, cargo, curl, jq, gsutil |
| A | Preflight — disk | PASS | 210G free (threshold: 80G) |
| B | Install from release | PASS | v0.2.8, SHA-256 verified, 12MB |
| B | `ephemeralml --version` | PASS | `ephemeralml 0.2.8` |
| B | `ephemeralml-verify --help` | PASS | Correct usage text |
| B | `ephemeralml-compliance --help` | PASS | verify/collect/export subcommands |
| C | CPU E2E — KMS setup | PASS | Keyring, key, WIP, provider, bucket |
| C | CPU E2E — Package model | PASS | SHA-256: 53aa5117..., 86.7 MB encrypted |
| C | CPU E2E — Deploy (c3-standard-4) | PASS | Container boot ~40s |
| C | CPU E2E — Inference + receipt | PASS | 384-dim embeddings, receipt ID f9e9dffb |
| C | CPU E2E — Receipt verify (--require-destroy-event) | PASS | Ed25519 + destroy evidence |
| C | CPU E2E — Compliance collect (--strict) | PASS | Bundle with attestation + manifest |
| C | CPU E2E — Compliance verify baseline | PASS | 16/16 rules |
| C | CPU E2E — Compliance export | PASS | Signed report |
| C | CPU E2E — Negative: wrong hash | PASS | Container refused to start |
| C | CPU E2E — Negative: wrong KMS key | PASS | Container refused to start |
| D | GPU E2E | **BLOCKED** | No A100/H100 quota (all limits = 0) |
| E | Model reuse — Cycle 1 | PASS | deploy=23s boot=44s infer=3s |
| E | Model reuse — Cycle 2 | PASS | deploy=21s boot=50s infer=1s |
| E | Model reuse — Cycle 3 | PASS | deploy=23s boot=44s infer=0s |
| E | GCS generation unchanged | PASS | All 5 objects identical generation |
| F | Load c=1 (20 req) | PASS | 100% success, 2.83 RPS |
| F | Load c=2 (20 req) | PASS | 100% success, 3.23 RPS |
| F | Load c=4 (20 req) | PASS | 100% success, 2.83 RPS |
| F | Load c=8 (20 req) | PASS | 100% success, 3.44 RPS |
| F | Load c=16 (20 req) | PASS | 100% success, 3.41 RPS |
| G | Wrong model ID | PASS | INVALID: model mismatch |
| G | Wrong model hash | PASS | Container refused to start (Phase C) |
| G | Wrong KMS key | PASS | Container refused to start (Phase C) |
| G | Missing destroy evidence | PASS | INVALID: Ed25519 sig failed + destroy missing |
| G | Freshness/max-age | PASS | INVALID: receipt 2467s old, max 1s |
| G | Network interruption | PARTIAL | No sudo; timeout-based test passed |

**Summary: 31 PASS, 2 BLOCKED (GPU quota), 1 PARTIAL (no sudo)**

---

## CPU vs GPU Comparison

| Metric | CPU (c3-standard-4, TDX) | GPU (a3-highgpu-1g, H100) |
|--------|--------------------------|---------------------------|
| Machine cost | ~$0.21/hr | ~$3.67/hr |
| Model tested | MiniLM-L6-v2 (22.7M) | **BLOCKED** (no quota) |
| Deploy time | ~22s | N/A |
| Boot time | ~44s | N/A |
| Inference latency (p50) | 346ms | N/A |
| Compliance rules | 16/16 | N/A |
| Negative tests | 2/2 | N/A |

GPU testing requires A100_80GB or H100 quota in us-central1 (currently 0).

---

## RPS/Latency Tables (CPU, c3-standard-4)

Each request = fresh HPKE handshake + TDX attestation + inference + receipt + destroy evidence.
No connection reuse. 20 requests per concurrency level.

| Concurrency | Success | RPS | p50 (ms) | p95 (ms) | p99 (ms) | Min (ms) | Max (ms) |
|-------------|---------|-----|----------|----------|----------|----------|----------|
| 1 | 20/20 | 2.83 | 346 | 371 | 408 | 327 | 408 |
| 2 | 20/20 | 3.23 | 585 | 656 | 663 | 534 | 663 |
| 4 | 20/20 | 2.83 | 1,347 | 1,592 | 1,634 | 1,001 | 1,634 |
| 8 | 20/20 | 3.44 | 2,095 | 2,311 | 2,320 | 1,030 | 2,320 |
| 16 | 20/20 | 3.41 | 4,159 | 4,654 | 4,714 | 986 | 4,714 |

**Key observations:**
- **100% success rate** at all concurrency levels (no drops, no errors)
- RPS plateaus at ~3.4 regardless of concurrency — server is single-threaded
- Latency scales linearly with concurrency (queuing effect)
- Consistent p50/p95 spread indicates stable performance

---

## Receipt/Compliance Overhead Table

Measured end-to-end including `cargo run` overhead (binary already compiled).

| Path | Samples | p50 (ms) | Range (ms) | Overhead vs Baseline |
|------|---------|----------|------------|---------------------|
| Inference only (c=1 baseline) | 20 | 346 | 327–408 | — |
| Inference + receipt verify | 5 | 883 | 736–1,106 | +155% |
| Inference + verify + compliance | 3 | 1,422 | 1,422–1,716 | +311% |

**Note:** Verify and compliance overhead includes process spawn cost (~200ms each).
In production with a long-running verifier service, overhead would be significantly lower.

Receipt generation overhead is included in the inference baseline (server generates receipt inline).

---

## Reuse-Across-Redeploy Proof

### Setup
- Model packaged once (Phase C, step 2)
- Encrypted model uploaded to `gs://ephemeralml-models-project-d3c20737-eec2-453d-8e5/models/minilm/`
- 5 GCS objects: config.json, tokenizer.json, model.safetensors.enc, wrapped_dek.bin, manifest.json

### 3 Deploy/Infer/Teardown Cycles (--skip-build)

| Cycle | Deploy (s) | Boot (s) | Inference (s) | Total (s) | Result |
|-------|-----------|---------|---------------|-----------|--------|
| 1 | 23 | 44 | 3 | 219 | PASS |
| 2 | 21 | 50 | 1 | 210 | PASS |
| 3 | 23 | 44 | 0 | 205 | PASS |

### GCS Object Immutability

| Object | Generation (before) | Generation (after 3 cycles) | Changed? |
|--------|--------------------|-----------------------------|----------|
| model.safetensors.enc | 1771517351265881 | 1771517351265881 | No |
| wrapped_dek.bin | 1771517353646236 | 1771517353646236 | No |
| manifest.json | 1771517356016461 | 1771517356016461 | No |

**Conclusion:** Encrypted model is fully reusable across deploy cycles. No re-packaging or re-upload needed.
Average cold-start (deploy + boot): ~68s. Inference after boot: ~1s.

---

## Failures Found

### ~~F1: Verifier exits 0 on INVALID~~ (RETRACTED)

**Severity:** ~~HIGH~~ N/A
**Status:** RETRACTED — original test methodology was flawed.
**Root cause of false finding:** The test piped verifier output through `grep`, which replaced the verifier's exit code with grep's exit code (0 = match found). Direct testing without pipes confirmed: `ephemeralml-verify` correctly exits 0 on VERIFIED and 1 on INVALID.
**Corrected on:** 2026-02-19 (mock-mode hardening audit)

### F2: Server is single-threaded (MEDIUM)

**Severity:** MEDIUM
**Impact:** RPS caps at ~3.4 regardless of available CPU cores (c3-standard-4 has 4 vCPUs)
**Evidence:** RPS identical at c=1 (2.83) and c=16 (3.41). Latency scales linearly with concurrency.
**Fix:** Accept connections concurrently (tokio::spawn per connection) or use a connection pool
**Effort:** Medium (architecture change)

### F3: No GPU quota for validation (MEDIUM)

**Severity:** MEDIUM (blocks customer demos)
**Impact:** Cannot validate GPU path (a3-highgpu-1g) or larger models
**Repro:** `gcloud compute regions describe us-central1 --format=json | jq '.quotas[] | select(.metric | contains("A100"))'`
**Fix:** Request A100_80GB quota increase in us-central1
**Effort:** Low (quota request)

### F4: Client falls back to Mock Mode silently (MEDIUM)

**Severity:** MEDIUM
**Impact:** If client binary built without `--features gcp`, `--gcp` flag is silently ignored and client runs in mock mode
**Repro:**
```bash
cargo run --release --bin ephemeral-ml-client -- --gcp --host <IP> --port 9000 --text "test"
# Output: "EphemeralML Client (Mock Mode)" — should be "GCP Mode"
```
**Expected:** Error if `--gcp` flag used but gcp feature not compiled in
**Fix:** Compile-time error or runtime error when `--gcp` used without feature
**Effort:** Low

### F5: Docker build sends large context without .dockerignore awareness (LOW)

**Severity:** LOW
**Impact:** First Docker build sent 12.15GB context (observed in prior v0.2.8 build). Subsequent builds use cache.
**Mitigation:** `.dockerignore` exists and includes `target/`, `.git/`, `test_assets/llama3/`. Likely caused by Docker legacy builder not respecting nested ignores.
**Fix:** Ensure BuildKit is used (`DOCKER_BUILDKIT=1`) or trim context explicitly
**Effort:** Low

### F6: Receipt model_id is "stage-0" not actual model name (LOW)

**Severity:** LOW
**Impact:** Receipt shows `model_id: "stage-0"` instead of `minilm-l6-v2`. Confusing for auditors.
**Root cause:** Default model-id in mock/CPU mode is the pipeline stage name
**Fix:** Default `--model-id` to directory name or require explicit value
**Effort:** Low

---

## Recommended Fixes (Ordered by Impact/Effort)

| Priority | Finding | Impact | Effort | Recommendation |
|----------|---------|--------|--------|----------------|
| ~~1~~ | ~~F1: Verifier exit code~~ | ~~HIGH~~ | ~~Low~~ | RETRACTED — verifier exits correctly (test methodology was flawed) |
| 1 | F4: Silent mock fallback | MEDIUM | Low | Add compile-time gate or runtime error (FIXED in mock-mode hardening audit) |
| 2 | F3: GPU quota | MEDIUM | Low | Request quota — blocks customer demos |
| 3 | F6: model_id naming | LOW | Low | Better defaults for model naming |
| 4 | F2: Single-threaded server | MEDIUM | Medium | Concurrent connection handling |
| 5 | F5: Docker context size | LOW | Low | Ensure BuildKit, verify .dockerignore |

---

## Cost and Disk Usage Summary

### GCP Costs

| Phase | Instance | Duration | Estimated Cost |
|-------|----------|----------|---------------|
| C — CPU E2E | c3-standard-4 | ~20 min | ~$0.07 |
| E — Reuse (3 cycles) | c3-standard-4 x3 | ~15 min total | ~$0.05 |
| F — Load test | c3-standard-4 | ~10 min | ~$0.04 |
| **Total** | | ~45 min | **~$0.16** |

### Disk Usage

| Checkpoint | Used | Free | Notes |
|-----------|------|------|-------|
| Phase A (start) | 234G | 210G | Baseline |
| Phase C (after E2E) | 236G | 209G | +2G (Docker build) |
| Phase F (end) | 236G | 208G | Stable |
| Final | 236G | 208G | No cleanup needed |

Evidence directory: ~200KB (logs, receipts, bundles)

---

## Evidence Inventory

```
evidence/real-user-flow-20260219_180646/
  phase-a-preflight.log                 # gcloud auth, quota, tools, disk
  phase-b-install.log                   # Release install + binary verification
  phase-c-cpu-e2e.log                   # Full 10-step golden path log
  phase-c-cpu-e2e-evidence/             # 20 files: receipt, bundle, reports, neg tests
    receipt.json                        # Signed receipt (f9e9dffb)
    attestation.bin                     # TDX attestation sidecar
    manifest.json                       # Model manifest
    compliance-bundle.json              # Evidence bundle
    compliance-report.json              # Signed compliance report
    metadata.json                       # Run metadata (10/10 steps)
    negative_wrong_hash_*.txt           # Wrong hash rejection proof
    negative_wrong_key_*.txt            # Wrong KMS key rejection proof
  phase-d-gpu-blocked.log              # GPU quota = 0 documentation
  phase-e-reuse.log                     # 3-cycle reuse test + GCS generation proof
  phase-e-cycle{1,2,3}-receipt.json     # Receipts from each reuse cycle
  phase-f-load.log                      # Load test results + overhead analysis
  phase-f-timings-c{1,2,4,8,16}.csv    # Per-request timing data
  phase-g-break-tests.log              # All 6 break test results
```
