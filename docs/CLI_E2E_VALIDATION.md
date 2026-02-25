# CLI E2E Validation Report

**Date:** 2026-02-20
**Branch:** main @ f9f520e (post-merge of PR #32)
**Project:** project-d3c20737-eec2-453d-8e5
**Region:** us-central1-a
**Evidence:** `evidence/cli-e2e-20260220_023458/`

## Summary

| Phase | Description | Result |
|-------|-------------|--------|
| 0 | Safety preflight | **PASS** |
| 1 | CLI surface sanity | **PASS** |
| 2 | Dry-run contract | **PASS** |
| 3 | Init / config resolution | **PASS** |
| 4 | setup-kms validation | **PASS** |
| 5 | Real CPU E2E (GCP TDX) | **PASS** |
| 6 | Negative tests | **PASS** (4/4) |
| 7 | GPU smoke test | **SKIP** (A100 quota=0) |

**Verdict: 7/7 PASS (1 expected SKIP)**

---

## Phase 0 — Safety Preflight

| Check | Result |
|-------|--------|
| Branch | main @ f9f520e |
| Disk free | 187 GB |
| Running instances | 0 |

## Phase 1 — CLI Surface Sanity

All 10 subcommands present: `doctor`, `init`, `setup`, `setup-kms`, `package-model`, `deploy`, `verify`, `teardown`, `e2e`, `release-gate`.

| Check | Result | Evidence |
|-------|--------|----------|
| `ephemeralml gcp --help` | 10 subcommands listed | phase1-gcp-help.txt |
| `ephemeralml gcp deploy --help` | --gpu, --zone, --skip-build, --dry-run, --yes flags | phase1-deploy-help.txt |
| `ephemeralml gcp setup-kms --help` | --image-digest, --allow-broad-binding flags | phase1-setupkms-help.txt |
| `ephemeralml gcp init --help` | --project, --zone, --non-interactive flags | phase1-init-help.txt |
| `ephemeralml gcp doctor` | All checks run | phase1-doctor.txt |

## Phase 2 — Dry-Run Contract

All 4 commands exit 0 with `--dry-run`, print command + env preview, skip preflight.

| Command | Exit | Evidence |
|---------|------|----------|
| `setup --dry-run` | 0 | phase2-setup-dryrun.txt |
| `setup-kms --allow-broad-binding --dry-run` | 0 | phase2-setupkms-dryrun.txt |
| `deploy --dry-run` | 0 | phase2-deploy-dryrun.txt |
| `e2e --dry-run` | 0 | phase2-e2e-dryrun.txt |

## Phase 3 — Init / Config Resolution

| Check | Result | Evidence |
|-------|--------|----------|
| `init --non-interactive` | Generates .env.gcp with project, zone, region, bucket | phase3-init.txt |
| Flag overrides .env.gcp | `--zone us-east1-b` overrides file value | phase3-precedence.txt |
| Region derived from zone | `us-central1-a` → `us-central1` confirmed | phase3-precedence.txt |

## Phase 4 — setup-kms Validation

| Check | Result | Evidence |
|-------|--------|----------|
| No mode flag → exit 1 | Fails with guidance message | phase4-kms-negative.txt |
| `--allow-broad-binding --dry-run` | Exit 0, args = [project, region, --allow-broad-binding] | phase4-kms-broad-dryrun.txt |
| `--image-digest sha256:abc --dry-run` | Exit 0, args = [project, region, sha256:abc] | phase4-kms-digest-dryrun.txt |
| Region confirmed | Uses region (us-central1), not zone (us-central1-a) | phase4-kms-broad-dryrun.txt |

## Phase 5 — Real CPU E2E (GCP Confidential Space, TDX)

Full deployment on `c3-standard-4` (Intel Sapphire Rapids, TDX).

| Step | Result | Duration | Evidence |
|------|--------|----------|----------|
| `setup` | PASS | ~30s | phase5-setup.txt |
| `setup-kms --allow-broad-binding` | PASS | ~15s | phase5-setupkms.txt |
| `package-model` | PASS | ~45s | phase5-package.txt |
| `deploy` | PASS | ~5min | phase5-deploy.txt |
| `verify --allow-unpinned-audience` | PASS | ~15s | phase5-verify.txt |
| Strict verify (--require-destroy-event) | PASS | <1s | phase5-strict-verify.txt |
| `teardown --yes` | PASS | ~10s | phase5-teardown.txt |
| Zero instances after teardown | PASS | — | — |

### Artifacts Captured

| File | Description |
|------|-------------|
| receipt.json | Ed25519-signed inference receipt (VERIFIED) |
| receipt.pubkey | Ephemeral public key (hex) |
| attestation.bin | GCP TDX attestation document |
| manifest.json | Model manifest (MiniLM-L6-v2, KMS-gated) |

### Receipt Details

- **Receipt ID:** 9ff387a3-b603-4ffb-a9f8-2ad94bededec
- **Platform:** tdx-mrtd-rtmr
- **Model:** stage-0 v1.0
- **Execution time:** 66ms
- **Signature:** Ed25519 — PASS
- **Destroy evidence:** 5 actions (explicit_zeroize × 3, drop_on_scope_exit × 2) — PASS
- **Estimated cost:** ~$0.02 (c3-standard-4 on-demand, ~8 min)

### Integration Note

`package-model` and `verify` scripts require env vars (`GCP_KMS_KEY`, `GCP_WIP_AUDIENCE`, `GCP_BUCKET`) that are **outputs** of `setup-kms`, not CLI config inputs. Users must export these after setup-kms. The CLI forwards config-level env vars but does not auto-chain setup-kms outputs to downstream commands. This is a known gap for follow-up.

## Phase 6 — Negative Tests

All negative tests correctly reject invalid inputs with non-zero exit codes.

| Test | Expected | Actual | Exit | Evidence |
|------|----------|--------|------|----------|
| Wrong public key (flipped byte) | Reject | `Cannot decompress Edwards point` | non-zero | phase6-wrong-key.txt |
| Wrong model ID | INVALID | `[FAIL] Model mismatch: 'stage-0' vs 'wrong-model'` | 1 | phase6-wrong-model.txt |
| Wrong measurement type | INVALID | `[FAIL] Measurement type mismatch: 'tdx-mrtd-rtmr' vs 'nitro-pcr'` | 1 | phase6-wrong-measurement.txt |
| Tampered signature | INVALID | `[FAIL] Ed25519 signature verification failed` | 1 | phase6-tampered-receipt.txt |

## Phase 7 — GPU Smoke Test

**SKIP** — NVIDIA_A100_GPUS quota = 0, NVIDIA_A100_80GB_GPUS quota = 0 (requests pending Google approval). L4 quota available but not CC-compatible for this test. Will validate when A100 quota is granted.

---

## Follow-Up Actions

1. **Auto-chain KMS outputs** — After `setup-kms`, persist `GCP_KMS_KEY`, `GCP_WIP_AUDIENCE`, `GCP_BUCKET` to `.env.gcp` so downstream commands pick them up automatically.
2. **GPU E2E** — Re-run Phase 5 with `--gpu` once A100 quota is approved.
3. **Receipt model_id mismatch** — Receipt shows `stage-0` instead of `minilm-l6-v2` from manifest. Align model IDs across server and manifest.
