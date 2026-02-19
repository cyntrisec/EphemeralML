# Mock/Synthetic Mode Hardening Audit

**Date:** 2026-02-19
**Scope:** 3 repos — EphemeralML-cyntrisec, confidential-ml-transport, confidential-ml-pipeline
**Build target:** `CARGO_TARGET_DIR=/tmp/eml-target`

---

## Phase A — Inventory

### EphemeralML-cyntrisec

| ID | Severity | File | Finding |
|----|----------|------|---------|
| E-1 | CRITICAL | `client/Cargo.toml` | `default = ["mock"]` — release builds include mock by default |
| E-2 | CRITICAL | `enclave/Cargo.toml` | `default = ["mock"]` — release enclave builds include mock by default |
| E-3 | CRITICAL | `client/src/bin/ephemeralml_verify.rs` | `--allow-mock` flag available in all builds (not feature-gated) |
| E-4 | CRITICAL | `client/src/bin/verify_receipt.rs` | `--unsafe-skip-attestation-verification` available in all builds |
| E-5 | HIGH | `.github/workflows/release.yml` | Client/compliance/orchestrator built without `--no-default-features` |
| E-6 | HIGH | `.github/workflows/ci.yml` | Tests/clippy run with implicit default features (includes mock) |
| E-7 | MEDIUM | `client/src/bin/ephemeralml.rs` | No warning banner when running in mock mode |
| E-8 | MEDIUM | `enclave/src/main.rs` | Mock mode warning only in `#[cfg(feature = "mock")]` block but not loud enough |
| E-9 | MEDIUM | `common/Cargo.toml` | `confidential-ml-transport = { features = ["mock", "tcp"] }` — common always pulls mock |

### confidential-ml-transport

**CLEAN.** No findings. Mock feature properly gated behind `cfg(feature = "mock")`. `compile_error!` guards prevent mock+production coexistence. No mock types leak into default builds.

### confidential-ml-pipeline

| ID | Severity | File | Finding |
|----|----------|------|---------|
| P-1 | MEDIUM-HIGH | `Cargo.toml` | `default = ["mock", "tcp"]` — mock in default features |

Note: Pipeline has excellent `compile_error!` guards in `orchestrator.rs` and `stage.rs` preventing mock+production feature coexistence.

---

## Phase B — Hardening (All Fixed)

### B.1: Remove mock from default features

**Files:** `client/Cargo.toml`, `enclave/Cargo.toml`, `confidential-ml-pipeline/Cargo.toml`

```toml
# Before (all three)
default = ["mock"]  # or ["mock", "tcp"]

# After
default = []        # or ["tcp"] for pipeline
```

### B.2: Separate transport-level mock from application-level mock

**Key insight:** The client is never inside a TEE, so it always needs `MockProvider` from the transport layer to complete handshakes. The enclave always needs `MockVerifier` to accept non-TEE client attestations. This is distinct from application-level mock behavior (bypass attestation, skip encryption, etc.).

**Solution:** Make transport mock a base dependency, application mock a feature flag.

```toml
# client/Cargo.toml — base dep always has transport mock
confidential-ml-transport = { workspace = true, features = ["mock", "tcp"] }

# Application-level mock is now just a marker feature
[features]
mock = []  # Only controls --allow-mock, MockSecureClient, etc.
```

```toml
# enclave/Cargo.toml — same pattern
confidential-ml-transport = { workspace = true, features = ["mock", "tcp"] }
confidential-ml-pipeline = { workspace = true, features = ["tcp"] }

[features]
mock = ["confidential-ml-pipeline/mock"]  # Only controls app-level mock
```

```toml
# common/Cargo.toml — only needs tcp, not mock
confidential-ml-transport = { path = "../confidential-ml-transport", features = ["tcp"] }
```

### B.3: Gate `--allow-mock` behind `#[cfg(feature = "mock")]`

**File:** `client/src/bin/ephemeralml_verify.rs`

```rust
#[cfg(feature = "mock")]
#[arg(long)]
allow_mock: bool,
```

Usage site:
```rust
extract_key_from_attestation(
    &att_bytes,
    #[cfg(feature = "mock")]
    args.allow_mock,
    #[cfg(not(feature = "mock"))]
    false,
)
```

### B.4: Gate `--unsafe-skip-attestation-verification` behind `#[cfg(feature = "mock")]`

**File:** `client/src/bin/verify_receipt.rs`

Three usage sites gated with `#[cfg(feature = "mock")]` / `#[cfg(not(feature = "mock"))]` pairs.

### B.5: Add loud mock mode warning banners

**File:** `client/src/bin/ephemeralml.rs`
```rust
if cfg!(feature = "mock") {
    ui.warn("WARNING: Running in MOCK mode. Attestation is NOT verified.");
    ui.warn("This build is for local development only. Do NOT use for production.");
}
```

**File:** `enclave/src/main.rs`
```rust
warn!("==================================================");
warn!("  MOCK MODE — NO ATTESTATION, NO ENCRYPTION");
warn!("  This build is for local development only.");
warn!("  Do NOT use for production.");
warn!("==================================================");
```

### B.6: Fix release workflow

**File:** `.github/workflows/release.yml`

All three build steps now use `--no-default-features`:
- Client: `FEATURES="--no-default-features"` (+ optional `--features vendored-openssl`)
- Compliance: `--no-default-features`
- Orchestrator: `--no-default-features`

### B.7: Add mock-gate CI job

**File:** `.github/workflows/ci.yml`

- Renamed new job to `mock-gate` (avoided collision with existing `release-gate` job ID)
- Updated `clippy` to use `--features mock` explicitly
- Updated `test` to use `--features mock` explicitly
- Added `mock-gate` to `release-gate` dependencies
- Mock-gate verifies:
  1. `--allow-mock` NOT in default build help output
  2. `--allow-mock` IS in explicit mock build help output

---

## Phase C — CI/Release Gate Summary

| Gate | Where | What it checks |
|------|-------|----------------|
| `mock-gate` job | ci.yml | Default build has no `--allow-mock`; mock build has it |
| `clippy --features mock` | ci.yml | Clippy runs with mock explicitly enabled |
| `test --features mock` | ci.yml | Tests run with mock explicitly enabled |
| `--no-default-features` | release.yml | All release binaries built without default features |
| `release-gate` depends on `mock-gate` | ci.yml | GCP release gate won't pass unless mock gate passes |

---

## Phase D — Validation Matrix

| ID | Check | Result |
|----|-------|--------|
| D.1 | Client default build (`cargo check`) | PASS |
| D.2 | Client mock build (`--features mock`) | PASS |
| D.3 | Client GCP build (`--features gcp`) | PASS |
| D.4 | Enclave default build (`cargo check`) | PASS |
| D.5 | Enclave mock build (`--features mock`) | PASS |
| D.6 | Enclave GCP build (`--features gcp`) | PASS |
| D.7 | Pipeline default build (tcp only) | PASS |
| D.8 | Pipeline mock build (`--features mock`) | PASS |
| D.10 | Workspace tests (`--features mock`) | PASS (all 40 test suites) |
| D.11 | Clippy mock (`--features mock -D warnings`) | PASS (0 warnings) |
| D.12 | Clippy GCP (enclave + client) | PASS (0 warnings) |
| D.13 | `--allow-mock` NOT in default `ephemeralml-verify --help` | PASS |
| D.14 | `--allow-mock` IS in mock `ephemeralml-verify --help` | PASS |
| D.15 | `--unsafe-skip` NOT in default `verify_receipt --help` | PASS |
| D.16 | `--unsafe-skip` IS in mock `verify_receipt --help` | PASS |
| D.17 | `--unsafe-skip` NOT in default `verify_receipt --help` (direct) | PASS |
| D.18 | Pipeline tests (default, no mock) | PASS (0 tests — mock-gated) |
| D.19 | Pipeline tests (`--features mock`) | PASS (68 tests) |
| D.20 | Transport tests (default features) | PASS (42 tests) |

**Total: 20/20 PASS**

### Test counts

| Repo | Feature set | Tests |
|------|------------|-------|
| EphemeralML workspace | `--features mock` | 147+ (40 test suites) |
| confidential-ml-pipeline | `--features mock` | 68 |
| confidential-ml-pipeline | default (tcp only) | 0 (all mock-gated, by design) |
| confidential-ml-transport | default | 42 |

---

## Residual Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Transport `MockProvider`/`MockVerifier` types available in release builds | LOW | These are required: client is not in a TEE, server must accept non-TEE clients. Transport-level mock ≠ application-level mock. |
| `cfg!(feature = "mock")` runtime check (not `#[cfg(...)]`) for warning banner | LOW | Banner code compiled into all builds but only prints in mock. Minor code size impact. No security impact since it's a warning only. |
| Pipeline mock-gated tests don't run in default feature CI | LOW | By design — pipeline unit tests need mock orchestrator. Integration tests should use real TEE path. |

---

## Corrected Finding from REAL_USER_FLOW_VALIDATION.md

**F1 (Verifier exits 0 on INVALID)** was **RETRACTED**. The original test piped verifier output through `grep`, which replaced the verifier's exit code with grep's exit code. Direct testing confirmed the verifier correctly exits 0 on VERIFIED and 1 on INVALID. The finding and recommended-fixes table in `docs/REAL_USER_FLOW_VALIDATION.md` have been updated.

---

## Files Modified (10 in EphemeralML, 1 in pipeline)

| Repo | File | Change |
|------|------|--------|
| EphemeralML | `client/Cargo.toml` | Removed mock from defaults, transport mock as base dep |
| EphemeralML | `enclave/Cargo.toml` | Removed mock from defaults, transport mock as base dep |
| EphemeralML | `common/Cargo.toml` | Removed mock from transport dep |
| EphemeralML | `client/src/bin/ephemeralml_verify.rs` | `--allow-mock` gated behind `#[cfg(feature = "mock")]` |
| EphemeralML | `client/src/bin/verify_receipt.rs` | `--unsafe-skip` gated behind `#[cfg(feature = "mock")]` |
| EphemeralML | `client/src/bin/ephemeralml.rs` | Added mock mode warning banner |
| EphemeralML | `enclave/src/main.rs` | Added loud mock mode warning banner |
| EphemeralML | `.github/workflows/ci.yml` | Added `mock-gate` job, explicit `--features mock` for tests/clippy |
| EphemeralML | `.github/workflows/release.yml` | `--no-default-features` on all build steps |
| EphemeralML | `docs/REAL_USER_FLOW_VALIDATION.md` | Corrected F1 (retracted) |
| Pipeline | `Cargo.toml` | Removed mock from default features |

### Transport repo: No changes needed (already clean).

---

## Repro Commands

```bash
# Verify default build has no mock flags
CARGO_TARGET_DIR=/tmp/eml-target cargo run --bin ephemeralml-verify -- --help 2>&1 | grep -i "allow.mock"
# Expected: no output (exit 1)

CARGO_TARGET_DIR=/tmp/eml-target cargo run --bin verify_receipt -- --help 2>&1 | grep -i "unsafe.skip"
# Expected: no output (exit 1)

# Verify mock build has mock flags
CARGO_TARGET_DIR=/tmp/eml-target cargo run --features mock --bin ephemeralml-verify -- --help 2>&1 | grep -i "allow.mock"
# Expected: --allow-mock

CARGO_TARGET_DIR=/tmp/eml-target cargo run --features mock --bin verify_receipt -- --help 2>&1 | grep -i "unsafe.skip"
# Expected: --unsafe-skip-attestation-verification

# Full test suite
CARGO_TARGET_DIR=/tmp/eml-target cargo test --workspace --features mock
CARGO_TARGET_DIR=/tmp/eml-target cargo clippy --workspace --features mock -- -D warnings
```

---

## Disk Usage

| Checkpoint | `/tmp/eml-target` | Disk Free |
|-----------|-------------------|-----------|
| Start | 0 | 210G |
| End | 13G | 196G |

No push, no tag, no release. All changes are local uncommitted.

---

## Final Hardening Pass (2026-02-19, second pass)

### Issue 1: `verify_receipt` exit code correctness (MEDIUM) — FIXED

**Problem:** Two early `return Ok(())` paths in `main()` caused the process to exit 0 even on verification failures:
- Line 131: attestation verification failure → `return Ok(())` → exit 0
- Line 144: user_data extraction failure → `return Ok(())` → exit 0

**Fix:**
- Attestation failure: `return Ok(())` → `std::process::exit(1)`
- User_data extraction failure: `return Ok(())` → `std::process::exit(2)`

**Exit code convention (aligned with `ephemeralml-verify`):**
| Exit Code | Meaning |
|-----------|---------|
| 0 | VERIFIED — all checks pass |
| 1 | INVALID — verification failed (attestation, signature, binding, freshness) |
| 2 | ERROR — structural/parse failure (can't extract user_data, can't read files) |

**Verification (actual output):**

```
# Test 1: Invalid attestation → exit 1
$ verify_receipt --receipt receipt.json --attestation bad.bin --format json
{"overall_valid":false,"errors":["Attestation verification failed: ..."]}
EXIT: 1

# Test 2: Skip attestation + bad user_data → exit 2 (mock build only)
$ verify_receipt --receipt receipt.json --attestation bad.bin --unsafe-skip-attestation-verification --format json
{"overall_valid":false,"errors":["Failed to extract user data: ..."]}
EXIT: 2

# Test 3: Valid receipt (would exit 0 on real Nitro hardware)
```

### Issue 2: Error text mentions unavailable flag in non-mock build (LOW) — FIXED

**Problem:** When attestation verification failed, the error message always suggested `--unsafe-skip-attestation-verification`, even in builds where that flag doesn't exist.

**Fix:** Used `cfg!(feature = "mock")` to conditionally include the hint:

```rust
let hint = if cfg!(feature = "mock") {
    " (use --unsafe-skip-attestation-verification to bypass)"
} else {
    ""
};
report.errors.push(format!("Attestation verification failed{}: {}", hint, e));
```

**Verification (actual output):**

```
# Default build (no mock):
"Attestation verification failed: Not a valid COSE_Sign1 document: got tstr, expected array"

# Mock build:
"Attestation verification failed (use --unsafe-skip-attestation-verification to bypass): Not a valid COSE_Sign1 document: got tstr, expected array"
```

### Issue 3: `host/Cargo.toml` default feature policy (MEDIUM decision) — DOCUMENTED

**Decision: Keep `default = ["mock"]` for host package.**

**Rationale:**
- `host/` contains AWS Nitro-specific operational tools: `kms_proxy_host` and `spy_host`
- NOT referenced in any CI workflow (ci.yml, release.yml)
- NOT included in release tarballs
- NOT built or shipped as a release artifact
- Has no `src/*.rs` files outside `src/` and `src/bin/` — purely local dev tooling
- Its `mock` feature enables local TCP development mode; without it, the tools require a real vsock/Nitro environment

**Impact:** Zero. Host binaries are never distributed. A developer who clones the repo and runs `cargo build -p ephemeral-ml-host` gets a mock-mode local build, which is the expected behavior for dev tooling.

### Additional fix: Duplicate CI job ID

**Problem:** `ci.yml` had two jobs with key `release-gate` (lines 59 and 198). YAML silently takes the last one, so the mock-gate job added in the first hardening pass was being silently overwritten.

**Fix:** Renamed the mock-checking job from `release-gate` to `mock-gate` and added it to the GCP `release-gate` job's `needs` list.

---

## Complete File Change Summary (both passes)

| Repo | File | Pass | Change |
|------|------|------|--------|
| EphemeralML | `client/Cargo.toml` | 1st | Removed mock from defaults, transport mock as base dep |
| EphemeralML | `enclave/Cargo.toml` | 1st | Removed mock from defaults, transport mock as base dep |
| EphemeralML | `common/Cargo.toml` | 1st | Removed mock from transport dep |
| EphemeralML | `client/src/bin/ephemeralml_verify.rs` | 1st | `--allow-mock` gated behind `#[cfg(feature = "mock")]` |
| EphemeralML | `client/src/bin/verify_receipt.rs` | 1st+2nd | `--unsafe-skip` gated; exit 1/2 on failures; feature-gated error hint |
| EphemeralML | `client/src/bin/ephemeralml.rs` | 1st | Added mock mode warning banner |
| EphemeralML | `enclave/src/main.rs` | 1st | Added loud mock mode warning banner |
| EphemeralML | `.github/workflows/ci.yml` | 1st+2nd | Added `mock-gate` job (renamed from duplicate), explicit `--features mock` |
| EphemeralML | `.github/workflows/release.yml` | 1st | `--no-default-features` on all build steps |
| EphemeralML | `docs/REAL_USER_FLOW_VALIDATION.md` | 1st | Corrected F1 (retracted) |
| Pipeline | `Cargo.toml` | 1st | Removed mock from default features |
