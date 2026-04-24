# ephemeralml-smoke-test

Phase 1 BYOC end-to-end smoke test. Runs doctor preflight, launches the
Cyntrisec enclave, runs a synthetic inference, verifies the AIR v1 receipt
offline, writes the evidence bundle to S3.

**Contract:** `startup-plans/10-operations/byoc-phase-1-ephemeralml-smoke-test-spec-2026-04-23.md`

## Status

Skeleton — CLI, output formatting (text + JSON), 5-stage registry with
fail-fast gating, `--no-upload` branch, evidence bundle types, and error
routing are real and tested. Individual stage probes return
`SKELETON_UNIMPLEMENTED` until the real-AWS deploy + doctor real-probe
implementations are done.

A skeleton run always exits **1** by design. A real run exits 0 only when all
5 stages pass end-to-end against a live deployment.

## The 5 stages (strict order, fail-fast)

1. `doctor` — subprocess `ephemeralml-doctor --json`; must return `overall_status: "pass"` with 6/6 `ok`
2. `enclave_launch` — re-verify EIF cosign + SLSA (TOCTOU close), then `nitro-cli run-enclave`
3. `inference` — VSock to enclave, submit fixed synthetic fixture, receive embedding + AIR v1 receipt
4. `receipt_verify` — in-process 4-layer AIR verification via `ephemeral_ml_common::receipt_verify::verify_receipt`
5. `s3_write` — 9-file evidence bundle uploaded to `s3://{bucket}/smoke-tests/{iso-timestamp}/`

Failure at stage N marks stages N+1..5 as `skipped` with reason `"prior stage failed"`. Result vector always has exactly 5 entries regardless of where failure occurs.

## Flags

| Flag | Purpose |
|---|---|
| `--json` | Machine-readable output |
| `--no-upload` | Run stages 1-4 only; skip stage 5 (CI mode) |
| `--verbose` | Include raw probe data |
| `--stack-name <name>` | Override auto-detected CloudFormation stack |
| `--retain-enclave` | Don't terminate enclave on exit (post-mortem debugging) |

## Exit codes

| Exit | Meaning |
|---|---|
| `0` | All 5 stages passed (or stages 1-4 passed with `--no-upload`) |
| `1` | One stage failed. `failed_stage` named in output |
| `2` | CLI usage error |
| `3` | Infrastructure unreachable |
| `4` | Unexpected internal error |

## Hard constraints (verify in real-probe implementations)

- No real customer data — fixed synthetic fixture only
- No network calls to Cyntrisec-operated infrastructure
- No telemetry / phone-home
- No upload of unverified receipts (stage 4 gates stage 5)
- Enclave ALWAYS torn down on exit (Drop/defer) unless `--retain-enclave`
- No persistent state across runs
- No retries within a stage — if a stage times out, fail; operator re-runs
