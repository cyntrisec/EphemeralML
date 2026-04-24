# ephemeralml-doctor

Phase 1 BYOC preflight check. Verifies that a deployed Cyntrisec pilot host is
ready to run inference before `ephemeralml-smoke-test` exercises it.

**Contract:** `startup-plans/10-operations/byoc-phase-1-ephemeralml-doctor-spec-2026-04-23.md`

## Status

Skeleton — the CLI, output formatting, error routing, and check registry are
real and tested. The six check implementations return
`check_code: "SKELETON_UNIMPLEMENTED"` until the Phase 1 real-AWS deploy run
produces the concrete outputs needed to exercise the real probes.

A skeleton run always exits **1** (check failures) by design. A real run
exits 0 only when all six checks pass against a live deployment.

## Running

```bash
# Default — text output, all six checks
sudo /opt/cyntrisec/bin/ephemeralml-doctor

# JSON for CI / support bundles
sudo /opt/cyntrisec/bin/ephemeralml-doctor --json

# One check only
sudo /opt/cyntrisec/bin/ephemeralml-doctor --check clock

# Help
ephemeralml-doctor --help
```

Must run as root because probes read `/etc/nitro_enclaves/allocator.yaml` and
`/sys/kernel/config/tsm/*`.

## Exit codes

| Exit | Meaning |
|---|---|
| `0` | All 6 checks passed. Host is ready for smoke-test. |
| `1` | One or more checks failed. Remediation printed inline. |
| `2` | CLI usage error (unknown `--check` name, invalid flag). |
| `3` | Infrastructure unreachable — IMDSv2 down, AWS APIs unreachable. |
| `4` | Unexpected internal error (indicates a doctor bug). |

## The six checks (fail-fast order)

1. `allocator` — Nitro Enclaves allocator service + `allocator.yaml` + `/dev/nitro_enclaves`
2. `eif` — EIF present + cosign-signed against embedded release public key + PCR0 recorded
3. `role` — IMDSv2 identity matches `{StackName}-host-role` + SSM config readable
4. `bucket` — S3 evidence bucket reachable + SSE-KMS + PublicAccessBlock + probe PUT under `_doctor/`
5. `kms` — KMS key Enabled + rotation on + `kms:ViaService=s3` enforcement (AccessDenied on direct call = PASS)
6. `clock` — `chronyc` offset < 5 seconds

## What this binary explicitly does NOT do

- No network calls to Cyntrisec-operated infrastructure
- No reading of customer data (probe markers live only under `_doctor/` prefix in the evidence bucket)
- No auto-remediation — fail + print remediation only; operator runs the fix
- No AIR v1 receipt generation — that is `ephemeralml-smoke-test`'s job
- No enclave launch — doctor verifies preconditions; smoke-test exercises the enclave
- No telemetry / phone-home
