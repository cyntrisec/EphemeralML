# ephemeralml-smoke-test

Phase 1 BYOC end-to-end smoke test. Runs doctor preflight, launches the
Cyntrisec enclave, runs a synthetic inference, verifies the AIR v1 receipt
offline, writes the evidence bundle to S3.

**Contract:** `startup-plans/10-operations/byoc-phase-1-ephemeralml-smoke-test-spec-2026-04-23.md`

## Status

AWS-native runner implemented. The command invokes the doctor, launches a
Nitro enclave, runs the host orchestrator against a fixed synthetic input,
verifies the AIR receipt offline, and uploads the resulting evidence bundle to
S3.

The runner remains fail-closed: it refuses to upload unless the local receipt
verification passes and every required evidence file is present. In particular,
`kms-release.json` must be produced by the runtime before Stage 5 can pass.

## The 5 stages (strict order, fail-fast)

1. `doctor` — subprocess `ephemeralml-doctor --json`; must return `overall_status: "pass"` with 6/6 `ok`
2. `enclave_launch` — start `kms_proxy_host`, reject debug mode, launch the EIF with `nitro-cli run-enclave`, and require RUNNING state
3. `inference` — run the host orchestrator against the fixed synthetic fixture and collect receipt/attestation artifacts
4. `receipt_verify` — offline AIR verification via `ephemeralml-verify`, including attestation-document hash binding when `attestation.cbor` is supplied
5. `s3_write` — 13-file evidence bundle uploaded to `s3://{bucket}/smoke-tests/{iso-timestamp}/`

Failure at stage N marks stages N+1..5 as `skipped` with reason `"prior stage failed"`. Result vector always has exactly 5 entries regardless of where failure occurs.

## Flags

| Flag | Purpose |
|---|---|
| `--json` | Machine-readable output |
| `--no-upload` | Run stages 1-4 only; skip stage 5 (CI mode) |
| `--verbose` | Include raw probe data |
| `--stack-name <name>` | Override auto-detected CloudFormation stack |
| `--retain-enclave` | Don't terminate enclave on exit (post-mortem debugging) |
| `--bundle-dir <path>` | Local directory where the bundle is assembled |
| `--eif-path <path>` | EIF to launch |
| `--kms-proxy-bin <path>` | Host-side VSock KMS/S3 proxy started before enclave boot |
| `--expected-model-hash <hex>` | Optional expected AIR model hash |
| `--evidence-bucket <name>` | Override SSM bucket discovery |
| `--model-bucket <name>` | Override S3 bucket for encrypted model weights; defaults to evidence bucket discovery |

## AWS KMS model release

For the high-confidence AWS PoC, build the EIF with
`enclave/Dockerfile.enclave.aws-poc`. Prepare the model package first:

```bash
scripts/aws/package_model.sh test_assets/minilm "$BUCKET" \
  --kms-key "$MODEL_KMS_KEY_ARN" \
  --sse-kms-key "$EVIDENCE_KMS_KEY_ARN"
```

That script uploads encrypted `model.safetensors` to S3, stages
`manifest.json` and `wrapped_dek.bin` under `docker-stage/model/`, and prints
the `MODEL_SIGNING_PUBKEY` build argument for the AWS PoC Dockerfile.

## Repeatable AWS-native PoC run

After the CloudFormation stack is created, the model is packaged, the EIF is
built, and the stack's `EnclaveImageSha384` parameter is updated to the final
EIF measurement, use the wrapper script:

```bash
scripts/aws/run_native_poc.sh \
  --stack-name <stack-name> \
  --region us-east-1 \
  --repetitions 3 \
  --expected-model-hash <sha256-model-artifact-set>
```

The script operates through SSM, uploads the current release smoke-test binary
to the host, runs the five-stage smoke test, deletes the temporary upload, and
stops only a host that it started itself unless `--stop-after-run` is set.

Summarize benchmark packets with:

```bash
scripts/aws/summarize_benchmarks.py artifacts/benchmarks/aws-native-poc-20260430
```

Create a redacted shareable packet from a private evidence bundle with:

```bash
scripts/aws/redact_evidence_bundle.py /tmp/private-bundle artifacts/benchmarks/aws-native-poc-YYYYMMDD
```

See `docs/AWS_NATIVE_POC_RUNBOOK.md` for the full operator flow and
customer-safe claim language.

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
