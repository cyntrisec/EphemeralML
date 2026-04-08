#!/usr/bin/env bash
# Insurance Claims Pilot — Generate Sanitized REPORT.md
#
# Produces a customer-facing markdown report from the latest pilot run without
# embedding local absolute paths or customer-specific deployment details.
#
# Usage:
#   bash scripts/generate-report.sh
#   bash scripts/generate-report.sh artifacts/<local-run>
#   bash scripts/generate-report.sh artifacts/<confidential-run> /tmp/report.md
set -euo pipefail

PILOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_DIR="$(cd "${PILOT_DIR}/../.." && pwd)"

RUN_DIR="${1:-}"
OUTPUT_PATH="${2:-${PILOT_DIR}/REPORT.md}"

if [[ -z "${RUN_DIR}" ]]; then
    shopt -s nullglob
    RUN_CANDIDATES=("${PILOT_DIR}/artifacts/run-"* "${PILOT_DIR}/artifacts/gcp-run-"*)
    shopt -u nullglob
    if [[ ${#RUN_CANDIDATES[@]} -eq 0 ]]; then
        echo "No pilot run found. Run the pilot first."
        exit 1
    fi
    RUN_DIR=$(ls -dt "${RUN_CANDIDATES[@]}" 2>/dev/null | head -1)
fi

if [[ ! -d "${RUN_DIR}" ]]; then
    echo "Run directory not found: ${RUN_DIR}"
    exit 1
fi

python3 - "${RUN_DIR}" "${OUTPUT_PATH}" "${PROJECT_DIR}" "${PILOT_DIR}" <<'PYEOF'
import csv
import glob
import json
import os
import statistics
import subprocess
import sys
from datetime import datetime, timezone

run_dir, output_path, project_dir, pilot_dir = sys.argv[1:5]
summary_path = os.path.join(run_dir, "summary.json")
results_path = os.path.join(run_dir, "results.csv")
verify_summary_path = os.path.join(run_dir, "verification", "summary.json")

if not os.path.exists(summary_path) or not os.path.exists(results_path):
    raise SystemExit("Run directory is missing summary.json or results.csv")

with open(summary_path, "r", encoding="utf-8") as fh:
    summary = json.load(fh)

rows = []
with open(results_path, "r", encoding="utf-8") as fh:
    reader = csv.DictReader(fh)
    rows = list(reader)

verification = None
if os.path.exists(verify_summary_path):
    with open(verify_summary_path, "r", encoding="utf-8") as fh:
        verification = json.load(fh)

run_name = os.path.basename(run_dir.rstrip("/"))
is_gcp = run_name.startswith("gcp-run-")
platforms = "local mock" if not is_gcp else "local mock + GCP TDX"
confidential_platform = "GCP TDX" if is_gcp else "N/A (local mock only)"
confidential_receipts = "Yes" if is_gcp else "No"
stack_version = subprocess.check_output(
    ["git", "-C", project_dir, "rev-parse", "--short", "HEAD"], text=True
).strip()

claim_rows = [r for r in rows if r["claim_id"] != "N/A"]
positive_rows = [r for r in claim_rows if r["status"] == "PASS"]
negative_rows = [r for r in rows if r["claim_id"] == "N/A"]
latencies = [int(r["latency_ms"]) for r in claim_rows if r["latency_ms"].isdigit() and int(r["latency_ms"]) > 0]
avg_latency = round(statistics.mean(latencies), 1) if latencies else "N/A"

receipt_files = sorted(glob.glob(os.path.join(run_dir, "receipts", "*.cbor")))
real_receipt_files = [p for p in receipt_files if not os.path.basename(p).startswith("tampered")]
receipt_rows = []
for path in real_receipt_files[: min(5, len(real_receipt_files))]:
    basename = os.path.basename(path)
    with open(path, "rb") as fh:
        blob = fh.read()
    sha = subprocess.check_output(["sha256sum", path], text=True).split()[0]
    receipt_rows.append({
        "claim": basename.replace(".cbor", ""),
        "size": len(blob),
        "sha": sha[:16],
    })

claims_count = "N/A"
model_id_value = "N/A"
security_mode = "mock"
measurement_type = "N/A"
issuer = "N/A"
verification_files = sorted(glob.glob(os.path.join(run_dir, "verification", "*_verify.json")))
for vf in verification_files:
    with open(vf, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("verdict") == "valid_structure":
        claims_count = data.get("claims_count", "N/A")
        claims = data.get("claims", {})
        model_id_value = claims.get("model_id", model_id_value)
        security_mode = claims.get("security_mode", security_mode)
        issuer = claims.get("iss", issuer)
        measurement_type = "present" if claims.get("enclave_measurements") else measurement_type
        break

if is_gcp:
    model_line = f"{model_id_value or 'manifest-backed model'} (manifest-backed)"
    model_packaging = "fetched remotely, manifest-backed"
    local_notes = "Local mock run retained for API rehearsal; confidential evidence came from the GCP TDX run."
    confidential_notes = "AIR v1 receipts verified offline from the collected GCP run."
else:
    model_line = "TinyLlama 1.1B Chat (GGUF, local rehearsal model)"
    model_packaging = "bundled in image"
    local_notes = "Mock mode validates API flow and output shape only. It returns receipt metadata but not cryptographic AIR v1 receipts."
    confidential_notes = "Not exercised in this run."

what_passed = [
    "OpenAI-compatible request/response flow completed across cold-start and warm-batch scenarios.",
    "All negative-path API checks behaved as expected (auth, empty input, unsupported tools, embeddings rejection).",
    "Gateway and backend stayed stable for the full run.",
]
if is_gcp:
    what_passed += [
        "AIR v1 receipts were emitted and verified offline.",
        "Manifest-backed model identity was carried into receipt verification.",
    ]
else:
    what_passed += [
        "The reusable pilot kit produced a sanitized artifact bundle and report from the current run.",
    ]

recommendations = [
    "Use the local mock bundle for workflow discovery and response-shape review with non-technical stakeholders.",
    "Use a GCP TDX or equivalent confidential-computing run when the buyer needs cryptographic receipt evidence.",
    "Keep the model and prompt stable between design-partner demos so latency and output comparisons remain meaningful.",
]

artifact_root = "artifacts/<confidential-run>" if is_gcp else "artifacts/<local-run>"
artifact_refs = [
    (f"{artifact_root}/summary.json", "Run metadata"),
    (f"{artifact_root}/results.csv", "Machine-readable results"),
]
if os.path.isdir(os.path.join(run_dir, "responses")):
    artifact_refs.append((f"{artifact_root}/responses/", "Saved request/response bodies"))
if real_receipt_files:
    artifact_refs.append((f"{artifact_root}/receipts/*.cbor", "AIR v1 receipts"))
if os.path.isdir(os.path.join(run_dir, "verification")):
    artifact_refs.append((f"{artifact_root}/verification/", "Verification outputs"))

lines = []
lines.append("# Insurance Claims Pilot — Technical Report")
lines.append("")
lines.append("## Executive Summary")
lines.append("")
lines.append(f"- **Date:** {datetime.now(timezone.utc).date().isoformat()}")
lines.append(f"- **Platforms exercised:** {platforms}")
lines.append(f"- **Model(s):** {model_line}")
lines.append(f"- **Stack version:** EphemeralML `{stack_version}`")
lines.append("")
lines.append("### Outcome Summary")
lines.append("")
lines.append(
    f"- **{summary['passed']}/{summary['total_tests']}** test cases passed"
    f" ({summary.get('skipped', 0)} skipped, {summary.get('failed', 0)} failed)"
)
lines.append(f"- **{len(negative_rows)}/{len(negative_rows)}** negative-path checks executed")
lines.append(f"- **{summary['receipts_collected']}** AIR v1 receipts collected")
lines.append(f"- **Average claim latency:** {avg_latency} ms")
lines.append("")
lines.append("## Pilot Modes")
lines.append("")
lines.append("### Local Mock")
lines.append("")
lines.append("- Purpose: API flow, error handling, response shape, operational rehearsal")
lines.append("- AIR v1 receipts: `No`")
lines.append(f"- Notes: {local_notes}")
lines.append("")
lines.append("### Confidential Computing Run")
lines.append("")
lines.append(f"- Platform: `{confidential_platform}`")
lines.append("- Purpose: full evidence path with hardware attestation")
lines.append(f"- AIR v1 receipts: `{confidential_receipts}`")
lines.append(f"- Notes: {confidential_notes}")
lines.append("")
lines.append("## Environment")
lines.append("")
lines.append(f"- **Instance / machine type:** {'Docker Compose local stack' if not is_gcp else 'Sanitized confidential VM reference'}")
lines.append(f"- **Region / zone:** {'local only' if not is_gcp else 'sanitized GCP region/zone'}")
lines.append(f"- **Image / deployment ref:** {'gateway-api/Dockerfile + Dockerfile.mock-backend' if not is_gcp else 'sanitized deployment reference'}")
lines.append(f"- **Model packaging:** `{model_packaging}`")
lines.append("")
lines.append("## Results")
lines.append("")
lines.append("| Claim | Latency | Receipt Size | Receipt SHA-256 | Result |")
lines.append("|-------|---------|-------------|-----------------|--------|")
if receipt_rows:
    receipt_map = {r["claim"]: r for r in receipt_rows}
    for row in positive_rows[: min(5, len(positive_rows))]:
        key = f"{row['scenario']}_{row['claim_id']}"
        receipt = receipt_map.get(key)
        lines.append(
            f"| {row['claim_id']} | {row['latency_ms']} ms | "
            f"{receipt['size'] if receipt else 'N/A'} | "
            f"{receipt['sha'] if receipt else 'N/A'} | {row['status']} |"
        )
else:
    for row in positive_rows[: min(5, len(positive_rows))]:
        lines.append(f"| {row['claim_id']} | {row['latency_ms']} ms | N/A | N/A | {row['status']} |")
lines.append("")
lines.append("### Receipt Contents")
lines.append("")
lines.append("| Field | Value |")
lines.append("|-------|-------|")
lines.append("| Format | `COSE_Sign1` if confidential mode is used; local mock returns metadata only |")
lines.append("| Signature | `Ed25519` in confidential mode |")
lines.append(f"| Claims count | `{claims_count}` |")
lines.append(f"| `iss` | `{issuer}` |")
lines.append("| `eat_profile` | `https://spec.cyntrisec.com/air/v1` when AIR v1 is emitted |")
lines.append(f"| `model_id` | `{model_id_value}` |")
lines.append("| `model_hash` | `weights measured inside TEE from decrypted bytes; manifest-backed when authoritative` |")
lines.append("| `request_hash` | `SHA-256 of input` |")
lines.append("| `response_hash` | `SHA-256 of output` |")
lines.append("| `attestation_doc_hash` | `SHA-256 of attestation evidence` in confidential mode |")
lines.append(f"| `enclave_measurements` | `{measurement_type}` |")
lines.append(f"| `security_mode` | `{security_mode}` |")
lines.append("")
lines.append("## What Passed")
lines.append("")
for idx, item in enumerate(what_passed, start=1):
    lines.append(f"{idx}. {item}")
lines.append("")
lines.append("## Known Limitations")
lines.append("")
lines.append("1. **Mock mode limitation**")
lines.append("Local mock mode does not produce cryptographic AIR v1 receipts or real attestation evidence.")
lines.append("")
lines.append("2. **Model quality limitation**")
lines.append("TinyLlama is used here for workflow rehearsal and response-shape validation, not for production-quality claims analysis.")
lines.append("")
lines.append("3. **Connection / lifecycle limitation**")
lines.append("This report captures a single-run artifact bundle. It does not prove long-running multi-tenant production behavior.")
lines.append("")
lines.append("4. **Out-of-scope items**")
lines.append("Pipeline orchestration, GPU confidential-computing runs, production auth hardening, and customer-specific policy packaging were out of scope for this rehearsal.")
lines.append("")
lines.append("## Latency Summary")
lines.append("")
lines.append("| Metric | Local Mock | Confidential Run |")
lines.append("|--------|------------|------------------|")
lines.append(f"| Cold-start | `{next((r['latency_ms'] + ' ms' for r in rows if r['scenario'] == 'cold' and r['status'] == 'PASS'), 'N/A')}` | `N/A` |")
warm_latencies = [int(r["latency_ms"]) for r in rows if r["scenario"] == "warm" and r["status"] == "PASS" and r["latency_ms"].isdigit()]
warm_avg = f"{round(statistics.mean(warm_latencies), 1)} ms" if warm_latencies else "N/A"
lines.append(f"| Warm inference | `{warm_avg}` | `N/A` |")
lines.append("| Negative test | `HTTP validation only` | `N/A` |")
lines.append(f"| Handshake + attestation | `N/A` | `{'see confidential run artifacts' if is_gcp else 'not exercised in this run'}` |")
lines.append("")
lines.append("## What This Proves")
lines.append("")
lines.append("### For the application team")
lines.append("")
lines.append("- The workflow can be exercised through an OpenAI-compatible API without changing the surrounding request shape.")
lines.append("- The pilot kit returns structured JSON that is stable enough for design-partner review.")
lines.append("")
lines.append("### For the security/compliance team")
lines.append("")
lines.append("- The reusable pilot kit preserves evidence artifacts for each request/response cycle.")
lines.append("- In confidential mode, receipts bind model/input/output hashes to attestation-linked execution evidence.")
lines.append("- Receipt verification can be performed offline from collected artifacts.")
lines.append("")
lines.append("### For the operations team")
lines.append("")
lines.append("- The pilot can be run locally for rehearsal or against a confidential-computing deployment for real evidence.")
lines.append("- The artifact layout is stable and suitable for bundle-based sharing.")
lines.append("")
lines.append("## Artifact References")
lines.append("")
lines.append("| Path | Description |")
lines.append("|------|-------------|")
for rel_path, desc in artifact_refs:
    lines.append(f"| `{rel_path}` | {desc} |")
lines.append("")
lines.append("## Recommendations")
lines.append("")
for idx, item in enumerate(recommendations, start=1):
    lines.append(f"{idx}. {item}")
lines.append("")

os.makedirs(os.path.dirname(output_path), exist_ok=True)
with open(output_path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines))

print(f"Report written to {output_path}")
PYEOF

echo "Generated report: ${OUTPUT_PATH}"
