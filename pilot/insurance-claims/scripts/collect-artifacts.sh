#!/usr/bin/env bash
# Insurance Claims Pilot — Collect Artifacts
#
# Bundles all pilot artifacts into a single distributable directory.
#
# Usage:
#   bash scripts/collect-artifacts.sh [run-dir]
set -euo pipefail

PILOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RUN_DIR="${1:-}"
if [[ -z "$RUN_DIR" ]]; then
    shopt -s nullglob
    RUN_CANDIDATES=("${PILOT_DIR}/artifacts/run-"* "${PILOT_DIR}/artifacts/gcp-run-"*)
    shopt -u nullglob
    if [[ ${#RUN_CANDIDATES[@]} -gt 0 ]]; then
        RUN_DIR=$(ls -dt "${RUN_CANDIDATES[@]}" 2>/dev/null | head -1 || echo "")
    fi
    if [[ -z "$RUN_DIR" ]]; then
        echo "  No run directory found."
        exit 1
    fi
fi

BOLD="\033[1m"; GREEN="\033[32m"; RESET="\033[0m"
info()  { echo -e "  ${BOLD}$1${RESET}"; }
ok()    { echo -e "  ${GREEN}${BOLD}$1${RESET}"; }

BUNDLE_DIR="${PILOT_DIR}/artifacts/pilot-bundle-$(date -u +%Y%m%d)"
mkdir -p "${BUNDLE_DIR}"

echo ""
info "EphemeralML Insurance Claims Pilot — Artifact Collection"
echo "  ────────────────────────────────────────"

# Copy pilot definition
cp -r "${PILOT_DIR}/data" "${BUNDLE_DIR}/"
cp -r "${PILOT_DIR}/requests" "${BUNDLE_DIR}/"

# Copy run artifacts
if [[ -d "${RUN_DIR}/responses" ]]; then
    cp -r "${RUN_DIR}/responses" "${BUNDLE_DIR}/"
fi
if [[ -d "${RUN_DIR}/receipts" ]]; then
    cp -r "${RUN_DIR}/receipts" "${BUNDLE_DIR}/"
fi
if [[ -d "${RUN_DIR}/timing" ]]; then
    cp -r "${RUN_DIR}/timing" "${BUNDLE_DIR}/"
fi
if [[ -d "${RUN_DIR}/verification" ]]; then
    cp -r "${RUN_DIR}/verification" "${BUNDLE_DIR}/"
fi
if [[ -f "${RUN_DIR}/results.csv" ]]; then
    cp "${RUN_DIR}/results.csv" "${BUNDLE_DIR}/"
fi
if [[ -f "${RUN_DIR}/summary.json" ]]; then
    cp "${RUN_DIR}/summary.json" "${BUNDLE_DIR}/"
fi

# Generate summary table
info "Generating summary table..."
python3 << 'PYEOF' "${BUNDLE_DIR}" 2>/dev/null || true
import json, sys, os, glob

bundle_dir = sys.argv[1]

# Load results CSV
results = []
csv_path = os.path.join(bundle_dir, "results.csv")
if os.path.exists(csv_path):
    with open(csv_path) as f:
        headers = f.readline().strip().split(",")
        for line in f:
            vals = line.strip().split(",")
            if len(vals) == len(headers):
                results.append(dict(zip(headers, vals)))

# Load timing data
timing = {}
for tf in glob.glob(os.path.join(bundle_dir, "timing", "*.json")):
    with open(tf) as f:
        t = json.load(f)
        timing[f"{t['scenario']}_{t['claim_id']}"] = t

# Load verification data
verification = {}
for vf in glob.glob(os.path.join(bundle_dir, "verification", "*_verify.json")):
    with open(vf) as f:
        v = json.load(f)
        basename = os.path.basename(vf).replace("_verify.json", "")
        verification[basename] = v

# Build markdown summary
md = []
md.append("# Insurance Claims Pilot — Results Summary")
md.append("")
md.append(f"**Generated:** {json.dumps(os.popen('date -u +%Y-%m-%dT%H:%M:%SZ').read().strip())}")
md.append("")

# Results table
md.append("## Test Results")
md.append("")
md.append("| Scenario | Claim ID | Status | Latency (ms) | Receipt | HTTP |")
md.append("|----------|----------|--------|-------------|---------|------|")
for r in results:
    receipt = "yes" if r.get("receipt_present") == "true" else "no"
    md.append(f"| {r['scenario']} | {r['claim_id']} | {r['status']} | {r['latency_ms']} | {receipt} | {r['http_status']} |")

md.append("")

# Timing summary
if timing:
    latencies = [t["latency_ms"] for t in timing.values() if t.get("latency_ms", 0) > 0]
    if latencies:
        md.append("## Latency Summary")
        md.append("")
        md.append(f"- **Min:** {min(latencies)} ms")
        md.append(f"- **Max:** {max(latencies)} ms")
        md.append(f"- **Avg:** {sum(latencies) // len(latencies)} ms")
        md.append(f"- **Count:** {len(latencies)}")
        md.append("")

# Verification summary
if verification:
    valid = sum(1 for v in verification.values() if v.get("verdict") == "valid_structure")
    md.append("## Receipt Verification")
    md.append("")
    md.append(f"- **Total receipts:** {len(verification)}")
    md.append(f"- **Valid structure:** {valid}")
    md.append(f"- **Claims per receipt:** {verification[list(verification.keys())[0]].get('claims_count', 'N/A')}")
    md.append("")

with open(os.path.join(bundle_dir, "SUMMARY.md"), "w") as f:
    f.write("\n".join(md))

print(f"Summary written to {os.path.join(bundle_dir, 'SUMMARY.md')}")
PYEOF

echo ""
ok "Artifacts collected: ${BUNDLE_DIR}/"
echo ""
echo "  Contents:"
find "${BUNDLE_DIR}" -type f | sort | while read -r f; do
    SIZE=$(du -h "$f" | cut -f1)
    echo "    ${SIZE}  ${f#${BUNDLE_DIR}/}"
done
echo ""
echo "  ════════════════════════════════════════"
