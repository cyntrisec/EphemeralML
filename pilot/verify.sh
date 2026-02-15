#!/usr/bin/env bash
# EphemeralML Pilot — Verify wrapper
#
# Runs inference against the deployed CVM, verifies the receipt,
# and saves evidence to pilot/evidence/.
#
# Usage:
#   bash pilot/verify.sh
#   bash pilot/verify.sh --ip 34.72.100.50
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EVIDENCE_DIR="${SCRIPT_DIR}/evidence"

mkdir -p "${EVIDENCE_DIR}"

# Source .env.gcp if present
if [[ -f "${PROJECT_DIR}/.env.gcp" ]]; then
    echo "  Sourcing ${PROJECT_DIR}/.env.gcp"
    # shellcheck disable=SC1091
    source "${PROJECT_DIR}/.env.gcp"
fi

# Build verify args from env
VERIFY_ARGS=()

if [[ -n "${EPHEMERALML_GCP_PROJECT:-}" ]]; then
    VERIFY_ARGS+=(--project "${EPHEMERALML_GCP_PROJECT}")
fi
if [[ -n "${EPHEMERALML_GCP_ZONE:-}" ]]; then
    VERIFY_ARGS+=(--zone "${EPHEMERALML_GCP_ZONE}")
fi

# Pass through extra args (e.g., --ip)
VERIFY_ARGS+=("$@")

echo ""
echo "  Running: scripts/gcp/verify.sh ${VERIFY_ARGS[*]}"
echo ""

bash "${PROJECT_DIR}/scripts/gcp/verify.sh" "${VERIFY_ARGS[@]}" 2>&1 | tee "${EVIDENCE_DIR}/verify_output.txt"
VERIFY_EXIT=${PIPESTATUS[0]}

# Copy receipt if available
if [[ -f /tmp/ephemeralml-receipt.cbor ]]; then
    cp /tmp/ephemeralml-receipt.cbor "${EVIDENCE_DIR}/receipt.cbor"
fi

# Save metadata
ZONE="${EPHEMERALML_GCP_ZONE:-us-central1-a}"
cat > "${EVIDENCE_DIR}/metadata.json" << EOF
{
  "project": "${EPHEMERALML_GCP_PROJECT:-unknown}",
  "zone": "${ZONE}",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "verify_exit": ${VERIFY_EXIT}
}
EOF

echo ""
echo "  ────────────────────────────────────────"
echo "  Evidence saved to: ${EVIDENCE_DIR}/"
echo ""
ls -1 "${EVIDENCE_DIR}/" | while read -r f; do
    echo "    ${f}"
done
echo ""
if [[ ${VERIFY_EXIT} -eq 0 ]]; then
    echo "  RESULT: PASS"
    echo "  Next: Review pilot/audit_evidence.md"
else
    echo "  RESULT: FAIL (exit code ${VERIFY_EXIT})"
    echo "  Check ${EVIDENCE_DIR}/verify_output.txt for details."
fi
echo "  ────────────────────────────────────────"

exit ${VERIFY_EXIT}
