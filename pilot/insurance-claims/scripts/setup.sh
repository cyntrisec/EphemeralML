#!/usr/bin/env bash
# Insurance Claims Pilot — Setup
#
# Builds and starts the EphemeralML mock stack with TinyLlama.
# For GCP deployment, use: bash scripts/setup.sh --gcp
set -euo pipefail

PILOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_DIR="$(cd "${PILOT_DIR}/../.." && pwd)"

MODE="${1:-local}"

# Colors
GREEN="\033[32m"; RED="\033[31m"; YELLOW="\033[33m"; BOLD="\033[1m"; RESET="\033[0m"
info()  { echo -e "  ${BOLD}$1${RESET}"; }
ok()    { echo -e "  ${GREEN}${BOLD}$1${RESET}"; }
warn()  { echo -e "  ${YELLOW}$1${RESET}"; }
fail()  { echo -e "  ${RED}${BOLD}$1${RESET}"; }

echo ""
info "EphemeralML Insurance Claims Pilot — Setup"
echo "  ────────────────────────────────────────"

# Ensure model is available
if [[ ! -f "${PROJECT_DIR}/test_assets/tinyllama/model.gguf" ]]; then
    fail "TinyLlama model not found at test_assets/tinyllama/model.gguf"
    echo "  Download it first: see EphemeralML README for model setup."
    exit 1
fi
ok "Model found: test_assets/tinyllama/model.gguf ($(du -h "${PROJECT_DIR}/test_assets/tinyllama/model.gguf" | cut -f1))"

if [[ "${MODE}" == "--gcp" ]]; then
    info "GCP deployment mode"
    echo ""
    echo "  This will deploy EphemeralML on a GCP Confidential VM (c3-standard-4, TDX)."
    echo "  Prerequisites:"
    echo "    - gcloud CLI authenticated"
    echo "    - .env.gcp configured (run: bash scripts/init_gcp.sh from repo root)"
    echo "    - Model uploaded to GCS bucket"
    echo ""
    echo "  Run from repo root:"
    echo "    bash pilot/deploy.sh"
    echo ""
    echo "  Then run the pilot:"
    echo "    bash pilot/insurance-claims/scripts/run-gcp-pilot.sh --ip <CVM_IP>"
    echo ""
    exit 0
fi

# Local mode — Docker Compose
info "Local mock mode (Docker Compose)"

if ! command -v docker &>/dev/null; then
    fail "Docker not found. Install Docker to run the local pilot."
    exit 1
fi

# Check Docker space
DOCKER_SPACE=$(docker system df --format '{{.Size}}' 2>/dev/null | head -1 || echo "unknown")
info "Docker space used: ${DOCKER_SPACE}"

# Build and start
cd "${PILOT_DIR}"
info "Building containers (this may take 3-5 minutes on first run)..."
docker compose build 2>&1 | tail -5

info "Starting stack..."
docker compose up -d

# Wait for gateway health
info "Waiting for gateway to be ready..."
MAX_WAIT=120
ELAPSED=0
while [[ $ELAPSED -lt $MAX_WAIT ]]; do
    if curl -sf http://localhost:8090/health >/dev/null 2>&1; then
        ok "Gateway is healthy"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if (( ELAPSED % 10 == 0 )); then
        echo "    ... waiting (${ELAPSED}s)"
    fi
done

if [[ $ELAPSED -ge $MAX_WAIT ]]; then
    fail "Gateway did not become healthy within ${MAX_WAIT}s"
    echo "  Check logs: docker compose -f ${PILOT_DIR}/compose.yaml logs"
    exit 1
fi

# Verify backend connectivity
READYZ=$(curl -sf http://localhost:8090/readyz 2>/dev/null || echo "failed")
if echo "$READYZ" | grep -q "ready"; then
    ok "Backend connected (readyz: ready)"
else
    warn "Backend may not be fully ready yet. Readyz: ${READYZ}"
    echo "  The backend may still be loading the model. Wait 30-60s and retry."
fi

echo ""
ok "Setup complete. Gateway at http://localhost:8090"
echo ""
echo "  Next: bash scripts/run-pilot.sh"
echo "  ────────────────────────────────────────"
