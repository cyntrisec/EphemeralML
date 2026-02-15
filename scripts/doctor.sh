#!/usr/bin/env bash
# EphemeralML Doctor — Preflight checker for local development environment.
#
# Validates that all prerequisites are installed and configured before
# building or deploying EphemeralML.
#
# Usage:
#   bash scripts/doctor.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
WARN=0
FAIL=0

check_ok() {
    echo "[OK]   $1"
    PASS=$((PASS + 1))
}

check_warn() {
    echo "[WARN] $1"
    WARN=$((WARN + 1))
}

check_fail() {
    echo "[FAIL] $1"
    FAIL=$((FAIL + 1))
}

echo ""
echo "EphemeralML Doctor"
echo "=================="
echo ""

# 1. Rust toolchain
if command -v rustc &>/dev/null; then
    RUST_VER="$(rustc --version | awk '{print $2}')"
    check_ok "Rust toolchain: ${RUST_VER}"
else
    check_fail "Rust toolchain: not installed (https://rustup.rs/)"
fi

# 2. Cargo
if command -v cargo &>/dev/null; then
    check_ok "cargo: $(command -v cargo)"
else
    check_fail "cargo: not found"
fi

# 3. Docker
if command -v docker &>/dev/null; then
    DOCKER_VER="$(docker --version 2>/dev/null | head -1)"
    if docker info &>/dev/null 2>&1; then
        check_ok "Docker: ${DOCKER_VER}"
    else
        check_warn "Docker: installed but daemon not running (${DOCKER_VER})"
    fi
else
    check_warn "Docker: not installed (needed for GCP deployment)"
fi

# 4. gcloud CLI
if command -v gcloud &>/dev/null; then
    GCLOUD_VER="$(gcloud --version 2>/dev/null | head -1 | awk '{print $NF}')"
    if gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>/dev/null | head -1 | grep -q '@'; then
        check_ok "gcloud: ${GCLOUD_VER} (authenticated)"
    else
        check_warn "gcloud: ${GCLOUD_VER} (not authenticated — run 'gcloud auth login')"
    fi
else
    check_warn "gcloud: not installed (needed for GCP deployment)"
fi

# 5. Model weights
MODEL_WEIGHTS="${PROJECT_DIR}/test_assets/minilm/model.safetensors"
if [ -f "${MODEL_WEIGHTS}" ] || [ -L "${MODEL_WEIGHTS}" ]; then
    if [ -L "${MODEL_WEIGHTS}" ]; then
        TARGET="$(readlink -f "${MODEL_WEIGHTS}" 2>/dev/null || echo "broken")"
        if [ -f "${TARGET}" ]; then
            SIZE="$(du -h "${TARGET}" | cut -f1)"
            check_ok "Model weights: ${MODEL_WEIGHTS} -> ${TARGET} (${SIZE})"
        else
            check_fail "Model weights: symlink broken (target: ${TARGET})"
        fi
    else
        SIZE="$(du -h "${MODEL_WEIGHTS}" | cut -f1)"
        check_ok "Model weights: ${MODEL_WEIGHTS} (${SIZE})"
    fi
else
    check_warn "Model weights: not found — run 'bash scripts/download_model.sh'"
fi

# 6. jq (optional)
if command -v jq &>/dev/null; then
    check_ok "jq: $(jq --version 2>/dev/null || echo 'installed')"
else
    check_warn "jq: not installed (optional, needed for some scripts)"
fi

# 7. GCP project
GCP_PROJECT="${EPHEMERALML_GCP_PROJECT:-}"
if [ -z "${GCP_PROJECT}" ] && command -v gcloud &>/dev/null; then
    GCP_PROJECT="$(gcloud config get-value project 2>/dev/null || true)"
fi
if [ -n "${GCP_PROJECT}" ] && [ "${GCP_PROJECT}" != "(unset)" ]; then
    check_ok "GCP project: ${GCP_PROJECT}"
else
    check_warn "GCP project: not set (set EPHEMERALML_GCP_PROJECT or 'gcloud config set project')"
fi

# Summary
echo ""
echo "---"
TOTAL=$((PASS + WARN + FAIL))
echo "${PASS}/${TOTAL} checks passed, ${WARN} warning(s), ${FAIL} failure(s)."
echo ""

if [ "${FAIL}" -gt 0 ]; then
    echo "Fix the failures above before building EphemeralML."
    exit 1
fi

exit 0
