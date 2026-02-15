#!/usr/bin/env bash
# EphemeralML Pilot — Deploy wrapper
#
# Thin wrapper around scripts/gcp/deploy.sh with pilot-friendly defaults.
# Sources .env.gcp if present. Defaults to --model-source gcs-kms.
#
# Usage:
#   bash pilot/deploy.sh
#   bash pilot/deploy.sh --debug
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source .env.gcp if present
if [[ -f "${PROJECT_DIR}/.env.gcp" ]]; then
    echo "  Sourcing ${PROJECT_DIR}/.env.gcp"
    # shellcheck disable=SC1091
    source "${PROJECT_DIR}/.env.gcp"
fi

# Build deploy args from env
DEPLOY_ARGS=()

if [[ -n "${EPHEMERALML_GCP_PROJECT:-}" ]]; then
    DEPLOY_ARGS+=(--project "${EPHEMERALML_GCP_PROJECT}")
fi
if [[ -n "${EPHEMERALML_GCP_ZONE:-}" ]]; then
    DEPLOY_ARGS+=(--zone "${EPHEMERALML_GCP_ZONE}")
fi

# Default to gcs-kms for pilot
MODEL_SOURCE="${EPHEMERALML_MODEL_SOURCE:-gcs-kms}"
DEPLOY_ARGS+=(--model-source "${MODEL_SOURCE}")

if [[ "${MODEL_SOURCE}" == "gcs-kms" ]]; then
    if [[ -n "${EPHEMERALML_GCP_KMS_KEY:-}" ]]; then
        DEPLOY_ARGS+=(--kms-key "${EPHEMERALML_GCP_KMS_KEY}")
    fi
    if [[ -n "${EPHEMERALML_GCP_WIP_AUDIENCE:-}" ]]; then
        DEPLOY_ARGS+=(--wip-audience "${EPHEMERALML_GCP_WIP_AUDIENCE}")
    fi
    if [[ -n "${EPHEMERALML_GCS_BUCKET:-}" ]]; then
        DEPLOY_ARGS+=(--bucket "${EPHEMERALML_GCS_BUCKET}")
    fi
    if [[ -n "${EPHEMERALML_GCP_MODEL_PREFIX:-}" ]]; then
        DEPLOY_ARGS+=(--model-prefix "${EPHEMERALML_GCP_MODEL_PREFIX}")
    fi
    if [[ -n "${EPHEMERALML_EXPECTED_MODEL_HASH:-}" ]]; then
        DEPLOY_ARGS+=(--model-hash "${EPHEMERALML_EXPECTED_MODEL_HASH}")
    fi
fi

# Pass through any extra args (e.g., --debug)
DEPLOY_ARGS+=("$@")

echo "  Running: scripts/gcp/deploy.sh ${DEPLOY_ARGS[*]}"
echo ""

bash "${PROJECT_DIR}/scripts/gcp/deploy.sh" "${DEPLOY_ARGS[@]}"

echo ""
echo "  ────────────────────────────────────────"
echo "  Next step: bash pilot/verify.sh"
echo "  ────────────────────────────────────────"
