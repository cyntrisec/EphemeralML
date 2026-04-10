#!/usr/bin/env bash
# Shared helpers for GCP shell scripts.

gcp_source_env_file() {
    local project_dir="$1"
    local env_file="${project_dir}/.env.gcp"
    if [[ -f "${env_file}" ]]; then
        # shellcheck disable=SC1090
        source "${env_file}"
    fi
}

gcp_export_env_aliases() {
    if [[ -z "${GCP_KMS_KEY:-}" && -n "${EPHEMERALML_GCP_KMS_KEY:-}" ]]; then
        export GCP_KMS_KEY="${EPHEMERALML_GCP_KMS_KEY}"
    fi
    if [[ -z "${GCP_BUCKET:-}" && -n "${EPHEMERALML_GCS_BUCKET:-}" ]]; then
        export GCP_BUCKET="${EPHEMERALML_GCS_BUCKET}"
    fi
    if [[ -z "${GCP_WIP_AUDIENCE:-}" && -n "${EPHEMERALML_GCP_WIP_AUDIENCE:-}" ]]; then
        export GCP_WIP_AUDIENCE="${EPHEMERALML_GCP_WIP_AUDIENCE}"
    fi
}

gcp_ui_info() {
    if declare -F ui_info >/dev/null 2>&1; then
        ui_info "$1"
    else
        echo "$1"
    fi
}

gcp_ui_fail() {
    if declare -F ui_fail >/dev/null 2>&1; then
        ui_fail "$1"
    else
        echo "$1"
    fi
}

gcp_ui_bullet() {
    if declare -F ui_bullet >/dev/null 2>&1; then
        ui_bullet "$1"
    else
        echo "  - $1"
    fi
}

gcp_effective_account() {
    if [[ -n "${CLOUDSDK_CORE_ACCOUNT:-}" ]]; then
        printf '%s\n' "${CLOUDSDK_CORE_ACCOUNT}"
        return 0
    fi
    gcloud config get-value account 2>/dev/null || true
}

gcp_require_project_access() {
    local project="$1"
    local context="${2:-non-interactive gcloud access}"
    local account
    local output

    account="$(gcp_effective_account)"
    if [[ -n "${account}" ]]; then
        gcp_ui_info "Using gcloud account: ${account}"
    fi

    if output="$(CLOUDSDK_CORE_DISABLE_PROMPTS=1 gcloud projects describe "${project}" --format='value(projectNumber)' 2>&1)"; then
        return 0
    fi

    gcp_ui_fail "ERROR: ${context} check failed for project '${project}'."
    if [[ -n "${account}" ]]; then
        gcp_ui_info "Account: ${account}"
    fi
    if [[ -n "${output}" ]]; then
        gcp_ui_info "gcloud output:"
        printf '%s\n' "${output}" | sed 's/^/  /'
    fi
    gcp_ui_bullet "If another local account works, rerun with: CLOUDSDK_CORE_ACCOUNT=<account> bash <script>"
    gcp_ui_bullet "Otherwise refresh auth with: gcloud auth login"
    return 1
}
