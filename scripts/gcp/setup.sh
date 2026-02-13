#!/usr/bin/env bash
# EphemeralML — One-time GCP infrastructure provisioning.
#
# Enables APIs, creates Artifact Registry repo, service account, and firewall rule.
# Idempotent — safe to re-run. Fails loudly if any step errors.
#
# Usage: bash scripts/gcp/setup.sh [--project PROJECT_ID]
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REPO_NAME="ephemeralml"
REPO_LOCATION="us"
SA_NAME="ephemeralml-cvm"
FIREWALL_RULE="allow-ephemeralml"
TAG="ephemeralml"

# Parse args — project must come from env or --project flag
PROJECT="${EPHEMERALML_GCP_PROJECT:-}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --project) PROJECT="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "${PROJECT}" ]]; then
    echo "ERROR: GCP project not set."
    echo "Set EPHEMERALML_GCP_PROJECT or pass --project PROJECT_ID"
    exit 1
fi

SA_EMAIL="${SA_NAME}@${PROJECT}.iam.gserviceaccount.com"

echo "============================================"
echo "  EphemeralML — GCP Setup"
echo "============================================"
echo
echo "  Project:  ${PROJECT}"
echo "  Region:   ${REPO_LOCATION}"
echo

# ---------------------------------------------------------------------------
# 1. Enable APIs
# ---------------------------------------------------------------------------
echo "[1/5] Enabling APIs..."
APIS=(
    "confidentialcomputing.googleapis.com"
    "artifactregistry.googleapis.com"
    "cloudkms.googleapis.com"
    "compute.googleapis.com"
)
FAILED_APIS=()
for api in "${APIS[@]}"; do
    echo "  - ${api}"
    if ! gcloud services enable "${api}" --project="${PROJECT}" --quiet 2>&1; then
        FAILED_APIS+=("${api}")
        echo "    FAILED to enable ${api}"
    fi
done
if [[ ${#FAILED_APIS[@]} -gt 0 ]]; then
    echo
    echo "ERROR: Failed to enable APIs: ${FAILED_APIS[*]}"
    echo "Check project permissions (roles/serviceusage.serviceUsageAdmin) and org policies."
    exit 1
fi
echo "  APIs enabled."
echo

# ---------------------------------------------------------------------------
# 2. Create Artifact Registry repository
# ---------------------------------------------------------------------------
echo "[2/5] Creating Artifact Registry repository..."
if gcloud artifacts repositories describe "${REPO_NAME}" \
    --project="${PROJECT}" \
    --location="${REPO_LOCATION}" &>/dev/null; then
    echo "  Repository '${REPO_NAME}' already exists."
else
    gcloud artifacts repositories create "${REPO_NAME}" \
        --project="${PROJECT}" \
        --location="${REPO_LOCATION}" \
        --repository-format=docker \
        --description="EphemeralML container images"
    echo "  Repository '${REPO_NAME}' created."
fi
echo

# ---------------------------------------------------------------------------
# 3. Create service account
# ---------------------------------------------------------------------------
echo "[3/5] Creating service account..."
if gcloud iam service-accounts describe "${SA_EMAIL}" \
    --project="${PROJECT}" &>/dev/null; then
    echo "  Service account '${SA_NAME}' already exists."
else
    gcloud iam service-accounts create "${SA_NAME}" \
        --project="${PROJECT}" \
        --display-name="EphemeralML Confidential VM"
    echo "  Service account '${SA_NAME}' created."
fi
echo

# ---------------------------------------------------------------------------
# 4. Grant IAM roles
# ---------------------------------------------------------------------------
echo "[4/5] Granting IAM roles..."
ROLES=(
    "roles/artifactregistry.reader"
    "roles/logging.logWriter"
    "roles/monitoring.metricWriter"
    "roles/confidentialcomputing.workloadUser"
)
FAILED_ROLES=()
for role in "${ROLES[@]}"; do
    echo "  - ${role}"
    if ! gcloud projects add-iam-policy-binding "${PROJECT}" \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="${role}" \
        --condition=None \
        --quiet 2>&1; then
        FAILED_ROLES+=("${role}")
        echo "    FAILED to grant ${role}"
    fi
done
if [[ ${#FAILED_ROLES[@]} -gt 0 ]]; then
    echo
    echo "ERROR: Failed to grant roles: ${FAILED_ROLES[*]}"
    echo "Check project permissions (roles/resourcemanager.projectIamAdmin)."
    exit 1
fi
echo "  Roles granted."
echo

# ---------------------------------------------------------------------------
# 5. Create firewall rule
# ---------------------------------------------------------------------------
echo "[5/5] Creating firewall rule..."
if gcloud compute firewall-rules describe "${FIREWALL_RULE}" \
    --project="${PROJECT}" &>/dev/null; then
    echo "  Firewall rule '${FIREWALL_RULE}' already exists."
else
    gcloud compute firewall-rules create "${FIREWALL_RULE}" \
        --project="${PROJECT}" \
        --direction=INGRESS \
        --priority=1000 \
        --network=default \
        --action=ALLOW \
        --rules=tcp:9000-9002 \
        --source-ranges=0.0.0.0/0 \
        --target-tags="${TAG}" \
        --description="Allow inbound TCP 9000-9002 for EphemeralML enclave"
    echo "  Firewall rule '${FIREWALL_RULE}' created."
fi
echo

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo "============================================"
echo "  Setup complete."
echo "============================================"
echo
echo "  Artifact Registry:  ${REPO_LOCATION}-docker.pkg.dev/${PROJECT}/${REPO_NAME}"
echo "  Service account:    ${SA_EMAIL}"
echo "  Firewall rule:      ${FIREWALL_RULE} (TCP 9000-9002, tag=${TAG})"
echo
echo "  Next: bash scripts/gcp/deploy.sh"
