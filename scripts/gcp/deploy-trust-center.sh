#!/usr/bin/env bash
# Build, scan, deploy, test, and promote the public Verification Center.
# The existing serving revision remains available for immediate rollback.

set -euo pipefail

PROJECT_ID="${1:?usage: $0 PROJECT_ID [REGION]}"
REGION="${2:-us-central1}"
SERVICE="${TRUST_CENTER_SERVICE:-trust-center}"
CANDIDATE_SERVICE="${TRUST_CENTER_CANDIDATE_SERVICE:-${SERVICE}-candidate}"
RUNTIME_SERVICE_ACCOUNT="${TRUST_CENTER_RUNTIME_SERVICE_ACCOUNT:-trust-center-runner@${PROJECT_ID}.iam.gserviceaccount.com}"
LIVE_URL="${TRUST_CENTER_LIVE_URL:-https://verify.cyntrisec.com}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

for command_name in curl gcloud git jq; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $command_name" >&2
        exit 2
    fi
done

if [[ -n "$(git -C "$REPO_DIR" status --porcelain)" ]]; then
    echo "ERROR: refusing to deploy from a dirty worktree" >&2
    exit 2
fi

git_sha="$(git -C "$REPO_DIR" rev-parse HEAD)"
upstream_sha="$(git -C "$REPO_DIR" rev-parse '@{upstream}' 2>/dev/null || true)"
if [[ -z "$upstream_sha" || "$git_sha" != "$upstream_sha" ]]; then
    echo "ERROR: refusing to deploy a commit that is not the current upstream tip" >&2
    echo "Local:    $git_sha" >&2
    echo "Upstream: ${upstream_sha:-not configured}" >&2
    exit 2
fi

short_sha="${git_sha:0:12}"
image_tag="${REGION}-docker.pkg.dev/${PROJECT_ID}/cloud-run-source-deploy/trust-center:verify-${short_sha}"

if [[ "$CANDIDATE_SERVICE" == "$SERVICE" ]]; then
    echo "ERROR: the candidate and production Cloud Run services must be different" >&2
    exit 2
fi

if gcloud run services describe "$CANDIDATE_SERVICE" \
    --project "$PROJECT_ID" --region "$REGION" >/dev/null 2>&1; then
    echo "ERROR: refusing to replace existing candidate service: $CANDIDATE_SERVICE" >&2
    exit 2
fi

previous_revision="$(gcloud run services describe "$SERVICE" \
    --project "$PROJECT_ID" --region "$REGION" --format=json \
    | jq -r '[.status.traffic[] | select(.percent == 100)][0].revisionName')"
if [[ -z "$previous_revision" || "$previous_revision" == null ]]; then
    echo "ERROR: failed to identify the current 100% production revision" >&2
    exit 2
fi

echo "Building and scanning $image_tag from $git_sha"
gcloud builds submit "$REPO_DIR" \
    --project "$PROJECT_ID" \
    --config "$REPO_DIR/cloudbuild-verifier.yaml" \
    --substitutions "_GIT_SHA=${git_sha},_IMAGE=${image_tag}"

image_digest="$(gcloud artifacts docker images describe "$image_tag" \
    --project "$PROJECT_ID" --format='value(image_summary.fully_qualified_digest)')"
if [[ -z "$image_digest" || "$image_digest" != *@sha256:* ]]; then
    echo "ERROR: failed to resolve immutable image digest for $image_tag" >&2
    exit 2
fi

auth_config=""
candidate_created=false
cleanup() {
    if [[ -n "$auth_config" ]]; then
        rm -f "$auth_config"
    fi
    if [[ "$candidate_created" == true ]]; then
        gcloud run services delete "$CANDIDATE_SERVICE" \
            --project "$PROJECT_ID" --region "$REGION" --quiet >/dev/null 2>&1 || \
            echo "WARNING: failed to delete private candidate service $CANDIDATE_SERVICE" >&2
    fi
}
trap cleanup EXIT

echo "Deploying private candidate service from $image_digest"
candidate_created=true
gcloud run deploy "$CANDIDATE_SERVICE" \
    --project "$PROJECT_ID" \
    --region "$REGION" \
    --image "$image_digest" \
    --service-account "$RUNTIME_SERVICE_ACCOUNT" \
    --set-env-vars EPHEMERALML_VERIFIER_MODE=public-trust-center,EPHEMERALML_VERIFIER_RATE_LIMIT=60 \
    --cpu 1 \
    --memory 256Mi \
    --concurrency 20 \
    --timeout 30 \
    --min-instances 0 \
    --max-instances 1 \
    --ingress all \
    --no-allow-unauthenticated \
    --invoker-iam-check \
    --default-url \
    --startup-probe 'httpGet.path=/health,httpGet.port=8080,timeoutSeconds=5,periodSeconds=10,failureThreshold=12' \
    --liveness-probe 'httpGet.path=/health,httpGet.port=8080,initialDelaySeconds=5,timeoutSeconds=5,periodSeconds=30,failureThreshold=3'

candidate_url="$(gcloud run services describe "$CANDIDATE_SERVICE" \
    --project "$PROJECT_ID" --region "$REGION" --format='value(status.url)')"
if [[ -z "$candidate_url" ]]; then
    echo "ERROR: Cloud Run did not report the private candidate URL" >&2
    exit 2
fi

identity_token="$(gcloud auth print-identity-token)"
if [[ -z "$identity_token" ]]; then
    echo "ERROR: failed to obtain an identity token for candidate testing" >&2
    exit 2
fi

auth_config="$(mktemp /tmp/trust-center-curl.XXXXXX)"
chmod 600 "$auth_config"
printf 'header = "Authorization: Bearer %s"\n' "$identity_token" >"$auth_config"
unset identity_token

ready=false
for _ in $(seq 1 30); do
    if curl --config "$auth_config" -fsS --max-time 3 \
        "$candidate_url/health" >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 2
done
if [[ "$ready" != true ]]; then
    echo "ERROR: authenticated candidate endpoint did not become healthy" >&2
    exit 1
fi

TRUST_CENTER_CURL_CONFIG="$auth_config" \
    bash "$REPO_DIR/scripts/smoke-test.sh" "$candidate_url"
TRUST_CENTER_CURL_CONFIG="$auth_config" \
    bash "$REPO_DIR/scripts/trust-center-conformance.sh" "$candidate_url"
TRUST_CENTER_CURL_CONFIG="$auth_config" EXPECTED_BUILD_SHA="$git_sha" \
    bash "$REPO_DIR/scripts/trust-center-drift-check.sh" "$candidate_url"

rm -f "$auth_config"
auth_config=""
gcloud run services delete "$CANDIDATE_SERVICE" \
    --project "$PROJECT_ID" --region "$REGION" --quiet
candidate_created=false
if gcloud run services describe "$CANDIDATE_SERVICE" \
    --project "$PROJECT_ID" --region "$REGION" >/dev/null 2>&1; then
    echo "ERROR: private candidate service still exists after cleanup" >&2
    exit 1
fi

echo "Deploying zero-traffic production revision from tested digest"
gcloud run services update-traffic "$SERVICE" \
    --project "$PROJECT_ID" --region "$REGION" --clear-tags

gcloud run deploy "$SERVICE" \
    --project "$PROJECT_ID" \
    --region "$REGION" \
    --image "$image_digest" \
    --service-account "$RUNTIME_SERVICE_ACCOUNT" \
    --set-env-vars EPHEMERALML_VERIFIER_MODE=public-trust-center,EPHEMERALML_VERIFIER_RATE_LIMIT=60 \
    --cpu 1 \
    --memory 256Mi \
    --concurrency 20 \
    --timeout 30 \
    --min-instances 0 \
    --max-instances 1 \
    --ingress all \
    --allow-unauthenticated \
    --no-default-url \
    --startup-probe 'httpGet.path=/health,httpGet.port=8080,timeoutSeconds=5,periodSeconds=10,failureThreshold=12' \
    --liveness-probe 'httpGet.path=/health,httpGet.port=8080,initialDelaySeconds=5,timeoutSeconds=5,periodSeconds=30,failureThreshold=3' \
    --revision-suffix "git-${short_sha}" \
    --no-traffic

candidate_revision="$(gcloud run services describe "$SERVICE" \
    --project "$PROJECT_ID" --region "$REGION" \
    --format='value(status.latestCreatedRevisionName)')"
if [[ -z "$candidate_revision" ]]; then
    echo "ERROR: Cloud Run did not report a production candidate revision" >&2
    exit 2
fi

deployed_image="$(gcloud run revisions describe "$candidate_revision" \
    --project "$PROJECT_ID" --region "$REGION" \
    --format='value(spec.containers[0].image)')"
if [[ "$deployed_image" != "$image_digest" ]]; then
    echo "ERROR: production candidate does not use the tested image digest" >&2
    echo "Expected: $image_digest" >&2
    echo "Actual:   ${deployed_image:-not reported}" >&2
    exit 2
fi

trap - EXIT

echo "Promoting $candidate_revision to 100% traffic"
gcloud run services update-traffic "$SERVICE" \
    --project "$PROJECT_ID" --region "$REGION" \
    --to-revisions "${candidate_revision}=100"

if ! bash "$REPO_DIR/scripts/smoke-test.sh" "$LIVE_URL" \
    || ! bash "$REPO_DIR/scripts/trust-center-conformance.sh" "$LIVE_URL" \
    || ! EXPECTED_BUILD_SHA="$git_sha" bash "$REPO_DIR/scripts/trust-center-drift-check.sh" "$LIVE_URL"; then
    echo "ERROR: post-promotion checks failed; rolling traffic back to $previous_revision" >&2
    gcloud run services update-traffic "$SERVICE" \
        --project "$PROJECT_ID" --region "$REGION" \
        --to-revisions "${previous_revision}=100"
    exit 1
fi

gcloud run services update-traffic "$SERVICE" \
    --project "$PROJECT_ID" --region "$REGION" --clear-tags

echo "PASS: $candidate_revision serves 100% of traffic; rollback target is $previous_revision"
